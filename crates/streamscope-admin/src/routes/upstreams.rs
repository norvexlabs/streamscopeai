//! Upstream server and model management with credential encryption.
//!
//! Upstream servers represent LLM provider endpoints (OpenAI, Anthropic, etc.).
//! Each server has models with routing weights, priorities, and context window
//! sizes. API credentials are AES-256-GCM encrypted at rest. Changes trigger
//! config sync to push updated model mappings to edge proxies.


use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use utoipa::{IntoParams, ToSchema};

use crate::db::tenant::{Scoped, TenantConn};
use streamscope_core::config::model_map::Provider;
use streamscope_core::config::upstream_transport::UpstreamTransport;
use streamscope_core::pricing::{Currency, Rate, Rates, Unit};
use streamscope_core::proxy::adaptive_concurrency::ItlTarget;
use streamscope_core::proxy::routing::ModelCapabilities as Caps;
use super::{ActionResponse, ApiError, ApiErrorCode, ApiErrorResponse, PageQuery, TotalPage};
use super::upstream_endpoints::{server_health_columns_sql, ServerHealth};
use super::model_sync::AutoSyncStatus;
use super::key_lifecycle::DryRunQuery;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const VALID_API_FORMATS: &[&str] = &["chat_completions", "responses", "anthropic_messages", "google_gemini"];

// ---------------------------------------------------------------------------
// Server types
// ---------------------------------------------------------------------------

#[derive(Deserialize, ToSchema)]
pub struct CreateServerRequest {
    pub name: String,
    pub provider: String,
    pub api_key: Option<String>,
    /// The server's URL, stored as its first (primary) endpoint. Omitted = the
    /// provider seed's endpoint; a provider without one requires it.
    pub upstream_url: Option<String>,
    pub upstream_api_format: Option<String>,
    /// Override for the appended chat-completions endpoint path when this
    /// provider's OpenAI-compatible chat endpoint is not `{upstream_url}/v1/chat/completions`
    /// (e.g. `/chat` for Writer, `/chat/completions` with no `/v1` for DeepInfra).
    /// Omitted = the provider seed default (else the canonical `/v1/chat/completions`).
    /// Applies only to the `chat_completions` protocol.
    #[serde(default)]
    pub chat_endpoint_path: Option<String>,
    /// How the gateway carries requests to this server, orthogonal to the
    /// protocol it speaks. `default` is a plain bearer-auth endpoint on
    /// canonical `/v1/...` paths. `azure_openai` addresses an Azure OpenAI in
    /// Microsoft Foundry resource on its v1 API (`{url}/openai/v1/...`) with the
    /// key in an `api-key` header; `azure_openai_entra` is the same surface with
    /// a Microsoft Entra ID token minted from a client-credentials document
    /// supplied as `api_key`. `aws_bedrock` addresses Amazon Bedrock's
    /// OpenAI-compatible surface (`{url}/openai/v1/...`) with a Bedrock API key
    /// as the bearer token. `google_vertex` addresses Google Vertex AI from a
    /// project/location URL, with an access token minted from a service-account
    /// JSON key supplied as `api_key`. Omitted = the provider seed's transport,
    /// else `default`.
    #[serde(default)]
    pub transport: Option<String>,
    /// Toggle autosync for this server (omitted = on). Autosync is the single
    /// switch that owns the mirror: when on, adding the server discovers its
    /// models and maintains a same-named mirror downstream; when off, the server
    /// is manual (no discovery, no mirror — build a custom downstream instead).
    #[serde(default)]
    pub auto_sync_enabled: Option<bool>,
    /// Create a **BYOK pass-through** provider: a keyless upstream (the client
    /// forwards its own credential; `api_key` is ignored) plus an empty `byok`
    /// downstream of the same name. Unconfigured models pass through to
    /// `upstream_url`; add routes inside the downstream to override individual
    /// models. No discovery / mirror (keyless), so `auto_sync_enabled` is forced
    /// off. Default false. **Create-only** — ignored on update, where BYOK is
    /// derived from the linked downstream (set-once at create).
    #[serde(default)]
    pub byok: Option<bool>,
    #[serde(default)]
    pub force: bool,
}

#[derive(Serialize, ToSchema)]
pub struct ServerResponse {
    pub id: Uuid,
    pub name: String,
    pub provider: String,
    pub has_credential: bool,
    /// True when a `byok = true` pass-through downstream is linked to this
    /// keyless upstream. Set-once at create — an update derives it solely
    /// from the linked downstream and never flips it.
    pub byok: bool,
    /// The primary endpoint's URL: the first enabled endpoint of the server.
    pub upstream_url: Option<String>,
    pub upstream_api_format: String,
    /// Override for the appended chat-completions endpoint path (null = the
    /// canonical `/v1/chat/completions`).
    pub chat_endpoint_path: Option<String>,
    /// How requests are carried to this server: `default`, `azure_openai`,
    /// `azure_openai_entra`, `aws_bedrock` or `google_vertex`.
    pub transport: String,
    pub enabled: bool,
    /// A seed-shipped pass-through: it is switched on and off and repointed,
    /// never deleted (the delete answers `409 BuiltinProviderProtected`).
    pub is_builtin: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub model_count: i64,
    /// When on, the autosync worker periodically re-discovers this server's
    /// models and mirrors them downstream (add + refresh + remove).
    pub auto_sync_enabled: bool,
    /// Timestamp of the last autosync (or "sync now") run, if any.
    pub last_auto_sync_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Outcome of the last run. Null until the first run.
    pub last_auto_sync_status: Option<AutoSyncStatus>,
    /// How many endpoints (replicas) the server has.
    pub endpoint_count: i64,
    /// Endpoints a connected gateway currently has out of rotation (breaker
    /// open).
    pub endpoints_down: i64,
    /// Whether the server can serve traffic now, from the same counts.
    pub health: ServerHealth,
    /// Whether the dispatch gate applies here: the server, or any enabled
    /// endpoint of it, declares an in-flight or a waiting-queue bound. Only a
    /// gated server has live load to report.
    pub gated: bool,
    /// How this engine expresses a request's priority class: `none` (the
    /// default — the gateway keeps the decision to itself) or `vllm_priority`.
    pub scheduling_dialect: String,
    /// How many requests the gateway may have in flight at one endpoint of this
    /// server, and how long that engine's own queue may grow before it is sent
    /// no more. Both null = the dispatch gate does not apply to this server.
    pub max_in_flight: Option<i32>,
    pub waiting_threshold: Option<i32>,
    /// Whether the gateways read this server's engines' own metrics
    /// (`/metrics`) for the dashboards. On by default for vLLM. An endpoint
    /// with a waiting-queue bound is read whatever this says.
    pub engine_metrics: bool,
    /// Whether the gateways LEARN each endpoint's in-flight limit from its
    /// engine's readings (KV-cache use, preemptions, prefix-cache hit rate),
    /// `max_in_flight` being the ceiling. Excludes a waiting-queue bound; the
    /// engines are read whatever `engine_metrics` says.
    pub adaptive_concurrency: bool,
    /// The token-latency target the learned limit keeps each engine within:
    /// no raise while the engine's inter-token latency is above it, and a step
    /// down when it stays above it. `auto` (the default) is a multiple of each
    /// engine's own time per token at low load, as the gateways learn it;
    /// `fixed` is `ms`; `off` grows the limit as far as the engine's memory
    /// holds.
    pub adaptive_itl_target: ItlTarget,
}

#[derive(Serialize, ToSchema)]
pub struct ServerDetailResponse {
    #[serde(flatten)]
    #[schema(inline)]
    pub server: ServerResponse,
    pub models: Vec<ModelResponse>,
    /// The provider is vLLM, read as every other provider check reads it:
    /// the QoS tab shows that engine's settings.
    pub vllm_engine: bool,
    /// What an automatic token-latency target is now, in milliseconds:
    /// `AUTO_ITL_TARGET_RATIO` times the slowest engine's time per token at
    /// low load, as the connected gateways report it
    /// (`ServerLive::auto_itl_target_ms`; each engine is held to its own
    /// figure's). `null` while the limit is not learned, or no engine has
    /// taught one yet — an automatic target is then still learning. Reported
    /// whatever the setting.
    pub auto_itl_target_ms: Option<f64>,
}

#[derive(sqlx::FromRow)]
struct ServerRow {
    id: Uuid,
    name: String,
    provider: String,
    encrypted_key: Option<String>,
    upstream_url: Option<String>,
    upstream_api_format: String,
    #[sqlx(default)]
    chat_endpoint_path: Option<String>,
    #[sqlx(default)]
    transport: String,
    enabled: bool,
    is_builtin: bool,
    created_at: chrono::DateTime<chrono::Utc>,
    model_count: Option<i64>,
    #[sqlx(default)]
    auto_sync_enabled: bool,
    #[sqlx(default)]
    last_auto_sync_at: Option<chrono::DateTime<chrono::Utc>>,
    #[sqlx(default)]
    last_auto_sync_status: Option<serde_json::Value>,
    #[sqlx(default)]
    scheduling_dialect: String,
    #[sqlx(default)]
    max_in_flight: Option<i32>,
    #[sqlx(default)]
    waiting_threshold: Option<i32>,
    #[sqlx(default)]
    engine_metrics: bool,
    #[sqlx(default)]
    adaptive_concurrency: bool,
    #[sqlx(default)]
    adaptive_itl_target_ms: Option<i32>,
    #[sqlx(default)]
    adaptive_itl_target_mode: String,
    /// Defaulted because the create/update `RETURNING` clauses do not compute
    /// it; the list/get SELECTs project it from the linked downstream.
    #[sqlx(default)]
    byok: bool,
    /// Projected by the list/get SELECTs ([`endpoint_summary_columns`]).
    #[sqlx(default)]
    endpoint_count: Option<i64>,
    #[sqlx(default)]
    endpoints_enabled: Option<i64>,
    #[sqlx(default)]
    endpoints_down: Option<i64>,
    #[sqlx(default)]
    endpoints_out: Option<i64>,
    #[sqlx(default)]
    gated: Option<bool>,
}

/// What decides whether a server's learned limit clashes with a queue bound.
#[derive(sqlx::FromRow)]
struct AdaptiveFacts {
    adaptive: bool,
    /// The server declares an engine-queue bound.
    server_bound: bool,
    /// Some endpoint of it (disabled ones included) declares one of its own.
    endpoint_bound: bool,
}

/// The one reading of [`AdaptiveFacts`], for the up-front check and the
/// re-check inside the write's transaction alike.
async fn adaptive_facts(conn: &mut Scoped, id: Uuid) -> Result<AdaptiveFacts, sqlx::Error> {
    sqlx::query_as(
        "SELECT s.adaptive_concurrency AS adaptive, s.waiting_threshold IS NOT NULL AS server_bound, \
                EXISTS (SELECT 1 FROM upstream_server_endpoints e \
                        WHERE e.server_id = s.id AND e.waiting_threshold IS NOT NULL) AS endpoint_bound \
         FROM upstream_servers s WHERE s.id = $1",
    )
    .bind(id)
    .fetch_one(conn)
    .await
}

/// A learned in-flight limit and an engine-queue bound on one server: the
/// window is steered by the same engine queue, so the two would fight over it.
pub(crate) fn adaptive_with_queue_bound() -> ApiError {
    ApiError::bad_request(
        "A learned in-flight limit replaces the engine-queue bound: clear the queue bound \
         (on the server and on every endpoint) or turn the learned limit off",
    )
    .code(ApiErrorCode::ValidationFailed)
}

/// Whether a new server's engines' own metrics are read. An engine that
/// publishes them (vLLM) is read unless the operator turns it off; any other
/// provider is not asked, since nothing there would answer.
pub(crate) fn engine_metrics_by_default(provider: &str) -> bool {
    matches!(Provider::from_str_relaxed(provider.trim()), Provider::Vllm)
}

/// The endpoint summary a server listing shows: how many endpoints, how many
/// are enabled and out of rotation ([`server_health_columns_sql`]), and whether
/// the dispatch gate applies.
fn endpoint_summary_columns() -> String {
    format!(
        "(SELECT COUNT(*) FROM upstream_server_endpoints e WHERE e.server_id = s.id) AS endpoint_count, \
         {}, \
         (s.max_in_flight IS NOT NULL OR s.waiting_threshold IS NOT NULL OR s.adaptive_concurrency OR EXISTS ( \
           SELECT 1 FROM upstream_server_endpoints e WHERE e.server_id = s.id AND e.enabled \
             AND (e.max_in_flight IS NOT NULL OR e.waiting_threshold IS NOT NULL))) AS gated",
        server_health_columns_sql()
    )
}

impl From<ServerRow> for ServerResponse {
    fn from(row: ServerRow) -> Self {
        Self {
            id: row.id,
            name: row.name,
            provider: row.provider,
            has_credential: row.encrypted_key.is_some(),
            byok: row.byok,
            upstream_url: row.upstream_url,
            upstream_api_format: row.upstream_api_format,
            chat_endpoint_path: row.chat_endpoint_path,
            transport: if row.transport.is_empty() {
                UpstreamTransport::Default.as_str().to_string()
            } else {
                row.transport
            },
            enabled: row.enabled,
            is_builtin: row.is_builtin,
            created_at: row.created_at,
            model_count: row.model_count.unwrap_or(0),
            auto_sync_enabled: row.auto_sync_enabled,
            last_auto_sync_at: row.last_auto_sync_at,
            last_auto_sync_status: row.last_auto_sync_status.and_then(AutoSyncStatus::from_stored),
            endpoint_count: row.endpoint_count.unwrap_or(0),
            endpoints_down: row.endpoints_down.unwrap_or(0),
            health: ServerHealth::of(
                row.enabled,
                row.endpoints_enabled.unwrap_or(0),
                row.endpoints_down.unwrap_or(0),
                row.endpoints_out.unwrap_or(0),
            ),
            gated: row.gated.unwrap_or(false),
            scheduling_dialect: if row.scheduling_dialect.is_empty() {
                streamscope_core::config::qos::SchedulingDialect::None.as_str().to_string()
            } else {
                row.scheduling_dialect
            },
            max_in_flight: row.max_in_flight,
            waiting_threshold: row.waiting_threshold,
            engine_metrics: row.engine_metrics,
            adaptive_concurrency: row.adaptive_concurrency,
            adaptive_itl_target: itl_target_of(&row.adaptive_itl_target_mode, row.adaptive_itl_target_ms),
        }
    }
}

impl ServerResponse {
    /// A server just created has exactly its primary endpoint, enabled, which
    /// no gateway has reported on: its summary is known without reading it
    /// back — and a read after the commit could only turn a create that
    /// succeeded into an error the caller would retry into a duplicate.
    fn into_created(mut self) -> Self {
        self.endpoint_count = 1;
        self.endpoints_down = 0;
        self.health = ServerHealth::of(self.enabled, 1, 0, 0);
        self.gated = self.max_in_flight.is_some() || self.waiting_threshold.is_some() || self.adaptive_concurrency;
        self
    }
}

/// Fill a response built from a write's `RETURNING` row — which carries no
/// URL and no endpoint summary — with the server's primary URL, endpoints,
/// health and gating as they stand now, read by the same columns the listing
/// uses. Without it a write's answer would state the defaults: no URL and no
/// endpoint, so a new server reads as down.
async fn with_endpoint_summary(
    conn: &mut Scoped,
    mut resp: ServerResponse,
) -> Result<ServerResponse, ApiError> {
    #[allow(clippy::type_complexity)]
    let (upstream_url, endpoint_count, endpoints_enabled, endpoints_down, endpoints_out, gated): (Option<String>, i64, i64, i64, i64, bool) =
        sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {url} AS upstream_url, {} FROM upstream_servers s WHERE s.id = $1",
            endpoint_summary_columns(),
            url = server_url_sql!("s"),
        )))
        .bind(resp.id)
        .fetch_one(conn)
        .await
        .map_err(|e| {
            tracing::error!(server_id = %resp.id, "server endpoint summary: {e}");
            ApiError::internal("failed to read the server")
        })?;
    resp.upstream_url = upstream_url;
    resp.endpoint_count = endpoint_count;
    resp.endpoints_down = endpoints_down;
    resp.health = ServerHealth::of(resp.enabled, endpoints_enabled, endpoints_down, endpoints_out);
    resp.gated = gated;
    Ok(resp)
}

// ---------------------------------------------------------------------------
// Model types
// ---------------------------------------------------------------------------

#[derive(Deserialize, ToSchema)]
pub struct CreateModelRequest {
    pub upstream_model: String,
    pub context_window: Option<i32>,
    pub max_output_tokens: Option<i32>,
    pub upstream_api_format: Option<String>,
    pub model_type: Option<String>,
    /// Explicit catalog entry to inherit from. NULL = auto-match by canonical name.
    #[serde(default)]
    pub catalog_model_id: Option<Uuid>,
    #[serde(default)]
    pub supports_vision: Option<bool>,
    #[serde(default)]
    pub supports_reasoning: Option<bool>,
    #[serde(default)]
    pub supports_function_calling: Option<bool>,
    #[serde(default)]
    pub supports_caching: Option<bool>,
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
    /// Per-model self-healing override. NULL = inherit the tenant `healing_enabled`.
    #[serde(default)]
    pub healing_enabled: Option<bool>,
    /// Price override, replacing the catalog's map WHOLE (omitted = inherit it).
    /// All-or-nothing by design: a price list is one provider's quote in one
    /// currency, so taking half of it from the catalog is the borrowed-price
    /// hazard the provider-matched ladder exists to prevent. An empty map is an
    /// operator saying "no price", and does not fall through to the catalog.
    #[serde(default)]
    pub rates: Option<Rates>,
}

#[derive(Deserialize, ToSchema)]
pub struct BatchCreateModelsRequest {
    pub models: Vec<CreateModelRequest>,
    /// True when these values were read from the provider's own discovery (the
    /// sync-review apply), false when an operator typed them (the default).
    ///
    /// It decides whether the inheritable fields are **pinned**: a value the
    /// operator supplied is theirs and must survive every later refresh, while a
    /// discovered one must keep tracking the provider. Both meanings arrive on
    /// this one endpoint, and they are indistinguishable from the payload alone.
    /// The default is the safe direction — an unmarked caller pins, which
    /// preserves a value rather than silently overwriting it later.
    #[serde(default)]
    pub from_discovery: bool,
}

/// The inheritable fields — the ones that resolve `model → catalog → default`
/// and that `user_overridden_caps` can pin. Expands to `[(name, was_set); N]`
/// for any request struct carrying these field names.
///
/// It is a macro so the list exists **once**: the create and update paths take
/// different request types but must agree exactly on which fields are pinnable.
/// When they disagreed, a price typed on one path was silently refreshable while
/// the same price typed on the other was not. Add a field here and both paths
/// get it.
macro_rules! inheritable_field_presence {
    ($req:expr) => {
        [
            ("context_window", $req.context_window.is_some()),
            ("max_output_tokens", $req.max_output_tokens.is_some()),
            ("supports_vision", $req.supports_vision.is_some()),
            ("supports_reasoning", $req.supports_reasoning.is_some()),
            ("supports_function_calling", $req.supports_function_calling.is_some()),
            ("supports_caching", $req.supports_caching.is_some()),
            ("supports_audio_input", $req.supports_audio_input.is_some()),
            ("supports_audio_output", $req.supports_audio_output.is_some()),
            ("supports_video_input", $req.supports_video_input.is_some()),
            ("supports_pdf_input", $req.supports_pdf_input.is_some()),
            ("supports_response_schema", $req.supports_response_schema.is_some()),
            ("supports_system_messages", $req.supports_system_messages.is_some()),
            ("healing_enabled", $req.healing_enabled.is_some()),
            // Pricing is ONE pinnable field: the rate map is inherited whole, so
            // it is pinned whole.
            ("rates", $req.rates.is_some()),
        ]
    };
}

/// The names of the inheritable fields the caller actually set — what gets
/// recorded in `user_overridden_caps` so a later catalog change or autosync
/// refresh cannot rewrite them.
fn pinned_field_names<const N: usize>(presence: [(&'static str, bool); N]) -> Vec<String> {
    presence
        .into_iter()
        .filter(|(_, set)| *set)
        .map(|(name, _)| name.to_string())
        .collect()
}

/// Where a resolved field value comes from, for the model editor's per-field
/// source badge. `User` = operator pinned it (in `user_overridden_fields`);
/// `Synced` = a provider discovery wrote it; `Catalog` = inherited from the
/// linked/matched catalog entry; `Default` = the built-in baseline.
#[derive(Serialize, ToSchema, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum FieldSource {
    User,
    Synced,
    Catalog,
    Default,
}

#[derive(Serialize, ToSchema)]
pub struct ModelResponse {
    pub id: Uuid,
    pub server_id: Uuid,
    pub server_name: String,
    pub provider: String,
    pub upstream_model: String,
    pub upstream_url: Option<String>,
    pub context_window: Option<i32>,
    pub max_output_tokens: Option<i32>,
    pub resolved_context_window: Option<i32>,
    pub resolved_max_output_tokens: Option<i32>,
    pub upstream_api_format: Option<String>,
    pub model_type: Option<String>,
    pub enabled: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub route_count: i64,
    /// Explicit catalog link (NULL = auto-match by canonical name).
    pub catalog_model_id: Option<Uuid>,
    /// Catalog entry actually used to resolve this model (link or auto-match).
    pub resolved_catalog_model_id: Option<Uuid>,
    /// Fields the operator has explicitly pinned (caps + pricing + token limits).
    pub user_overridden_fields: Vec<String>,
    /// Per-field provenance of the resolved value, keyed by field name.
    pub sources: std::collections::HashMap<String, FieldSource>,
    // Raw capability values (what's stored on upstream_models, NULL = inherit from catalog)
    pub supports_vision: Option<bool>,
    pub supports_reasoning: Option<bool>,
    pub supports_function_calling: Option<bool>,
    pub supports_caching: Option<bool>,
    pub supports_audio_input: Option<bool>,
    pub supports_audio_output: Option<bool>,
    pub supports_video_input: Option<bool>,
    pub supports_pdf_input: Option<bool>,
    pub supports_response_schema: Option<bool>,
    pub supports_system_messages: Option<bool>,
    /// Per-model self-healing override (NULL = inherit the tenant `healing_enabled`).
    pub healing_enabled: Option<bool>,
    // Resolved capabilities (COALESCE'd with catalog)
    pub resolved_supports_vision: bool,
    pub resolved_supports_reasoning: bool,
    pub resolved_supports_function_calling: bool,
    pub resolved_supports_caching: bool,
    pub resolved_supports_audio_input: bool,
    pub resolved_supports_audio_output: bool,
    pub resolved_supports_video_input: bool,
    pub resolved_supports_pdf_input: bool,
    pub resolved_supports_response_schema: bool,
    pub resolved_supports_system_messages: bool,
    /// Stored price override (null = inherit the catalog's map whole).
    pub rates: Option<Rates>,
    /// Price actually in force: this model's own map, else the map of the
    /// catalog row for the SAME provider, else empty (no price known).
    pub resolved_rates: Rates,
}

#[derive(sqlx::FromRow)]
struct ModelRow {
    id: Uuid,
    server_id: Uuid,
    server_name: String,
    provider: String,
    upstream_model: String,
    upstream_url: Option<String>,
    context_window: Option<i32>,
    max_output_tokens: Option<i32>,
    upstream_api_format: Option<String>,
    model_type: Option<String>,
    enabled: bool,
    created_at: chrono::DateTime<chrono::Utc>,
    route_count: Option<i64>,
    #[sqlx(default)]
    resolved_context_window: Option<i32>,
    #[sqlx(default)]
    resolved_max_output_tokens: Option<i32>,
    #[sqlx(default)]
    catalog_model_id: Option<Uuid>,
    #[sqlx(default)]
    resolved_catalog_model_id: Option<Uuid>,
    #[sqlx(default)]
    user_overridden_fields: Vec<String>,
    // Catalog's own price map — needed to tell "inherited from the catalog" from
    // "nobody knows", which the resolved map alone cannot distinguish (both are
    // an empty map).
    #[sqlx(default, json(nullable))]
    catalog_rates: Option<Rates>,
    // Raw capability values
    #[sqlx(default)]
    supports_vision: Option<bool>,
    #[sqlx(default)]
    supports_reasoning: Option<bool>,
    #[sqlx(default)]
    supports_function_calling: Option<bool>,
    #[sqlx(default)]
    supports_caching: Option<bool>,
    #[sqlx(default)]
    supports_audio_input: Option<bool>,
    #[sqlx(default)]
    supports_audio_output: Option<bool>,
    #[sqlx(default)]
    supports_video_input: Option<bool>,
    #[sqlx(default)]
    supports_pdf_input: Option<bool>,
    #[sqlx(default)]
    supports_response_schema: Option<bool>,
    #[sqlx(default)]
    supports_system_messages: Option<bool>,
    #[sqlx(default)]
    healing_enabled: Option<bool>,
    // Resolved capabilities
    #[sqlx(default)]
    resolved_supports_vision: Option<bool>,
    #[sqlx(default)]
    resolved_supports_reasoning: Option<bool>,
    #[sqlx(default)]
    resolved_supports_function_calling: Option<bool>,
    #[sqlx(default)]
    resolved_supports_caching: Option<bool>,
    #[sqlx(default)]
    resolved_supports_audio_input: Option<bool>,
    #[sqlx(default)]
    resolved_supports_audio_output: Option<bool>,
    #[sqlx(default)]
    resolved_supports_video_input: Option<bool>,
    #[sqlx(default)]
    resolved_supports_pdf_input: Option<bool>,
    #[sqlx(default)]
    resolved_supports_response_schema: Option<bool>,
    #[sqlx(default)]
    resolved_supports_system_messages: Option<bool>,
    // Stored price override (NULL = inherit the catalog's map whole).
    #[sqlx(default, json(nullable))]
    rates: Option<Rates>,
    // Price in force: own map, else the same-provider catalog row's, else empty.
    #[sqlx(json)]
    resolved_rates: Rates,
}

impl From<ModelRow> for ModelResponse {
    fn from(row: ModelRow) -> Self {
        // Per-field provenance: a raw (stored) value is the operator's pick when
        // it's pinned, else a discovered/synced value; a NULL column inherits
        // from the catalog when the catalog supplied a value, else the default.
        let overridden: std::collections::HashSet<String> =
            row.user_overridden_fields.iter().cloned().collect();
        let mut sources = std::collections::HashMap::new();
        let mut src = |name: &str, raw_set: bool, catalog_set: bool| {
            let s = if raw_set {
                if overridden.contains(name) { FieldSource::User } else { FieldSource::Synced }
            } else if catalog_set {
                FieldSource::Catalog
            } else {
                FieldSource::Default
            };
            sources.insert(name.to_string(), s);
        };
        src("context_window", row.context_window.is_some(), row.resolved_context_window.is_some());
        src("max_output_tokens", row.max_output_tokens.is_some(), row.resolved_max_output_tokens.is_some());
        src("supports_vision", row.supports_vision.is_some(), row.resolved_supports_vision.is_some());
        src("supports_reasoning", row.supports_reasoning.is_some(), row.resolved_supports_reasoning.is_some());
        src("supports_function_calling", row.supports_function_calling.is_some(), row.resolved_supports_function_calling.is_some());
        src("supports_caching", row.supports_caching.is_some(), row.resolved_supports_caching.is_some());
        src("supports_audio_input", row.supports_audio_input.is_some(), row.resolved_supports_audio_input.is_some());
        src("supports_audio_output", row.supports_audio_output.is_some(), row.resolved_supports_audio_output.is_some());
        src("supports_video_input", row.supports_video_input.is_some(), row.resolved_supports_video_input.is_some());
        src("supports_pdf_input", row.supports_pdf_input.is_some(), row.resolved_supports_pdf_input.is_some());
        src("supports_response_schema", row.supports_response_schema.is_some(), row.resolved_supports_response_schema.is_some());
        src("supports_system_messages", row.supports_system_messages.is_some(), row.resolved_supports_system_messages.is_some());
        // Pricing is one field: the map is inherited whole, so it has one source.
        // A catalog row that carries capabilities but no prices supplies nothing,
        // so an empty catalog map counts as "no catalog price".
        src(
            "rates",
            row.rates.is_some(),
            row.catalog_rates.as_ref().is_some_and(|r| !r.is_empty()),
        );

        Self {
            id: row.id,
            resolved_context_window: row.resolved_context_window,
            resolved_max_output_tokens: row.resolved_max_output_tokens,
            catalog_model_id: row.catalog_model_id,
            resolved_catalog_model_id: row.resolved_catalog_model_id,
            user_overridden_fields: row.user_overridden_fields,
            sources,
            server_id: row.server_id,
            server_name: row.server_name,
            provider: row.provider,
            upstream_model: row.upstream_model,
            upstream_url: row.upstream_url,
            context_window: row.context_window,
            max_output_tokens: row.max_output_tokens,
            upstream_api_format: row.upstream_api_format,
            model_type: row.model_type,
            enabled: row.enabled,
            created_at: row.created_at,
            route_count: row.route_count.unwrap_or(0),
            // Raw capability values
            supports_vision: row.supports_vision,
            supports_reasoning: row.supports_reasoning,
            supports_function_calling: row.supports_function_calling,
            supports_caching: row.supports_caching,
            supports_audio_input: row.supports_audio_input,
            supports_audio_output: row.supports_audio_output,
            supports_video_input: row.supports_video_input,
            supports_pdf_input: row.supports_pdf_input,
            supports_response_schema: row.supports_response_schema,
            supports_system_messages: row.supports_system_messages,
            healing_enabled: row.healing_enabled,
            // Resolved capabilities: NULL falls back to the standard text-LLM
            // baseline — the SAME constants the proxy resolves with, so admin
            // display never drifts from enforcement.
            resolved_supports_vision: row.resolved_supports_vision.unwrap_or(Caps::DEFAULT_VISION),
            resolved_supports_reasoning: row.resolved_supports_reasoning.unwrap_or(Caps::DEFAULT_REASONING),
            resolved_supports_function_calling: row.resolved_supports_function_calling.unwrap_or(Caps::DEFAULT_FUNCTION_CALLING),
            resolved_supports_caching: row.resolved_supports_caching.unwrap_or(Caps::DEFAULT_CACHING),
            resolved_supports_audio_input: row.resolved_supports_audio_input.unwrap_or(Caps::DEFAULT_AUDIO_INPUT),
            resolved_supports_audio_output: row.resolved_supports_audio_output.unwrap_or(Caps::DEFAULT_AUDIO_OUTPUT),
            resolved_supports_video_input: row.resolved_supports_video_input.unwrap_or(Caps::DEFAULT_VIDEO_INPUT),
            resolved_supports_pdf_input: row.resolved_supports_pdf_input.unwrap_or(Caps::DEFAULT_PDF_INPUT),
            resolved_supports_response_schema: row.resolved_supports_response_schema.unwrap_or(Caps::DEFAULT_RESPONSE_SCHEMA),
            resolved_supports_system_messages: row.resolved_supports_system_messages.unwrap_or(Caps::DEFAULT_SYSTEM_MESSAGES),
            rates: row.rates,
            resolved_rates: row.resolved_rates,
        }
    }
}

/// Built once from the shared [`catalog_join`], so this read path and every other
/// resolution site inherit the same capability/pricing ladders.
static MODEL_SELECT: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    format!("{MODEL_SELECT_HEAD}{}", crate::routes::catalog_join("m", "s"))
});

const MODEL_SELECT_HEAD: &str = concat!(r#"
    SELECT m.id, m.server_id, s.name as server_name, s.provider,
           m.upstream_model, "#, server_url_sql!("s"), r#" AS upstream_url,
           m.context_window, m.max_output_tokens,
           COALESCE(m.context_window, c.context_window) as resolved_context_window,
           "#, resolved_max_output_sql!("m", "c"), r#" as resolved_max_output_tokens,
           COALESCE(m.upstream_api_format, s.upstream_api_format) as upstream_api_format,
           m.model_type,
           m.enabled, m.created_at,
           m.catalog_model_id, c.catalog_match_id as resolved_catalog_model_id,
           m.user_overridden_caps as user_overridden_fields,
           (SELECT COUNT(*) FROM downstream_routes dr WHERE dr.model_id = m.id)::bigint as route_count,
           -- Raw capability values (what's stored on upstream_models)
           m.supports_vision, m.supports_reasoning, m.supports_function_calling, m.supports_caching,
           m.supports_audio_input, m.supports_audio_output, m.supports_video_input, m.supports_pdf_input,
           m.supports_response_schema, m.supports_system_messages,
           m.healing_enabled,
           -- Resolved capabilities (COALESCE with catalog)
           COALESCE(m.supports_vision, c.supports_vision) as resolved_supports_vision,
           COALESCE(m.supports_reasoning, c.supports_reasoning) as resolved_supports_reasoning,
           COALESCE(m.supports_function_calling, c.supports_function_calling) as resolved_supports_function_calling,
           COALESCE(m.supports_caching, c.supports_caching) as resolved_supports_caching,
           COALESCE(m.supports_audio_input, c.supports_audio_input) as resolved_supports_audio_input,
           COALESCE(m.supports_audio_output, c.supports_audio_output) as resolved_supports_audio_output,
           COALESCE(m.supports_video_input, c.supports_video_input) as resolved_supports_video_input,
           COALESCE(m.supports_pdf_input, c.supports_pdf_input) as resolved_supports_pdf_input,
           COALESCE(m.supports_response_schema, c.supports_response_schema) as resolved_supports_response_schema,
           COALESCE(m.supports_system_messages, c.supports_system_messages) as resolved_supports_system_messages,
           -- Stored price override (what's on upstream_models)
           m.rates,
           -- Resolved price. Pricing comes from `catp`, which only ever matches a
           -- catalog row of the SAME provider — never another vendor's price for a
           -- like-named model. The map is inherited WHOLE: a row either quotes its
           -- own prices or takes the catalog's, never a mixture.
           COALESCE(m.rates, catp.rates, '{}'::jsonb) as resolved_rates,
           -- The catalog's own map, to tell an inherited price from an unknown one
           -- (the resolved map is empty in both cases).
           catp.rates as catalog_rates
    FROM upstream_models m
    JOIN upstream_servers s ON s.id = m.server_id"#);

const MODEL_GROUP_BY: &str = "";

/// Reference implementation of the canonical catalog key. Catalog matching runs
/// in SQL at every resolution site via the `canonical_catalog_key(text)` function;
/// this Rust twin exists only to pin that SQL with a unit test. Keep the two
/// byte-for-byte identical: strip the vendor path up to the LAST `/`
/// (`accounts/fireworks/models/deepseek-v3` → `deepseek-v3`), strip a Bedrock
/// cross-region inference-profile prefix (`us.anthropic.claude-…` →
/// `anthropic.claude-…`), reduce an `ft:` fine-tune to `ft:<base>`
/// (`ft:gpt-4o:org::id` → `ft:gpt-4o`) or take the part before the first `:`
/// otherwise (`gpt-4o:extended` → `gpt-4o`), lowercase, dots → dashes (`Qwen3.6` →
/// `qwen3-6`), then strip a trailing `-YYYYMMDD` stamp (`gpt-4o-20240115` →
/// `gpt-4o`).
#[cfg(test)]
pub(crate) fn canonical_catalog_key(upstream_model: &str) -> String {
    let without_path = match upstream_model.rfind('/') {
        Some(pos) => &upstream_model[pos + 1..],
        None => upstream_model,
    };
    let stripped = strip_bedrock_region(without_path);
    let base = match stripped.len() >= 3 && stripped[..3].eq_ignore_ascii_case("ft:") {
        // Both halves are kept: a fine-tune is priced above its base model, so
        // keying on the base alone would hand it the cheaper rate.
        true => format!("ft:{}", stripped[3..].split(':').next().unwrap_or("")),
        false => stripped.split(':').next().unwrap_or(stripped).to_string(),
    };
    let lowered = base.to_lowercase().replace('.', "-");
    strip_trailing_date(&lowered)
}

/// Bedrock addresses a model through a cross-region inference profile, so the id
/// an operator configures carries a region the catalog row does not
/// (`us.anthropic.claude-…` against a catalog `anthropic.claude-…`). Regions of one
/// model share a canonical key deliberately — the capabilities are identical, and
/// per-region pricing belongs to the server, not the model.
#[cfg(test)]
fn strip_bedrock_region(model: &str) -> &str {
    for prefix in ["us-gov.", "us.", "eu.", "apac.", "global."] {
        if model.len() > prefix.len() && model[..prefix.len()].eq_ignore_ascii_case(prefix) {
            return &model[prefix.len()..];
        }
    }
    model
}

/// Reference implementation of the canonical provider key, twin of the SQL
/// `canonical_provider_key(text)` and pinned against it by a unit test — keep the
/// two byte-for-byte identical.
///
/// Squash to lowercase alphanumerics, then fold the known aliases onto the
/// provider vocabulary in `seeds/providers/providers.json`. An unrecognised token
/// passes through squashed rather than collapsing to a catch-all, so a provider we
/// don't model keeps an identity distinct from every other unknown.
///
/// Invariant when extending: every value emitted here must be reachable from BOTH
/// the provider vocabulary AND the catalog seed's own provider column, or a
/// catalog row can never price-match a server. `google` is the live example — an
/// `icon_only` vendor row that is never a selectable upstream, so catalog rows
/// carrying it fold onto `google_gemini`.
#[cfg(test)]
pub(crate) fn canonical_provider_key(provider: &str) -> String {
    let squashed: String = provider
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect();
    let folded = match squashed.as_str() {
        "openai" => "openai",
        "anthropic" => "anthropic",
        "googlegemini" | "gemini" | "google" => "google_gemini",
        "googlevertex" | "googlevertexanthropic" | "vertex" | "vertexai" => "google_vertex",
        "azureopenai" | "azure" => "azure_openai",
        "awsbedrock" | "amazonbedrock" | "bedrock" => "aws_bedrock",
        "openrouter" => "openrouter",
        "deepseek" => "deepseek",
        "together" | "togetherai" => "together",
        "fireworks" | "fireworksai" => "fireworks",
        "moonshot" | "moonshotai" => "moonshot",
        "nvidia" | "nim" | "nvidianim" => "nvidia",
        "ollama" | "ollamacloud" => "ollama",
        "groq" => "groq",
        "mistral" => "mistral",
        "xai" => "xai",
        "vllm" => "vllm",
        "custom" => "custom",
        // Meta's own API is the `llama` provider; `meta` is the icon-only
        // vendor row, so fold it there rather than leaving it unreachable.
        "meta" | "metallama" | "llama" => "llama",
        _ => return squashed,
    };
    folded.to_string()
}

/// Strip a trailing `-YYYYMMDD` (a dash + literal `20` + six digits = 9 chars)
/// date stamp, matching the SQL `'-20[0-9]{6}$'` replacement.
#[cfg(test)]
fn strip_trailing_date(s: &str) -> String {
    let bytes = s.as_bytes();
    if bytes.len() >= 9 {
        let tail = &bytes[bytes.len() - 9..];
        if tail[0] == b'-'
            && tail[1] == b'2'
            && tail[2] == b'0'
            && tail[3..].iter().all(u8::is_ascii_digit)
        {
            return s[..s.len() - 9].to_string();
        }
    }
    s.to_string()
}

// ---------------------------------------------------------------------------
// Provider metadata
// ---------------------------------------------------------------------------

#[derive(Serialize, ToSchema)]
pub struct ProviderMeta {
    pub value: String,
    /// Display label (e.g. "OpenAI").
    pub label: String,
    /// 24x24 fill SVG path for the provider's brand glyph.
    pub icon: String,
    pub default_url: Option<String>,
    pub default_upstream_api_format: String,
    /// Provider seed's chat-completions endpoint path override (null = canonical
    /// `/v1/chat/completions`). Lets the UI prefill the field when a provider is
    /// picked.
    pub default_chat_endpoint_path: Option<String>,
}

/// Returns the canonical provider catalog — label, icon, default URL, and native
/// API format — read from the single-source provider seed. Backs the UI provider
/// dropdown, brand icons, and URL auto-fill. `icon_only` seed rows (registry
/// glyphs that aren't selectable providers) are excluded.
#[utoipa::path(
    get,
    path = "/api/v1/admin/servers/provider-defaults",
    tag = "Servers",
    responses(
        (status = 200, description = "Provider metadata (from the provider seed)", body = TotalPage<ProviderMeta>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_provider_defaults() -> Json<TotalPage<ProviderMeta>> {
    let list: Vec<ProviderMeta> = crate::seed_loader::provider_catalog()
        .iter()
        .filter(|p| !p.icon_only)
        .map(|p| ProviderMeta {
            value: p.provider.clone(),
            label: p.label.clone(),
            icon: p.icon.clone(),
            default_url: p.default_url.clone(),
            default_upstream_api_format: p.default_api_format.clone(),
            default_chat_endpoint_path: p.chat_endpoint_path.clone(),
        })
        .collect();
    let total = list.len() as i64;
    Json(TotalPage::new(list, total, 0, total))
}

// ---------------------------------------------------------------------------
// Server CRUD
// ---------------------------------------------------------------------------

#[utoipa::path(
    post,
    path = "/api/v1/admin/servers",
    tag = "Servers",
    request_body = CreateServerRequest,
    responses(
        (status = 201, description = "Server created", body = ServerResponse),
        (status = 400, description = "Invalid request", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 409, description = "Server name already exists", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_server(
    mut db: TenantConn,
    Json(req): Json<CreateServerRequest>,
) -> Result<(StatusCode, Json<ServerResponse>), ApiError> {
    if let Some(fmt) = &req.upstream_api_format
        && !VALID_API_FORMATS.contains(&fmt.as_str())
    {
        return Err(ApiError::bad_request("invalid upstream_api_format").code(ApiErrorCode::ApiFormatInvalid));
    }

    let upstream_url = resolve_server_url(req.upstream_url.clone(), &req.provider)?;

    let upstream_api_format: String = req
        .upstream_api_format
        .clone()
        .or_else(|| crate::seed_loader::provider_default_api_format(&req.provider))
        .unwrap_or_else(|| "chat_completions".to_string());

    // Endpoint-path override: a validated explicit request value wins; a blank/absent
    // one falls back to the provider seed's path (populated for providers whose
    // OpenAI-compatible chat endpoint isn't the canonical `{url}/v1/chat/completions`).
    // None = canonical.
    let chat_endpoint_path = match normalize_chat_endpoint_path(req.chat_endpoint_path.clone())? {
        Some(p) => Some(p),
        None => crate::seed_loader::provider_chat_endpoint_path(&req.provider),
    };

    let tenant_id = db.tenant_uuid();
    // A BYOK provider is keyless (the client forwards its own credential) and has
    // no discovery/mirror — its downstream is empty (pure pass-through). Force
    // autosync off and drop any supplied key.
    let byok = req.byok.unwrap_or(false);
    let transport = resolve_transport(TransportRequest {
        requested: req.transport.as_deref(),
        provider: &req.provider,
        upstream_api_format: &upstream_api_format,
        chat_endpoint_path: chat_endpoint_path.as_deref(),
        upstream_url: Some(upstream_url.as_str()),
        api_key: req.api_key.as_deref(),
        byok,
        existing: None,
    })?;
    let resolved_transport = UpstreamTransport::from_str_relaxed(&transport);
    // Autosync is the single switch that owns the mirror: on (default) ⇒ discover
    // models + maintain a same-named mirror downstream; off ⇒ manual server.
    // What cannot be discovered must not be left switched on: neither the
    // provider nor the transport would answer, so every run — the inline first
    // sync included — would fail with nothing for the operator to fix. The same
    // two facts hide the toggle in the console, so a server created there is
    // stored as the console already describes it.
    let auto_sync = if byok || !can_discover(&req.provider, resolved_transport) {
        false
    } else {
        req.auto_sync_enabled.unwrap_or(true)
    };

    if !req.force {
        // Refresh the trusted-CA cache from the DB so a just-imported custom CA
        // applies to this request's probe + discovery on any replica.
        crate::custom_ca::refresh_from_conn(db.conn()).await;

        // When autosync is on, the server creates a mirror downstream of the same
        // name below. Reject up front if that name already belongs to a downstream
        // provider so the mirror can't silently re-point an unrelated one (a
        // duplicate upstream name is caught by the unique index on insert).
        if auto_sync || byok {
            let name_taken: Option<Uuid> = sqlx::query_scalar(
                "SELECT id FROM downstream_providers WHERE tenant_id = $1 AND name = $2",
            )
            .bind(tenant_id)
            .bind(&req.name)
            .fetch_optional(db.conn())
            .await
            .map_err(|e| {
                tracing::error!("create server downstream-name check: {e}");
                ApiError::internal("failed to create server")
            })?;
            if name_taken.is_some() {
                return Err(ApiError::conflict("name already in use by a downstream provider", ApiErrorCode::ServerNameTaken));
            }
        }

        // `force` ("Save anyway") skips the reachability probe. A BYOK upstream is
        // keyless — there's no credential to probe with, so skip it too. Providers
        // with no model-listing endpoint (the probe target) are also skipped — else
        // a correct base URL would surface a spurious 404.
        if !byok && probe_is_worth_making(&req.provider, resolved_transport) {
            probe_upstream_liveness(&upstream_url, &upstream_api_format, req.api_key.as_deref(), chat_endpoint_path.as_deref(), resolved_transport).await?;
        }
    }

    // BYOK upstreams store no credential — the client forwards its own.
    let (encrypted_key, credential_nonce) =
        encrypt_api_key(if byok { None } else { req.api_key.as_deref() })?;

    // The server row, its primary endpoint and (for BYOK) its pass-through
    // downstream land together or not at all.
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("create server begin: {e}");
        ApiError::internal("failed to create server")
    })?;
    let mut row = sqlx::query_as::<_, ServerRow>(
        r#"INSERT INTO upstream_servers (name, provider, encrypted_key, credential_nonce, upstream_api_format, chat_endpoint_path, tenant_id, auto_sync_enabled, transport, engine_metrics)
           VALUES ($1, $2, $3, $4, $5, $6, $7, COALESCE($8, true), $10, $11)
           RETURNING id, name, provider, encrypted_key, NULL::text AS upstream_url, upstream_api_format, chat_endpoint_path, transport, enabled, is_builtin, created_at, 0::bigint as model_count,
                         scheduling_dialect, max_in_flight, waiting_threshold, engine_metrics, adaptive_concurrency, adaptive_itl_target_ms, adaptive_itl_target_mode,
                     auto_sync_enabled, last_auto_sync_at, last_auto_sync_status, $9::bool AS byok"#,
    )
    .bind(&req.name)
    .bind(&req.provider)
    .bind(&encrypted_key)
    .bind(&credential_nonce)
    .bind(&upstream_api_format)
    .bind(&chat_endpoint_path)
    .bind(tenant_id)
    // Persist the COMPUTED autosync (forced off for BYOK) — not the raw request
    // field, which would COALESCE to true and have the worker run unauthenticated
    // discovery against the keyless upstream.
    .bind(Some(auto_sync))
    // The BYOK downstream is created just after this INSERT, so the EXISTS the
    // list/get SELECTs use isn't true yet — report the computed flag directly.
    .bind(byok)
    .bind(&transport)
    .bind(engine_metrics_by_default(&req.provider))
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        // `idx_upstream_servers_name` is the only unique index this INSERT can
        // trip, so the SQLSTATE alone identifies it — matching the index NAME in
        // the error text would make an ordinary migration rename downgrade this
        // 409 to a 500, silently and only on the conflict path.
        if super::is_unique_violation(&e) {
            return ApiError::conflict("server name already exists", ApiErrorCode::ServerNameTaken);
        }
        tracing::error!("create server: {e}");
        ApiError::internal("failed to create server")
    })?;
    // The server's URL is its first endpoint.
    row.upstream_url = Some(
        super::upstream_endpoints::write_primary_url(&mut tx, tenant_id, row.id, &upstream_url)
            .await
            .map_err(|e| {
                tracing::error!("create server primary endpoint: {e}");
                ApiError::internal("failed to create server")
            })?,
    );

    if byok {
        // Create the empty BYOK downstream (pure pass-through) linked to this
        // keyless upstream. No discovery/mirror — routes added later override
        // individual models; everything else passes through.
        if let Err(e) = sqlx::query(
            "INSERT INTO downstream_providers (tenant_id, name, description, icon, upstream_server_id, is_builtin, byok) \
             VALUES ($1, $2, $3, $4, $5, false, true)",
        )
        .bind(tenant_id)
        .bind(&row.name)
        .bind("Bring-your-own-key pass-through. Empty by default: every model passes through to the provider with the client's own credential. Add a route to override a specific model.")
        .bind(&req.provider)
        .bind(row.id)
        .execute(&mut *tx)
        .await
        {
            tracing::error!("create BYOK downstream: {e}");
            return Err(ApiError::internal("failed to create BYOK downstream"));
        }
    }
    tx.commit().await.map_err(|e| {
        tracing::error!("create server commit: {e}");
        ApiError::internal("failed to create server")
    })?;
    // Auto-create the downstream mirror right away by running an add-only first
    // sync, so the operator doesn't have to click "Sync now". Best-effort: a
    // discovery failure (unreachable provider, empty list) leaves the server
    // created (the background worker reconciles it on its next tick) — never fail
    // the create over a discovery hiccup. Skipped when autosync is off (manual
    // server), or for a forced add (operator can Sync now manually).
    let mut first_sync_failure: Option<AutoSyncStatus> = None;
    if !byok
        && !req.force
        && auto_sync
        && let Err(e) = first_sync_new_server(db.conn(), tenant_id, row.id).await
    {
        let reason = e.reason();
        tracing::warn!(server_id = %row.id, "inline first sync for new server failed: {reason}");
        // The server exists and its models do not. Record WHY on the row, or
        // its page reads exactly like a server nobody has synced yet and the
        // operator learns the reason only by asking for a sync again — but do
        // NOT stamp the attempt: the worker's due window is what reconciles a
        // server whose first contact failed, and marking it would close that
        // window for a whole interval.
        // The response body was built from the INSERT, which predates this
        // write, so an API caller reading it would be told the server is clean.
        // Carry back exactly what the row now holds rather than rebuilding it.
        first_sync_failure = super::model_sync::record_sync_failure(db.conn(), row.id, &reason, false).await.and_then(AutoSyncStatus::from_stored);
    }

    let mut resp = ServerResponse::from(row).into_created();
    // `last_auto_sync_at` stays unset even here: the row still reads as due, and
    // the status carries the failure's own time.
    if first_sync_failure.is_some() {
        resp.last_auto_sync_status = first_sync_failure;
    }
    Ok((StatusCode::CREATED, Json(resp)))
}

/// Run an add-only first sync for a freshly-created server: discover its models
/// and create the mirror downstream provider + auto routes immediately, so the
/// operator doesn't have to click "Sync now". `AutoFirstSync` is add-only — it
/// never disables a route the operator just hand-configured.
async fn first_sync_new_server(
    conn: &mut Scoped,
    tenant_id: Uuid,
    server_id: Uuid,
) -> Result<(), super::model_sync::SyncError> {
    super::model_sync::run_sync(conn, tenant_id, server_id, Some(super::model_sync::SyncMode::AutoFirstSync))
        .await
        .map(|_| ())
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/servers",
    tag = "Servers",
    params(PageQuery),
    responses(
        (status = 200, description = "Paginated list of servers", body = TotalPage<ServerResponse>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_servers(
    mut db: TenantConn,
    Query(page): Query<PageQuery>,
) -> Result<Json<TotalPage<ServerResponse>>, ApiError> {
    let (limit, offset) = page.resolve();
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM upstream_servers")
        .fetch_one(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("count servers: {e}");
            ApiError::internal("failed to list servers")
        })?;
    let summary = endpoint_summary_columns();
    let rows = sqlx::query_as::<_, ServerRow>(sqlx::AssertSqlSafe(format!(
        r#"SELECT s.id, s.name, s.provider, s.encrypted_key, {url} AS upstream_url, s.upstream_api_format, s.chat_endpoint_path, s.transport,
                  s.enabled, s.is_builtin, s.created_at,
                  COUNT(m.id)::bigint as model_count,
                  s.auto_sync_enabled, s.last_auto_sync_at, s.last_auto_sync_status,
                  s.scheduling_dialect, s.max_in_flight, s.waiting_threshold, s.engine_metrics, s.adaptive_concurrency, s.adaptive_itl_target_ms, s.adaptive_itl_target_mode,
                  EXISTS(SELECT 1 FROM downstream_providers d WHERE d.upstream_server_id = s.id AND d.byok = true) AS byok,
                  {summary}
           FROM upstream_servers s
           LEFT JOIN upstream_models m ON m.server_id = s.id
           GROUP BY s.tenant_id, s.id
           ORDER BY s.name LIMIT $1 OFFSET $2"#,
        url = server_url_sql!("s"),
    )))
    .bind(limit)
    .bind(offset)
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("list servers: {e}");
        ApiError::internal("failed to list servers")
    })?;

    let items: Vec<ServerResponse> = rows.into_iter().map(Into::into).collect();
    Ok(Json(TotalPage::new(items, limit, offset, total)))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/servers/{id}",
    tag = "Servers",
    params(("id" = Uuid, Path, description = "Server ID")),
    responses(
        (status = 200, description = "Server details with models", body = ServerDetailResponse),
        (status = 404, description = "Server not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_server(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<ServerDetailResponse>, ApiError> {
    let summary = endpoint_summary_columns();
    let server = sqlx::query_as::<_, ServerRow>(sqlx::AssertSqlSafe(format!(
        r#"SELECT s.id, s.name, s.provider, s.encrypted_key, {url} AS upstream_url, s.upstream_api_format, s.chat_endpoint_path, s.transport,
                  s.enabled, s.is_builtin, s.created_at,
                  COUNT(m.id)::bigint as model_count,
                  s.auto_sync_enabled, s.last_auto_sync_at, s.last_auto_sync_status,
                  s.scheduling_dialect, s.max_in_flight, s.waiting_threshold, s.engine_metrics, s.adaptive_concurrency, s.adaptive_itl_target_ms, s.adaptive_itl_target_mode,
                  EXISTS(SELECT 1 FROM downstream_providers d WHERE d.upstream_server_id = s.id AND d.byok = true) AS byok,
                  {summary}
           FROM upstream_servers s
           LEFT JOIN upstream_models m ON m.server_id = s.id
           WHERE s.id = $1
           GROUP BY s.tenant_id, s.id"#,
        url = server_url_sql!("s"),
    )))
    .bind(id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("get server: {e}");
        ApiError::internal("failed to get server")
    })?
    .ok_or_else(|| ApiError::not_found("server not found", ApiErrorCode::ServerNotFound))?;

    let models = sqlx::query_as::<_, ModelRow>(
        sqlx::AssertSqlSafe(&*format!("{} WHERE m.server_id = $1 {MODEL_GROUP_BY} ORDER BY m.upstream_model", MODEL_SELECT.as_str()),
    ))
    .bind(id)
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("get server models: {e}");
        ApiError::internal("failed to get server models")
    })?;

    let vllm_engine = matches!(Provider::from_str_relaxed(server.provider.trim()), Provider::Vllm);
    // Only a learned limit's windows learn the figure. A failed read costs
    // the figure, never the server.
    let auto_itl_target_ms = if server.adaptive_concurrency {
        match crate::routes::server_analytics::latest_load(&mut db, Some(id)).await {
            Ok(rows) => crate::routes::server_analytics::summarize_live(&rows)
                .0
                .get(&id)
                .and_then(|live| live.auto_itl_target_ms),
            Err(_) => None,
        }
    } else {
        None
    };
    let server_resp: ServerResponse = server.into();
    let models_resp: Vec<ModelResponse> = models.into_iter().map(Into::into).collect();

    Ok(Json(ServerDetailResponse {
        server: server_resp,
        models: models_resp,
        vllm_engine,
        auto_itl_target_ms,
    }))
}

/// The write behind `PATCH`. The request arrives as a complete server: the
/// handler has already filled every field it did not mention from the stored
/// row, so the derivation and validation below see a whole one.
///
/// `mask` is what keeps that filling-in from becoming a write. It marks the
/// columns the patch actually named; the rest are left to the row's own value
/// inside the `UPDATE`, so a value read here and superseded by a concurrent
/// edit is never written back.
async fn apply_server_update(
    db: &mut TenantConn,
    id: Uuid,
    req: CreateServerRequest,
    mask: WriteMask,
    // The engine-metrics switch the caller asked for, if any: written in this
    // transaction when a provider change would otherwise reset it, so the
    // provider change and the caller's choice land together.
    engine_metrics: Option<bool>,
) -> Result<Json<ServerResponse>, ApiError> {
    if let Some(fmt) = &req.upstream_api_format
        && !VALID_API_FORMATS.contains(&fmt.as_str())
    {
        return Err(ApiError::bad_request("invalid upstream_api_format").code(ApiErrorCode::ApiFormatInvalid));
    }

    let upstream_url = url_for_write(mask.upstream_url, req.upstream_url.clone(), &req.provider)?;

    let upstream_api_format: String = req
        .upstream_api_format
        .clone()
        .or_else(|| crate::seed_loader::provider_default_api_format(&req.provider))
        .unwrap_or_else(|| "chat_completions".to_string());

    // Endpoint-path override: a validated explicit request value wins, else the
    // provider seed default (None = canonical `/v1/chat/completions`).
    let chat_endpoint_path = match normalize_chat_endpoint_path(req.chat_endpoint_path.clone())? {
        Some(p) => Some(p),
        None => crate::seed_loader::provider_chat_endpoint_path(&req.provider),
    };

    // A BYOK upstream is keyless — the client forwards its own credential. BYOK
    // is set-once at create: derive it SOLELY from the linked downstream so an
    // update can never flip managed↔BYOK (a BYOK server stays keyless/no-probe;
    // a managed one can't be silently keyed-off by a stray `byok` on the request).
    // A stored key on a BYOK upstream is inert (`build_passthrough_target` is
    // keyless by construction) but confusing — keep it NULL.
    let is_byok = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM downstream_providers WHERE upstream_server_id = $1 AND byok = true)",
    )
    .bind(id)
    .fetch_one(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("update server byok check: {e}");
        ApiError::internal("failed to update server")
    })?;

    // What this server currently authenticates with — a transport change that
    // crosses credential shapes must arrive with the new credential.
    let stored: Option<(String, Option<String>, String)> = sqlx::query_as(
        "SELECT transport, encrypted_key, provider FROM upstream_servers WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("update server transport read: {e}");
        ApiError::internal("failed to update server")
    })?;
    let (stored_transport, stored_encrypted_key, stored_provider) =
        stored.ok_or_else(|| ApiError::not_found("server not found", ApiErrorCode::ServerNotFound))?;
    let stored = StoredCredential {
        transport: stored_transport,
        has_credential: stored_encrypted_key.is_some(),
    };

    let transport = resolve_transport(TransportRequest {
        requested: req.transport.as_deref(),
        provider: &req.provider,
        upstream_api_format: &upstream_api_format,
        chat_endpoint_path: chat_endpoint_path.as_deref(),
        upstream_url: Some(upstream_url.as_str()).filter(|u| !u.is_empty()),
        api_key: req.api_key.as_deref(),
        byok: is_byok,
        existing: Some(stored),
    })?;

    // A per-model protocol override outlives a transport change, so switching a
    // server ONTO a transport while one of its models still overrides to a
    // protocol that transport does not carry would leave that model addressing a
    // URL grammar the vendor does not serve. Refuse the switch and name what to
    // clear. The overrides are filtered in Rust against the transport's own rule
    // rather than by a hardcoded SQL list, so a transport added later is covered.
    let resolved_transport = UpstreamTransport::from_str_relaxed(&transport);
    if resolved_transport.owns_url() {
        let overrides: Vec<(String, String)> = sqlx::query_as(
            "SELECT upstream_model, upstream_api_format FROM upstream_models \
             WHERE server_id = $1 AND upstream_api_format IS NOT NULL \
             ORDER BY upstream_model",
        )
        .bind(id)
        .fetch_all(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("update server model-format check: {e}");
            ApiError::internal("failed to update server")
        })?;
        let clashing: Vec<String> = overrides
            .into_iter()
            .filter(|(_, fmt)| !resolved_transport.allows_format(fmt))
            .map(|(model, _)| model)
            .take(5)
            .collect();
        if !clashing.is_empty() {
            return Err(ApiError::bad_request(format!(
                "These models override the protocol to one a {} server does not serve — \
                 clear their protocol override first: {}",
                transport_label(resolved_transport),
                clashing.join(", ")
            ))
            .code(ApiErrorCode::TransportInvalid));
        }
    }

    // Only a default-transport server has replicas: a cloud transport addresses
    // one deployment, so a server with several endpoints cannot switch to one.
    if resolved_transport != UpstreamTransport::Default {
        let endpoints: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM upstream_server_endpoints WHERE server_id = $1")
                .bind(id)
                .fetch_one(db.conn())
                .await
                .map_err(|e| {
                    tracing::error!("update server endpoint count: {e}");
                    ApiError::internal("failed to update server")
                })?;
        if endpoints > 1 {
            return Err(ApiError::bad_request(format!(
                "This server has {endpoints} endpoints — remove all but one before switching it to a {} transport",
                transport_label(resolved_transport)
            ))
            .code(ApiErrorCode::EndpointsUnsupported));
        }
    }

    if !req.force && !is_byok && probe_is_worth_making(&req.provider, resolved_transport) {
        // Check with the credential this server will ACTUALLY forward with: the
        // new one when the write rotates it, otherwise the stored one. Probing
        // keyless because the operator did not retype a key they were not
        // changing is how re-pointing a server at a host that refuses its
        // credential passes the check and fails at the next sync instead —
        // exactly the case this check exists to catch, reached from the one
        // form that does not show the key. Matches what adding an endpoint
        // already does.
        let rotated = req.api_key.as_deref().filter(|k| !k.is_empty());
        // A stored credential that will not decrypt — a database restored under
        // a different `ENCRYPTION_KEY`, say — is nothing this check can
        // present, so it checks keyless rather than refusing the write. The
        // alternative is a 500 with no error code, which the console cannot
        // offer "Save anyway" for: an operator could not change a URL without
        // first rotating a key they had no reason to touch.
        let carried = match rotated {
            Some(_) => None,
            None => decrypt_server_key(stored_encrypted_key.clone()).unwrap_or_else(|_| {
                tracing::error!(server_id = %id, "stored credential will not decrypt — checking keyless");
                None
            }),
        };
        let probe_key = rotated.or(carried.as_deref());
        probe_upstream_liveness(&upstream_url, &upstream_api_format, probe_key, chat_endpoint_path.as_deref(), resolved_transport).await?;
    }

    // What cannot be discovered must not be left switched on. Create clamps this
    // too — both paths must, or the toggle re-enables it.
    let auto_sync_requested = if can_discover(&req.provider, resolved_transport) {
        req.auto_sync_enabled
    } else {
        Some(false)
    };

    // The server row and its primary endpoint change together.
    let db_tenant = db.tenant_uuid();
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("update server begin: {e}");
        ApiError::internal("failed to update server")
    })?;
    let mut row = if is_byok {
        // BYOK: force keyless regardless of any supplied `api_key`, and keep
        // autosync off (no discovery on a keyless pass-through upstream).
        sqlx::query_as::<_, ServerRow>(
            r#"UPDATE upstream_servers SET name = CASE WHEN $8 THEN $2 ELSE name END,
                      provider = CASE WHEN $9 THEN $3 ELSE provider END,
                      upstream_api_format = CASE WHEN $10 THEN $4 ELSE upstream_api_format END,
                      chat_endpoint_path = CASE WHEN $11 THEN $5 ELSE chat_endpoint_path END,
                      encrypted_key = NULL, credential_nonce = NULL, auto_sync_enabled = false,
                      transport = CASE WHEN $12 THEN $7 ELSE transport END
               WHERE id = $1
               RETURNING id, name, provider, encrypted_key, NULL::text AS upstream_url, upstream_api_format, chat_endpoint_path, transport, enabled, is_builtin, created_at, 0::bigint as model_count,
                         scheduling_dialect, max_in_flight, waiting_threshold, engine_metrics, adaptive_concurrency, adaptive_itl_target_ms, adaptive_itl_target_mode,
                         auto_sync_enabled, last_auto_sync_at, last_auto_sync_status, $6::bool AS byok"#,
        )
        .bind(id)
        .bind(&req.name)
        .bind(&req.provider)
        .bind(&upstream_api_format)
        .bind(&chat_endpoint_path)
        .bind(is_byok)
        .bind(&transport)
        .bind(mask.name)
        .bind(mask.provider)
        .bind(mask.upstream_api_format)
        .bind(mask.chat_endpoint_path)
        .bind(mask.transport)
        .fetch_optional(&mut *tx)
        .await
    } else if let Some(key) = &req.api_key
        && !key.is_empty()
    {
        let (encrypted_key, credential_nonce) = encrypt_api_key(Some(key))?;
        sqlx::query_as::<_, ServerRow>(
            r#"UPDATE upstream_servers SET name = CASE WHEN $11 THEN $2 ELSE name END,
                      provider = CASE WHEN $12 THEN $3 ELSE provider END,
                      encrypted_key = $4, credential_nonce = $5,
                      upstream_api_format = CASE WHEN $13 THEN $6 ELSE upstream_api_format END,
                      chat_endpoint_path = CASE WHEN $14 THEN $8 ELSE chat_endpoint_path END,
                      auto_sync_enabled = COALESCE($7, auto_sync_enabled),
                      transport = CASE WHEN $15 THEN $10 ELSE transport END
               WHERE id = $1
               RETURNING id, name, provider, encrypted_key, NULL::text AS upstream_url, upstream_api_format, chat_endpoint_path, transport, enabled, is_builtin, created_at, 0::bigint as model_count,
                         scheduling_dialect, max_in_flight, waiting_threshold, engine_metrics, adaptive_concurrency, adaptive_itl_target_ms, adaptive_itl_target_mode,
                         auto_sync_enabled, last_auto_sync_at, last_auto_sync_status, $9::bool AS byok"#,
        )
        .bind(id)
        .bind(&req.name)
        .bind(&req.provider)
        .bind(&encrypted_key)
        .bind(&credential_nonce)
        .bind(&upstream_api_format)
        .bind(auto_sync_requested)
        .bind(&chat_endpoint_path)
        .bind(is_byok)
        .bind(&transport)
        .bind(mask.name)
        .bind(mask.provider)
        .bind(mask.upstream_api_format)
        .bind(mask.chat_endpoint_path)
        .bind(mask.transport)
        .fetch_optional(&mut *tx)
        .await
    } else {
        sqlx::query_as::<_, ServerRow>(
            r#"UPDATE upstream_servers SET name = CASE WHEN $9 THEN $2 ELSE name END,
                      provider = CASE WHEN $10 THEN $3 ELSE provider END,
                      upstream_api_format = CASE WHEN $11 THEN $4 ELSE upstream_api_format END,
                      chat_endpoint_path = CASE WHEN $12 THEN $6 ELSE chat_endpoint_path END,
                      auto_sync_enabled = COALESCE($5, auto_sync_enabled),
                      transport = CASE WHEN $13 THEN $8 ELSE transport END
               WHERE id = $1
               RETURNING id, name, provider, encrypted_key, NULL::text AS upstream_url, upstream_api_format, chat_endpoint_path, transport, enabled, is_builtin, created_at, 0::bigint as model_count,
                         scheduling_dialect, max_in_flight, waiting_threshold, engine_metrics, adaptive_concurrency, adaptive_itl_target_ms, adaptive_itl_target_mode,
                         auto_sync_enabled, last_auto_sync_at, last_auto_sync_status, $7::bool AS byok"#,
        )
        .bind(id)
        .bind(&req.name)
        .bind(&req.provider)
        .bind(&upstream_api_format)
        .bind(auto_sync_requested)
        .bind(&chat_endpoint_path)
        .bind(is_byok)
        .bind(&transport)
        .bind(mask.name)
        .bind(mask.provider)
        .bind(mask.upstream_api_format)
        .bind(mask.chat_endpoint_path)
        .bind(mask.transport)
        .fetch_optional(&mut *tx)
        .await
    }
    .map_err(|e| {
        // The rename twin of the create above: all three branches SET `name`, so
        // they land on `idx_upstream_servers_name` exactly as the create does.
        // Keep the two in step — a conflict answered as a fault on one path and
        // as a conflict on the other is the same endpoint contradicting itself.
        if super::is_unique_violation(&e) {
            return ApiError::conflict("server name already exists", ApiErrorCode::ServerNameTaken);
        }
        tracing::error!("update server: {e}");
        ApiError::internal("failed to update server")
    })?
    .ok_or_else(|| ApiError::not_found("server not found", ApiErrorCode::ServerNotFound))?;

    // A server moved to another provider takes that provider's default for
    // reading engine metrics: a hosted API polled for vLLM gauges would be
    // asked, with its key, forever. A PATCH that names the switch itself
    // writes it afterwards.
    // Only when the default itself differs: a relabel between two providers
    // with the same default keeps whatever the operator chose.
    // A learned in-flight limit reads the engine whatever the switch says, so a
    // move to a provider that is not read by default turns it off too (a PATCH
    // naming it writes it afterwards, as for the switch).
    if engine_metrics_by_default(&req.provider) != engine_metrics_by_default(&stored_provider) {
        row.engine_metrics = engine_metrics.unwrap_or_else(|| engine_metrics_by_default(&req.provider));
        if !engine_metrics_by_default(&req.provider) {
            row.adaptive_concurrency = false;
        }
        sqlx::query(
            "UPDATE upstream_servers SET engine_metrics = $2, \
               adaptive_concurrency = adaptive_concurrency AND $3 WHERE id = $1",
        )
            .bind(id)
            .bind(row.engine_metrics)
            .bind(engine_metrics_by_default(&req.provider))
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!("update server engine metrics: {e}");
                ApiError::internal("failed to update server")
            })?;
    }

    // The server's `upstream_url` is its primary endpoint's URL; the response
    // reads it back below.
    if mask.upstream_url {
        super::upstream_endpoints::write_primary_url(&mut tx, db_tenant, id, &upstream_url)
            .await
            .map_err(|e| {
                if super::is_unique_violation(&e) {
                    return ApiError::conflict("Another endpoint of this server already has that URL", ApiErrorCode::EndpointUrlTaken);
                }
                tracing::error!("update server primary endpoint: {e}");
                ApiError::internal("failed to update server")
            })?;
    }
    tx.commit().await.map_err(|e| {
        tracing::error!("update server commit: {e}");
        ApiError::internal("failed to update server")
    })?;

    Ok(Json(with_endpoint_summary(db.conn(), row.into()).await?))
}

/// The replaceable columns of a stored server, read so a partial update can
/// fill in every field it did not mention.
#[derive(sqlx::FromRow)]
struct StoredServerFields {
    name: String,
    provider: String,
    upstream_url: Option<String>,
    upstream_api_format: String,
    chat_endpoint_path: Option<String>,
    transport: String,
}

/// The URL a server forwards to: the request's own, else the provider seed's.
///
/// Every server states a concrete URL. There is no fallback host at request
/// time, so a server whose provider has no default (vLLM, Ollama, a custom
/// endpoint) and whose request names none is refused here rather than stored
/// without one. A blank value counts as absent.
fn resolve_server_url(requested: Option<String>, provider: &str) -> Result<String, ApiError> {
    requested
        .filter(|u| !u.trim().is_empty())
        .or_else(|| crate::seed_loader::provider_default_url(provider))
        .ok_or_else(|| {
            ApiError::bad_request(
                "This provider has no default endpoint — enter the server's URL, e.g. http://vllm:8000",
            )
            .code(ApiErrorCode::UpstreamUrlMissing)
        })
}

/// The URL a server write carries: resolved — and a missing one refused — only
/// when the write sets it. A write that leaves it alone (a rename, a toggle)
/// keeps the primary endpoint as it is, so the one returned here is only read
/// (by the transport and probe checks), never written.
fn url_for_write(sets_url: bool, requested: Option<String>, provider: &str) -> Result<String, ApiError> {
    if sets_url {
        resolve_server_url(requested, provider)
    } else {
        Ok(requested.unwrap_or_default())
    }
}

/// Refuse a patch field whose value is present but blank.
///
/// An empty string is not a spelling of "leave it alone", and for these fields it
/// is not a spelling of "clear" either: `resolve_transport` and the
/// provider-default ladder both read blank as *unset*, so forwarding one would
/// re-derive the field from the provider seed — the very reset this endpoint
/// exists to prevent. Refusing beats laundering, because the caller learns which
/// field it got wrong instead of watching a server quietly move.
fn require_non_blank(field: &'static str, value: Option<String>) -> Result<Option<String>, ApiError> {
    match value {
        Some(v) if v.trim().is_empty() => Err(ApiError::bad_request(format!(
            "`{field}` cannot be empty — omit it to leave it unchanged."
        ))),
        other => Ok(other),
    }
}

/// Which replaceable columns a write is allowed to touch.
///
/// A `PATCH` sets only the columns the request actually named, and that is
/// what closes a lost update: an unnamed column keeps whatever the row holds
/// **at write time** rather than the value read a moment earlier, so two
/// admins editing different fields of one server do not overwrite each other.
///
/// The reads in [`apply_server_update`] only *validate*. A concurrent edit therefore makes the validation slightly
/// stale instead of silently reverting data — and no row lock is held, which
/// matters because `probe_upstream_liveness` sits between the reads and the
/// write and is an outbound call to an operator-supplied host. A
/// `SELECT … FOR UPDATE` opened before that probe would hold both the lock
/// and a pool connection across it, serialising every admin write behind one
/// hanging provider: worse than the bug it fixed.
#[derive(Clone, Copy)]
struct WriteMask {
    name: bool,
    provider: bool,
    upstream_url: bool,
    upstream_api_format: bool,
    chat_endpoint_path: bool,
    transport: bool,
}

impl WriteMask {
    /// Whether this patch writes none of the connection columns. A patch that
    /// does that and turns the server on or off changes nothing about the
    /// connection, so it skips the liveness probe — a dead server must stay
    /// switchable off.
    fn writes_nothing(&self) -> bool {
        !(self.name
            || self.provider
            || self.upstream_url
            || self.upstream_api_format
            || self.chat_endpoint_path
            || self.transport)
    }

    /// What a `PATCH` may write.
    ///
    /// A field the caller named is written. Two couplings mean that is not the
    /// whole answer, and both are derivations the handler already performs:
    ///
    /// - **`provider` re-derives its neighbours.** The url, protocol and
    ///   endpoint-path ladders each fall back to the provider seed, so a
    ///   provider change must be free to move them; masking them out would
    ///   leave a server pointing at the previous provider's URL.
    /// - **`transport` is resolved from all of them.** `resolve_transport`
    ///   reads the provider, protocol, endpoint path, url and credential
    ///   together, so it is written whenever any of those is in play.
    ///   Otherwise a patch could pass a validation performed on the whole
    ///   resolved shape while writing only half of it.
    ///
    /// The common case — a rename — therefore touches exactly `name`.
    fn for_patch(patch: &PatchServerRequest) -> Self {
        let from_provider = patch.provider.is_some();
        Self {
            name: patch.name.is_some(),
            provider: from_provider,
            upstream_url: patch.upstream_url.is_some() || from_provider,
            upstream_api_format: patch.upstream_api_format.is_some() || from_provider,
            chat_endpoint_path: patch.chat_endpoint_path.is_some() || from_provider,
            transport: patch.transport.is_some()
                || from_provider
                || patch.upstream_url.is_some()
                || patch.upstream_api_format.is_some()
                || patch.chat_endpoint_path.is_some()
                || patch.api_key.is_some(),
        }
    }
}

/// The largest fixed token-latency target a learned limit takes, in
/// milliseconds: a minute between two tokens is no target.
pub(crate) const MAX_ITL_TARGET_MS: u32 = 60_000;

/// A server's token-latency target, from the two columns it is stored in
/// (`adaptive_itl_target_mode`, `adaptive_itl_target_ms`). The one reading of
/// them, for the API and the gateways' configuration alike. The mode decides:
/// a figure is read only beside a fixed one, and a fixed one without a figure
/// in range — which this API never stores — or a mode this build does not
/// know reads as the default.
pub(crate) fn itl_target_of(mode: &str, ms: Option<i32>) -> ItlTarget {
    match mode {
        "off" => ItlTarget::Off,
        "fixed" => match ms.and_then(|v| u32::try_from(v).ok()).filter(|v| *v > 0) {
            Some(ms) => ItlTarget::Fixed { ms },
            None => ItlTarget::Auto,
        },
        _ => ItlTarget::Auto,
    }
}

/// The two columns a token-latency target is stored in: the mode, and the
/// figure — only a fixed target has one.
fn itl_target_columns(target: ItlTarget) -> (&'static str, Option<i32>) {
    match target {
        ItlTarget::Auto => ("auto", None),
        ItlTarget::Off => ("off", None),
        // Within MAX_ITL_TARGET_MS once validated; saturating otherwise.
        ItlTarget::Fixed { ms } => ("fixed", Some(i32::try_from(ms).unwrap_or(i32::MAX))),
    }
}

/// A partial update to one upstream server.
///
/// Every field is optional and an omitted one keeps whatever is stored.
///
/// The two nullable columns are three-state: absent = unchanged, `null` (or an
/// empty string) = cleared, falling back to the provider default, a value = set.
/// On every other field a blank value is refused — see [`require_non_blank`].
#[derive(Deserialize, ToSchema)]
pub struct PatchServerRequest {
    /// New display name.
    pub name: Option<String>,
    /// New provider key.
    pub provider: Option<String>,
    /// New credential. Absent or empty keeps the stored one — there is no way to
    /// read a credential back, so it can never be round-tripped by a caller
    /// echoing the current server.
    pub api_key: Option<String>,
    /// New URL of the primary endpoint. Explicit `null` clears it back to the
    /// provider default.
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<String>)]
    pub upstream_url: Option<Option<String>>,
    /// New upstream protocol.
    pub upstream_api_format: Option<String>,
    /// New chat-endpoint-path override. Explicit `null` clears it back to the
    /// provider default.
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<String>)]
    pub chat_endpoint_path: Option<Option<String>>,
    /// New transport.
    pub transport: Option<String>,
    /// Turn autosync on or off.
    pub auto_sync_enabled: Option<bool>,
    /// How this engine expresses a priority class: `none` or `vllm_priority`.
    /// An explicit opt-in, because it has to match how the engine was started.
    pub scheduling_dialect: Option<String>,
    /// Capacity the gateway may use at each endpoint of this server. Present
    /// and `null` clears the knob (unbounded); absent leaves it unchanged.
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<i32>)]
    pub max_in_flight: Option<Option<i32>>,
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<i32>)]
    pub waiting_threshold: Option<Option<i32>>,
    /// Read this server's engines' own metrics for the dashboards (or stop).
    pub engine_metrics: Option<bool>,
    /// Learn each endpoint's in-flight limit from its engine's readings (or
    /// stop). Refused while the server or any endpoint of it declares a
    /// waiting-queue bound: the learned limit replaces that bound.
    pub adaptive_concurrency: Option<bool>,
    /// The learned limit's token-latency target: `auto`, `off`, or `fixed`
    /// with `ms` from 1 to 60 000. Absent leaves it unchanged. Kept while the
    /// limit is fixed, and applied whenever it is learned.
    pub adaptive_itl_target: Option<ItlTarget>,
    /// Also clear every endpoint's own `max_in_flight` / `waiting_threshold`
    /// — disabled endpoints included, since enabling one would otherwise bring
    /// its bound back — in the same transaction as the server's scheduling
    /// fields. What a switch to a mode that holds nothing needs: an endpoint's
    /// bound gates on its own, whatever the server says.
    #[serde(default)]
    pub clear_endpoint_bounds: bool,
    /// Turn the server on or off. A disabled server is not sent to the
    /// gateways: its routes serve nothing, and a pass-through (BYOK) provider
    /// linked to it reaches nothing. The built-in pass-through servers are
    /// seeded off.
    pub enabled: Option<bool>,
    /// Skip the write-time liveness probe. Absent = probe, as on create.
    #[serde(default)]
    pub force: Option<bool>,
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/servers/{id}",
    tag = "Servers",
    params(("id" = Uuid, Path, description = "Server ID")),
    request_body = PatchServerRequest,
    responses(
        (status = 200, description = "Updated server", body = ServerResponse),
        (status = 400, description = "Invalid request", body = ApiErrorResponse),
        (status = 404, description = "Server not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn patch_server(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
    Json(patch): Json<PatchServerRequest>,
) -> Result<Json<ServerResponse>, ApiError> {
    // Read the stored row FIRST and fill every unmentioned field from it, so the
    // connection write below cannot reset anything this request did not
    // name. Reading the columns rather than trusting a caller-supplied echo is
    // what makes that true even for a caller that knows nothing about a field
    // added later.
    let stored: StoredServerFields = sqlx::query_as(
        concat!(
            "SELECT s.name, s.provider, ", server_url_sql!("s"), " AS upstream_url, \
                    s.upstream_api_format, s.chat_endpoint_path, s.transport \
             FROM upstream_servers s WHERE s.id = $1"
        ),
    )
    .bind(id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("patch server read: {e}");
        ApiError::internal("failed to update server")
    })?
    .ok_or_else(|| ApiError::not_found("server not found", ApiErrorCode::ServerNotFound))?;

    // A nullable field takes `null` — or, equivalently, an empty string — to mean
    // "clear it back to the provider default". Every other field has no such
    // meaning, so a blank one is refused above rather than silently re-derived.
    let blank_is_clear = |v: Option<Option<String>>| {
        v.map(|inner| inner.filter(|u: &String| !u.trim().is_empty()))
    };

    // What this request is allowed to write. A field the caller did not name
    // is not written at all, so a concurrent edit to it survives.
    let mask = WriteMask::for_patch(&patch);

    let engine_metrics = patch.engine_metrics;
    let scheduling = patch.scheduling_dialect.is_some()
        || patch.max_in_flight.is_some()
        || patch.waiting_threshold.is_some()
        || engine_metrics.is_some()
        || patch.adaptive_concurrency.is_some()
        || patch.adaptive_itl_target.is_some()
        || patch.clear_endpoint_bounds;
    // A move to a provider that is not read by default turns the learned limit
    // off in this same request (`apply_server_update`), unless it is named.
    let moved_off = patch.provider.as_deref().is_some_and(|p| {
        !engine_metrics_by_default(p) && engine_metrics_by_default(&stored.provider)
    });
    let merged = CreateServerRequest {
        name: require_non_blank("name", patch.name)?.unwrap_or(stored.name),
        provider: require_non_blank("provider", patch.provider)?.unwrap_or(stored.provider),
        api_key: patch.api_key,
        upstream_url: blank_is_clear(patch.upstream_url).unwrap_or(stored.upstream_url),
        upstream_api_format: Some(
            require_non_blank("upstream_api_format", patch.upstream_api_format)?
                .unwrap_or(stored.upstream_api_format),
        ),
        chat_endpoint_path: blank_is_clear(patch.chat_endpoint_path)
            .unwrap_or(stored.chat_endpoint_path),
        transport: Some(
            require_non_blank("transport", patch.transport)?.unwrap_or(stored.transport),
        ),
        auto_sync_enabled: patch.auto_sync_enabled,
        // BYOK is set-once at create and derived from the linked downstream on
        // every update, so there is nothing for a patch to say about it.
        byok: None,
        // On/off, scheduling and the engine-metrics switch change nothing a
        // liveness probe could vouch for, so a patch naming only those is not
        // refused by one: turning metrics off for an engine that is down must
        // work while it is down. Anything else still probes.
        force: patch.force.unwrap_or(false) || (mask.writes_nothing() && (scheduling || patch.enabled.is_some())),
    };

    // Scheduling and capacity name no secret and no URL, so they are written
    // directly rather than routed through the connection write. Validated
    // BEFORE that path runs, so a bad value refuses the whole request without
    // touching anything, and written only AFTER it succeeds — a refused edit (a
    // failed probe, a name conflict) therefore changes nothing. The two writes
    // are still separate statements: if this one fails the earlier edit stands,
    // and the caller is told the scheduling settings did not land.
    if scheduling {
        if let Some(dialect) = patch.scheduling_dialect.as_deref()
            && !matches!(dialect, "none" | "vllm_priority")
        {
            return Err(ApiError::bad_request(
                "scheduling_dialect must be 'none' or 'vllm_priority'",
            )
            .code(ApiErrorCode::ValidationFailed));
        }
        if patch.max_in_flight.flatten().is_some_and(|v| v < 1) {
            return Err(ApiError::bad_request("max_in_flight is out of range").code(ApiErrorCode::ValidationFailed));
        }
        if patch.waiting_threshold.flatten().is_some_and(|v| v < 0) {
            return Err(ApiError::bad_request("waiting_threshold is out of range").code(ApiErrorCode::ValidationFailed));
        }
        if let Some(ItlTarget::Fixed { ms }) = patch.adaptive_itl_target
            && !(1..=MAX_ITL_TARGET_MS).contains(&ms)
        {
            return Err(ApiError::bad_request("adaptive_itl_target.ms is out of range")
                .code(ApiErrorCode::ValidationFailed));
        }
        // Refused up front, so a request that would end with both a learned
        // limit and a queue bound changes nothing at all. The transaction below
        // checks the committed state again, for a concurrent edit.
        let facts = adaptive_facts(db.conn(), id).await.map_err(|e| {
            tracing::error!("read server scheduling: {e}");
            ApiError::internal("failed to update the server's scheduling settings")
        })?;
        let (server_bound, endpoint_bound) = (facts.server_bound, facts.endpoint_bound);
        let adaptive = patch.adaptive_concurrency.unwrap_or(facts.adaptive && !moved_off);
        let server_bound = patch.waiting_threshold.map_or(server_bound, |v| v.is_some());
        let endpoint_bound = endpoint_bound && !patch.clear_endpoint_bounds;
        if adaptive && (server_bound || endpoint_bound) {
            return Err(adaptive_with_queue_bound());
        }
    }

    // Turning a dialect ON is the other half of the preset guard: with one set,
    // the request's `priority` is written by the gateway and would overwrite
    // whatever a preset put there on every request. Refuse rather than leave
    // exactly the state the preset writer is told is unacceptable.
    if patch.scheduling_dialect.as_deref().is_some_and(|d| d != "none") {
        let clashing: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM model_presets p \
             JOIN upstream_models m ON m.id = p.model_id \
             WHERE m.server_id = $1 AND p.settings ? 'priority'",
        )
        .bind(id)
        .fetch_one(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("check presets for priority: {e}");
            ApiError::internal("failed to update the server's scheduling settings")
        })?;
        if clashing > 0 {
            return Err(ApiError::bad_request(format!(
                "{clashing} invocation preset(s) on this server's models set 'priority'. \
                 With a scheduling dialect the gateway writes that field itself, so remove it \
                 from those presets first."
            ))
            .code(ApiErrorCode::PresetSettingsInvalid));
        }
    }

    let mut updated = apply_server_update(&mut db, id, merged, mask, engine_metrics).await?;
    if !scheduling && patch.enabled.is_none() {
        return Ok(updated);
    }

    // On/off names no secret and no URL either, so it is written the same way
    // and after the same successful connection write.
    if let Some(enabled) = patch.enabled {
        sqlx::query("UPDATE upstream_servers SET enabled = $2 WHERE id = $1")
            .bind(id)
            .bind(enabled)
            .execute(db.conn())
            .await
            .map_err(|e| {
                tracing::error!("update server enabled: {e}");
                ApiError::internal("the server was updated, but it was not turned on or off — try again")
            })?;
        // The fallback response below must not report the state before this write.
        updated.0.enabled = enabled;
    }

    if scheduling {
        let itl_target = patch.adaptive_itl_target.map(itl_target_columns);
        let not_written = |e: sqlx::Error| {
            tracing::error!("update server scheduling: {e}");
            ApiError::internal("the server was updated, but its scheduling settings were not — try them again")
        };
        // The server's fields and its endpoints' own bounds land together or
        // not at all: half of a mode switch leaves an endpoint gating a server
        // that says it holds nothing.
        let mut tx = db.conn().begin().await.map_err(not_written)?;
        sqlx::query(
            "UPDATE upstream_servers SET \
               scheduling_dialect = COALESCE($2, scheduling_dialect), \
               max_in_flight = CASE WHEN $3 THEN $4 ELSE max_in_flight END, \
               waiting_threshold = CASE WHEN $5 THEN $6 ELSE waiting_threshold END, \
               engine_metrics = COALESCE($7, engine_metrics), \
               adaptive_concurrency = COALESCE($8, adaptive_concurrency), \
               adaptive_itl_target_mode = COALESCE($9, adaptive_itl_target_mode), \
               adaptive_itl_target_ms = CASE WHEN $9 IS NOT NULL THEN $10 ELSE adaptive_itl_target_ms END \
             WHERE id = $1",
        )
        .bind(id)
        .bind(patch.scheduling_dialect.as_deref())
        .bind(patch.max_in_flight.is_some())
        .bind(patch.max_in_flight.flatten())
        .bind(patch.waiting_threshold.is_some())
        .bind(patch.waiting_threshold.flatten())
        .bind(engine_metrics)
        .bind(patch.adaptive_concurrency)
        .bind(itl_target.map(|(mode, _)| mode))
        .bind(itl_target.and_then(|(_, ms)| ms))
        .execute(&mut *tx)
        .await
        .map_err(not_written)?;
        if patch.clear_endpoint_bounds {
            sqlx::query(
                "UPDATE upstream_server_endpoints SET max_in_flight = NULL, waiting_threshold = NULL \
                 WHERE server_id = $1 AND (max_in_flight IS NOT NULL OR waiting_threshold IS NOT NULL)",
            )
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(not_written)?;
        }
        // Checked on the state the transaction is about to commit, not on the
        // request: which half of the pair is already stored — and whether an
        // endpoint carries a queue bound of its own — is only known here. The
        // server row is locked by the UPDATE above, and an endpoint edit locks
        // it too before checking the same pair, so neither can slip past the
        // other.
        let facts = adaptive_facts(&mut tx, id).await.map_err(not_written)?;
        if facts.adaptive && (facts.server_bound || facts.endpoint_bound) {
            // Only a concurrent endpoint edit gets here (the request itself
            // was checked up front), and whatever else this request changed
            // has already landed: say so.
            return Err(ApiError::bad_request(
                "The server was updated, but its scheduling settings were not: an endpoint was given \
                 an engine-queue bound meanwhile, which a learned in-flight limit replaces — clear it \
                 and try again",
            )
            .code(ApiErrorCode::ValidationFailed));
        }
        tx.commit().await.map_err(not_written)?;
    }

    // Re-read so the response carries what was just written rather than the row
    // as it was a moment before. A failure here is only a stale response body —
    // the write landed — so the earlier one is returned instead of an error.
    let summary = endpoint_summary_columns();
    let refreshed = sqlx::query_as::<_, ServerRow>(sqlx::AssertSqlSafe(format!(
        r#"SELECT s.id, s.name, s.provider, s.encrypted_key, {url} AS upstream_url, s.upstream_api_format, s.chat_endpoint_path, s.transport,
                  s.enabled, s.is_builtin, s.created_at,
                  COUNT(m.id)::bigint as model_count,
                  s.auto_sync_enabled, s.last_auto_sync_at, s.last_auto_sync_status,
                  s.scheduling_dialect, s.max_in_flight, s.waiting_threshold, s.engine_metrics, s.adaptive_concurrency, s.adaptive_itl_target_ms, s.adaptive_itl_target_mode,
                  EXISTS(SELECT 1 FROM downstream_providers d WHERE d.upstream_server_id = s.id AND d.byok = true) AS byok,
                  {summary}
           FROM upstream_servers s
           LEFT JOIN upstream_models m ON m.server_id = s.id
           WHERE s.id = $1
           GROUP BY s.tenant_id, s.id"#,
        url = server_url_sql!("s"),
    )))
    .bind(id)
    .fetch_optional(db.conn())
    .await
    .ok()
    .flatten();
    Ok(refreshed.map_or(updated, |row| Json(row.into())))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/servers/{id}",
    tag = "Servers",
    params(("id" = Uuid, Path, description = "Server ID"), DryRunQuery),
    responses(
        (status = 200, description = "Server deleted (or the deletion previewed); impact reports its pass-through and any orphaned downstream routes", body = ActionResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 404, description = "Server not found", body = ApiErrorResponse),
        (status = 409, description = "A built-in pass-through's server (`builtin_provider_protected`)", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_server(
    // First: a preview is marked before any other extractor can refuse it.
    crate::middleware::DryRun(dry_run): crate::middleware::DryRun,
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<ActionResponse>, ApiError> {
    let tenant_id = db.tenant_uuid();
    // The preview IS the deletion, rolled back — so what it reports cannot
    // drift from what the deletion does.
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("delete server begin: {e}");
        ApiError::internal("failed to delete server")
    })?;
    let done = delete_server_with_passthrough(&mut tx, tenant_id, id).await?;
    let ended = if dry_run { tx.rollback().await } else { tx.commit().await };
    ended.map_err(|e| {
        tracing::error!("delete server end: {e}");
        ApiError::internal("failed to delete server")
    })?;
    Ok(Json(done.into_response(dry_run)))
}

/// What deleting a server did (or, rolled back, would do).
pub(super) struct ServerDeletion {
    /// The pass-through provider linked to the server, deleted with it.
    passthrough: Option<Uuid>,
    /// The pass-through's model overrides, deleted with it.
    pub(super) overrides_removed: i64,
    /// Keys bound to the pass-through, revoked.
    pub(super) keys_revoked: i64,
    /// Workspace grants of the pass-through, removed with it.
    pub(super) workspaces_ungranted: i64,
    orphans: super::downstream::OrphanImpact,
}

impl ServerDeletion {
    /// Whether provider `provider_id` was the pass-through deleted.
    pub(super) fn took_passthrough(&self, provider_id: Uuid) -> bool {
        self.passthrough == Some(provider_id)
    }

    fn into_response(self, dry_run: bool) -> ActionResponse {
        let lead = if dry_run { "Deleting the server deletes" } else { "Server deleted with" };
        let verb = match (self.passthrough.is_some(), dry_run) {
            (true, _) => format!(
                "{lead} its pass-through: {} override(s) removed, {} bound key(s) revoked, {} workspace grant(s) removed",
                self.overrides_removed, self.keys_revoked, self.workspaces_ungranted
            ),
            (false, false) => "Server deleted".to_string(),
            (false, true) => "Deleting the server deletes no pass-through".to_string(),
        };
        let mut response = orphan_action_response(&verb, self.orphans);
        if self.passthrough.is_some()
            && let Some(impact) = response.impact.as_mut()
        {
            impact.overrides_removed = Some(self.overrides_removed);
            impact.keys_revoked = Some(u64::try_from(self.keys_revoked).unwrap_or(0));
            impact.workspaces_ungranted = Some(self.workspaces_ungranted);
        }
        response
    }
}

/// Delete server `server_id` and the pass-through linked to it, inside the
/// caller's transaction. The ONE delete of a pass-through: the server delete,
/// the pass-through's Delete and a provider delete of a pass-through all come
/// here, so neither half is ever left without the other (a keyless server with
/// no provider reads as one of the operator's own; a provider with no server
/// is offered to members and never served). The schema refuses the split too
/// (`downstream_providers_passthrough_has_server`).
///
/// Refuses a built-in pass-through's server (409) — the provider seed would
/// re-create it — and an unknown server (404).
pub(super) async fn delete_server_with_passthrough(
    conn: &mut Scoped,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<ServerDeletion, ApiError> {
    let failed = |what: &'static str| {
        move |e: sqlx::Error| {
            tracing::error!("delete server {what}: {e}");
            ApiError::internal("failed to delete server")
        }
    };

    // Lock order: the server row (FOR UPDATE, the lock its delete takes), then
    // its scoped catalog entries in id order, then its linked providers in id
    // order (each pass-through locked by `revoke_keys_bound_to`), then —
    // through the delete — its models. A model write takes the server row
    // before the entries it links to, every catalog removal takes entries
    // before models, and a provider linked to this server meanwhile waits on
    // the server row, so each waits here rather than deadlocking. A caller
    // must take no provider lock before calling this.
    let is_builtin: Option<bool> = sqlx::query_scalar(
        "SELECT is_builtin FROM upstream_servers WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
    )
    .bind(id)
    .bind(tenant_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(failed("lock"))?;
    match is_builtin {
        None => return Err(ApiError::not_found("server not found", ApiErrorCode::ServerNotFound)),
        // Built-in pass-through servers are managed by the provider seed and
        // controlled by turning them on/off and by workspace grants: deleting
        // one would let the next startup sync re-create it, silently undoing
        // an operator's removal.
        Some(true) => {
            return Err(ApiError::conflict(
                "built-in BYOK provider cannot be deleted; turn it off or revoke its workspace grants instead",
                ApiErrorCode::BuiltinProviderProtected,
            ));
        }
        Some(false) => {}
    }
    sqlx::query("SELECT id FROM model_catalog WHERE server_id = $1 AND tenant_id = $2 ORDER BY id FOR UPDATE")
        .bind(id)
        .bind(tenant_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(failed("lock catalog entries"))?;

    // The models this server owns — used to orphan any custom downstream routes
    // that depend on them before the server (and its models) are deleted.
    let model_ids: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM upstream_models WHERE server_id = $1")
        .bind(id)
        .fetch_all(&mut *conn)
        .await
        .map_err(failed("fetch models"))?;

    // Every provider linked to the server, in id order — a link is not unique
    // for a plain provider, so a mirror may point at a pass-through's server
    // too. At most one is a pass-through (`idx_downstream_providers_one_passthrough`).
    let linked: Vec<(Uuid, bool)> = sqlx::query_as(
        "SELECT id, byok FROM downstream_providers WHERE upstream_server_id = $1 AND tenant_id = $2 ORDER BY id",
    )
    .bind(id)
    .bind(tenant_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(failed("find linked providers"))?;

    // The pass-through goes with its keyless server, overrides and workspace
    // grants included (cascade). Its bound keys are revoked first, under a
    // lock on its row (`revoke_keys_bound_to`): a route or key written against
    // it meanwhile waits on that lock and then fails, never lands on a
    // provider about to vanish. First, so the orphan step below never reports
    // its overrides as routes left behind.
    let mut done = ServerDeletion {
        passthrough: None,
        overrides_removed: 0,
        keys_revoked: 0,
        workspaces_ungranted: 0,
        orphans: super::downstream::OrphanImpact::default(),
    };
    for &(pid, _) in linked.iter().filter(|(_, byok)| *byok) {
        done.passthrough = Some(pid);
        done.keys_revoked += super::key_lifecycle::revoke_keys_bound_to(conn, pid)
            .await
            .map_err(failed("revoke bound keys"))?;
        let (overrides, grants): (i64, i64) = sqlx::query_as(
            "SELECT (SELECT COUNT(*) FROM downstream_routes WHERE provider_id = $1), \
                    (SELECT COUNT(*) FROM workspace_downstream_access WHERE downstream_provider_id = $1)",
        )
        .bind(pid)
        .fetch_one(&mut *conn)
        .await
        .map_err(failed("count pass-through overrides and grants"))?;
        done.overrides_removed += overrides;
        done.workspaces_ungranted += grants;
        sqlx::query("DELETE FROM downstream_providers WHERE id = $1 AND tenant_id = $2")
            .bind(pid)
            .bind(tenant_id)
            .execute(&mut *conn)
            .await
            .map_err(failed("pass-through provider"))?;
    }

    // Orphan (never destroy) curated routes that reference this server's models —
    // in ANY downstream, including the server's own mirror. This deletes the
    // disposable auto routes and flags the curated ones; the model rows are
    // deleted below and the FK (`ON DELETE SET NULL`) nulls the flagged routes'
    // `model_id`. Run this BEFORE touching the mirror provider so a curated route
    // an operator added into the mirror is preserved, not cascade-destroyed.
    done.orphans = super::downstream::orphan_model_routes(conn, &model_ids)
        .await
        .map_err(failed("orphan routes"))?;

    // Drop the auto-created mirror provider only when it holds no curated
    // (`auto_synced = false`) routes — i.e. the operator never added anything of
    // their own to it. Deleting it keeps the upstream↔downstream lifecycle
    // symmetric (re-adding the same name starts clean). If the operator HAS added
    // curated routes to the mirror, keep the provider: deleting the server nulls
    // its `upstream_server_id` (FK) so it lives on as a plain custom downstream,
    // and those routes (orphaned above, or still pointing at other servers) survive.
    for &(mid, _) in linked.iter().filter(|(_, byok)| !*byok) {
        let curated: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM downstream_routes WHERE provider_id = $1 AND auto_synced = false",
        )
        .bind(mid)
        .fetch_one(&mut *conn)
        .await
        .map_err(failed("count mirror routes"))?;
        if curated == 0 {
            sqlx::query("DELETE FROM downstream_providers WHERE id = $1 AND tenant_id = $2")
                .bind(mid)
                .bind(tenant_id)
                .execute(&mut *conn)
                .await
                .map_err(failed("mirror"))?;
        }
    }

    sqlx::query("DELETE FROM upstream_servers WHERE id = $1 AND tenant_id = $2")
        .bind(id)
        .bind(tenant_id)
        .execute(&mut *conn)
        .await
        .map_err(failed("delete"))?;
    Ok(done)
}

/// Build the `ActionResponse` for a delete that may have orphaned curated routes.
fn orphan_action_response(
    verb: &str,
    impact: super::downstream::OrphanImpact,
) -> ActionResponse {
    let message = if impact.orphaned_routes > 0 {
        format!(
            "{verb}. {} downstream route(s) orphaned in: {}. Clean them up under the affected downstream(s).",
            impact.orphaned_routes,
            impact.downstreams.join(", ")
        )
    } else {
        format!("{verb}.")
    };
    ActionResponse::ok().with_message(message).with_impact(impact)
}

// ---------------------------------------------------------------------------
// Model CRUD
// ---------------------------------------------------------------------------

/// The models a batch create added.
#[derive(Serialize, ToSchema)]
pub struct CreatedModels {
    pub models: Vec<ModelResponse>,
}

// Model creation serves two callers with opposite intent about the values in the
// body: an operator adding a model by hand, and the sync-review screen importing
// what discovery just read. `BatchCreateModelsRequest::from_discovery` tells them
// apart, and decides whether the inheritable fields are pinned into
// `user_overridden_caps` — see that field's own note. (Kept as a plain comment:
// a doc comment here would become the endpoint's OpenAPI description, and the
// field's own doc is where an API consumer needs this.)
#[utoipa::path(
    post,
    path = "/api/v1/admin/servers/{id}/models",
    tag = "Models",
    params(("id" = Uuid, Path, description = "Server ID")),
    request_body = BatchCreateModelsRequest,
    responses(
        (status = 201, description = "Models created", body = CreatedModels),
        (status = 400, description = "Invalid request", body = ApiErrorResponse),
        (status = 404, description = "Server not found, or a linked catalog entry is missing or deleted (`catalog_entry_not_found`)", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_server_models(
    mut db: TenantConn,
    Path(server_id): Path<Uuid>,
    Json(req): Json<BatchCreateModelsRequest>,
) -> Result<(StatusCode, Json<CreatedModels>), ApiError> {
    let Some(server_transport) = server_transport(db.conn(), server_id).await? else {
        return Err(ApiError::not_found("server not found", ApiErrorCode::ServerNotFound));
    };

    let tenant_id = db.tenant_uuid();
    // One transaction over the insert loop + mirror sync so a mid-sequence
    // failure rolls back fully — never a partial set of models with a
    // half-built mirror provider.
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("create models begin: {e}");
        ApiError::internal("failed to create models")
    })?;
    // Memberships are written below: take the server row first, the lock
    // order every endpoint write follows (`upstream_endpoints::lock_server`).
    super::upstream_endpoints::lock_server(&mut tx, server_id).await.map_err(|e| {
        tracing::error!("create models server lock: {e}");
        ApiError::internal("failed to create models")
    })?;

    let mut created = Vec::new();
    // Every linked catalog entry, share-locked up front in id order (the order
    // catalog removals lock in) and before any model row is written.
    let links: Vec<Uuid> = req.models.iter().filter_map(|m| m.catalog_model_id).collect();
    super::catalog::require_live_entries(&mut tx, &links).await?;
    for m in &req.models {
        if let Some(fmt) = &m.upstream_api_format {
            if !VALID_API_FORMATS.contains(&fmt.as_str()) {
                return Err(ApiError::bad_request("invalid upstream_api_format").code(ApiErrorCode::ApiFormatInvalid));
            }
            // The per-model override WINS over the server's protocol on the wire,
            // so it must satisfy the same transport rule the server write does —
            // otherwise an Azure server could be pointed at a URL grammar Azure
            // does not serve, one model at a time.
            if !server_transport.allows_format(fmt) {
                return Err(transport_format_error(server_transport));
            }
        }

        let row = sqlx::query_as::<_, ModelRow>(sqlx::AssertSqlSafe(
            &*crate::routes::with_catalog_join(
            concat!(r#"WITH cat_match AS (
                   SELECT model_type
                   FROM model_catalog
                   WHERE model_key = canonical_catalog_key($2)
                         AND tenant_id = $7 AND NOT suppressed
                         AND (server_id IS NULL OR server_id = $1)
                   -- model_type is a capability, so it takes the capability ladder:
                   -- this server's own catalog row first, then its provider, then any
                   -- provider, with a deterministic final tie-break. An explicitly
                   -- linked catalog row is deliberately NOT consulted here — the link
                   -- is applied to the inserted row, and reading model_type from it
                   -- would need the link resolved before the INSERT that establishes it.
                   ORDER BY COALESCE(server_id = $1, false) DESC,
                            (provider_key
                             = canonical_provider_key((SELECT s.provider FROM upstream_servers s WHERE s.tenant_id = $7 AND s.id = $1))) DESC,
                            (model = $2) DESC,
                            model, provider_key
                   LIMIT 1
               ),
               inserted AS (
                   -- Store only what the caller supplied; NULL columns inherit live
                   -- from the catalog at read time (never baked in here). catalog_model_id
                   -- is set only when the caller explicitly picks one — otherwise the row
                   -- resolves via the canonical name auto-match.
                   INSERT INTO upstream_models (server_id, upstream_model, context_window, max_output_tokens, upstream_api_format, model_type, tenant_id,
                       supports_vision, supports_reasoning, supports_function_calling, supports_caching,
                       supports_audio_input, supports_audio_output, supports_video_input, supports_pdf_input,
                       supports_response_schema, supports_system_messages, healing_enabled,
                       rates, catalog_model_id, user_overridden_caps)
                   VALUES ($1, $2, $3, $4, $5,
                       COALESCE($6, (SELECT model_type FROM cat_match), 'text'),
                       $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $20,
                       $19, $18, $21)
                   ON CONFLICT (tenant_id, server_id, upstream_model) DO NOTHING
                   RETURNING *
               )
               SELECT i.id, i.server_id, s.name as server_name, s.provider,
                      i.upstream_model, "#, server_url_sql!("s"), r#" AS upstream_url,
                      i.context_window, i.max_output_tokens,
                      COALESCE(i.context_window, c.context_window) as resolved_context_window,
                      "#, resolved_max_output_sql!("i", "c"), r#" as resolved_max_output_tokens,
                      COALESCE(i.upstream_api_format, s.upstream_api_format) as upstream_api_format,
                      i.model_type,
                      i.enabled, i.created_at,
                      i.catalog_model_id, c.catalog_match_id as resolved_catalog_model_id,
                      i.user_overridden_caps as user_overridden_fields,
                      (SELECT COUNT(*) FROM downstream_routes dr WHERE dr.model_id = i.id)::bigint as route_count,
                      -- Raw capability values
                      i.supports_vision, i.supports_reasoning, i.supports_function_calling, i.supports_caching,
                      i.supports_audio_input, i.supports_audio_output, i.supports_video_input, i.supports_pdf_input,
                      i.supports_response_schema, i.supports_system_messages,
                      i.healing_enabled,
                      -- Resolved capabilities (COALESCE with catalog)
                      COALESCE(i.supports_vision, c.supports_vision) as resolved_supports_vision,
                      COALESCE(i.supports_reasoning, c.supports_reasoning) as resolved_supports_reasoning,
                      COALESCE(i.supports_function_calling, c.supports_function_calling) as resolved_supports_function_calling,
                      COALESCE(i.supports_caching, c.supports_caching) as resolved_supports_caching,
                      COALESCE(i.supports_audio_input, c.supports_audio_input) as resolved_supports_audio_input,
                      COALESCE(i.supports_audio_output, c.supports_audio_output) as resolved_supports_audio_output,
                      COALESCE(i.supports_video_input, c.supports_video_input) as resolved_supports_video_input,
                      COALESCE(i.supports_pdf_input, c.supports_pdf_input) as resolved_supports_pdf_input,
                      COALESCE(i.supports_response_schema, c.supports_response_schema) as resolved_supports_response_schema,
                      COALESCE(i.supports_system_messages, c.supports_system_messages) as resolved_supports_system_messages,
                      -- Pricing: stored override, the map in force, and the
                      -- catalog's own map (inherited whole, never mixed).
                      i.rates,
                      COALESCE(i.rates, catp.rates, '{}'::jsonb) as resolved_rates,
                      catp.rates as catalog_rates
               FROM inserted i
               JOIN upstream_servers s ON s.id = i.server_id
--{catalog_join}"#),
            "i",
            "s",
        ),
        ))
        .bind(server_id)
        .bind(&m.upstream_model)
        .bind(m.context_window)
        .bind(m.max_output_tokens)
        .bind(&m.upstream_api_format)
        .bind(&m.model_type)
        .bind(tenant_id)
        .bind(m.supports_vision)
        .bind(m.supports_reasoning)
        .bind(m.supports_function_calling)
        .bind(m.supports_caching)
        .bind(m.supports_audio_input)
        .bind(m.supports_audio_output)
        .bind(m.supports_video_input)
        .bind(m.supports_pdf_input)
        .bind(m.supports_response_schema)
        .bind(m.supports_system_messages)
        .bind(m.catalog_model_id) // $18: explicit catalog link (else auto-match)
        // $19: NULL (no map supplied) leaves the column NULL, which inherits the
        // catalog — a JSON `null` would be a stored value and would not.
        .bind(m.rates.as_ref().map(sqlx::types::Json))
        .bind(m.healing_enabled) // $20
        // $21: pin what the operator typed. A discovery-sourced batch pins
        // nothing, so its values keep tracking the provider on later refreshes.
        .bind(if req.from_discovery {
            Vec::new()
        } else {
            pinned_field_names(inheritable_field_presence!(m))
        })
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("create model: {e}");
            ApiError::internal("failed to create model")
        })?;

        if let Some(row) = row {
            // Every model carries a default (passthrough) preset from creation, so
            // the mirror below (which fans out per preset) always emits its alias.
            super::model_presets::ensure_default_preset(&mut tx, tenant_id, row.id)
                .await
                .map_err(|e| {
                    tracing::error!("ensure default preset: {e}");
                    ApiError::internal("failed to create model")
                })?;
            super::upstream_endpoints::assume_on_listed_endpoints(&mut tx, tenant_id, server_id, row.id)
                .await
                .map_err(|e| {
                    tracing::error!("model endpoint membership: {e}");
                    ApiError::internal("failed to create model")
                })?;
            created.push(row.into());
        }
    }

    // Mirror sync: auto-create/update downstream routes for this server.
    if !created.is_empty() {
        let server_name: Option<String> =
            sqlx::query_scalar("SELECT name FROM upstream_servers WHERE id = $1")
                .bind(server_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| {
                    tracing::error!("mirror sync: read server name: {e}");
                    ApiError::internal("failed to create model")
                })?;
        if let Some(name) = server_name {
            // Non-fatal here: the model write stands, so a mirror hiccup (incl. a
            // NameConflict) is logged, not surfaced — unlike Sync-now / the
            // autosync worker, which roll the whole apply back and record the
            // conflict for the operator to fix.
            let mirrored = mirror_sync_best_effort(&mut tx, server_id, &name, tenant_id)
                .await
                .map_err(|e| {
                    tracing::error!("mirror sync savepoint: {e}");
                    ApiError::internal("failed to create model")
                })?;
            if let Some(result) = mirrored
                && result.routes_added > 0
            {
                tracing::info!("Mirror sync added {} routes for server '{}'", result.routes_added, name);
            }
        }
    }

    tx.commit().await.map_err(|e| {
        tracing::error!("create models commit: {e}");
        ApiError::internal("failed to create models")
    })?;

    Ok((StatusCode::CREATED, Json(CreatedModels { models: created })))
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ModelListQuery {
    pub server_id: Option<Uuid>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/models",
    tag = "Models",
    params(ModelListQuery),
    responses(
        (status = 200, description = "Paginated list of models", body = TotalPage<ModelResponse>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_models(
    mut db: TenantConn,
    Query(query): Query<ModelListQuery>,
) -> Result<Json<TotalPage<ModelResponse>>, ApiError> {
    let page = PageQuery { limit: query.limit, offset: query.offset };
    let (limit, offset) = page.resolve();

    let (count_sql, rows_sql, bind_server_id) = if let Some(server_id) = query.server_id {
        (
            "SELECT COUNT(*) FROM upstream_models WHERE server_id = $1".to_string(),
            format!("{} WHERE m.server_id = $1 {MODEL_GROUP_BY} ORDER BY s.name, m.upstream_model LIMIT $2 OFFSET $3", MODEL_SELECT.as_str()),
            Some(server_id),
        )
    } else {
        (
            "SELECT COUNT(*) FROM upstream_models".to_string(),
            format!("{} {MODEL_GROUP_BY} ORDER BY s.name, m.upstream_model LIMIT $1 OFFSET $2", MODEL_SELECT.as_str()),
            None,
        )
    };

    let mut count_q = sqlx::query_scalar(sqlx::AssertSqlSafe(&*count_sql));
    if let Some(server_id) = bind_server_id {
        count_q = count_q.bind(server_id);
    }
    let total: i64 = count_q.fetch_one(db.conn()).await.map_err(|e| {
        tracing::error!("count models: {e}");
        ApiError::internal("failed to list models")
    })?;

    let mut rows_q = sqlx::query_as::<_, ModelRow>(sqlx::AssertSqlSafe(&*rows_sql));
    if let Some(server_id) = bind_server_id {
        rows_q = rows_q.bind(server_id);
    }
    rows_q = rows_q.bind(limit).bind(offset);

    let rows = rows_q.fetch_all(db.conn()).await.map_err(|e| {
        tracing::error!("list models: {e}");
        ApiError::internal("failed to list models")
    })?;

    let items: Vec<ModelResponse> = rows.into_iter().map(Into::into).collect();
    Ok(Json(TotalPage::new(items, limit, offset, total)))
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateModelRequest {
    pub upstream_model: Option<String>,
    pub context_window: Option<i32>,
    pub max_output_tokens: Option<i32>,
    pub upstream_api_format: Option<String>,
    pub model_type: Option<String>,
    pub enabled: Option<bool>,
    #[serde(default)]
    pub supports_vision: Option<bool>,
    #[serde(default)]
    pub supports_reasoning: Option<bool>,
    #[serde(default)]
    pub supports_function_calling: Option<bool>,
    #[serde(default)]
    pub supports_caching: Option<bool>,
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
    /// Per-model self-healing override. NULL = inherit the tenant `healing_enabled`.
    #[serde(default)]
    pub healing_enabled: Option<bool>,
    /// Price override, replacing the catalog's map WHOLE (omitted = leave the
    /// stored value alone; name `rates` in `reset_fields` to go back to
    /// inheriting). An empty map is an operator saying "no price", which does
    /// not fall through to the catalog.
    #[serde(default)]
    pub rates: Option<Rates>,
    /// The explicit catalog link (inherit from this entry): absent leaves it,
    /// `null` clears it so the model auto-matches by name again.
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<Uuid>)]
    pub catalog_model_id: Option<Option<Uuid>>,
    /// Fields to reset to inherited — clears the stored override (column → NULL)
    /// and drops the field from `user_overridden_fields`.
    #[serde(default)]
    pub reset_fields: Vec<String>,
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/models/{id}",
    tag = "Models",
    params(("id" = Uuid, Path, description = "Model ID")),
    request_body = UpdateModelRequest,
    responses(
        (status = 200, description = "Updated model", body = ModelResponse),
        (status = 400, description = "Invalid request", body = ApiErrorResponse),
        (status = 404, description = "Model not found (`model_not_found`), or the linked catalog entry is missing or deleted (`catalog_entry_not_found`)", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_model(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateModelRequest>,
) -> Result<Json<ModelResponse>, ApiError> {
    // Validate non-empty upstream_api_format values (empty string = clear to NULL/inherit).
    if let Some(fmt) = &req.upstream_api_format
        && !fmt.is_empty()
    {
        if !VALID_API_FORMATS.contains(&fmt.as_str()) {
            return Err(ApiError::bad_request("invalid upstream_api_format").code(ApiErrorCode::ApiFormatInvalid));
        }
        // The override wins over the server's protocol on the wire, so it faces
        // the same transport rule the server write does.
        let transport: Option<String> = sqlx::query_scalar(
            "SELECT s.transport FROM upstream_models m \
             JOIN upstream_servers s ON s.id = m.server_id WHERE m.id = $1",
        )
        .bind(id)
        .fetch_optional(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("update model transport read: {e}");
            ApiError::internal("failed to update model")
        })?;
        let transport = transport
            .ok_or_else(|| ApiError::not_found("model not found", ApiErrorCode::ModelNotFound))?;
        let server_transport = UpstreamTransport::from_str_relaxed(&transport);
        if !server_transport.allows_format(fmt) {
            return Err(transport_format_error(server_transport));
        }
    }

    // Each inheritable field the caller explicitly set is recorded in
    // `user_overridden_fields` so a later catalog change or autosync refresh
    // cannot silently rewrite it. Covers caps, pricing, and token limits.
    let touched_fields = pinned_field_names(inheritable_field_presence!(req));

    let tenant_id = db.tenant_uuid();
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("update model begin: {e}");
        ApiError::internal("failed to update model")
    })?;
    // Re-enabling writes endpoint memberships: take the server row first, the
    // lock order every endpoint write follows (`upstream_endpoints::lock_server`).
    if req.enabled == Some(true) {
        let server_id: Option<Uuid> = sqlx::query_scalar("SELECT server_id FROM upstream_models WHERE id = $1")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!("update model server lookup: {e}");
                ApiError::internal("failed to update model")
            })?;
        if let Some(server_id) = server_id {
            super::upstream_endpoints::lock_server(&mut tx, server_id).await.map_err(|e| {
                tracing::error!("update model server lock: {e}");
                ApiError::internal("failed to update model")
            })?;
        }
    }
    // The link's entry is share-locked BEFORE the model row: a catalog delete
    // locks the entry and then unlinks models, so the reverse order deadlocks.
    if let Some(Some(cat)) = req.catalog_model_id {
        // A missing model answers as one, whatever link it was sent.
        let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM upstream_models WHERE id = $1)")
            .bind(id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!("update model existence: {e}");
                ApiError::internal("failed to update model")
            })?;
        if !exists {
            return Err(ApiError::not_found("model not found", ApiErrorCode::ModelNotFound));
        }
        super::catalog::require_live_entries(&mut tx, &[cat]).await?;
    }
    let row = sqlx::query_as::<_, ModelRow>(sqlx::AssertSqlSafe(
        &*crate::routes::with_catalog_join(
        concat!(r#"WITH updated AS (
               -- Reset wins: a field named in $22 is cleared to NULL (re-inherit);
               -- otherwise COALESCE keeps the prior value when the caller omits it.
               UPDATE upstream_models SET
                   upstream_model = COALESCE($2, upstream_model),
                   context_window = CASE WHEN 'context_window' = ANY($22::text[]) THEN NULL ELSE COALESCE($3, context_window) END,
                   max_output_tokens = CASE WHEN 'max_output_tokens' = ANY($22::text[]) THEN NULL ELSE COALESCE($4, max_output_tokens) END,
                   upstream_api_format = CASE
                       WHEN $5::text IS NULL THEN upstream_api_format
                       WHEN $5::text = '' THEN NULL
                       ELSE $5
                   END,
                   model_type = COALESCE($6, model_type),
                   enabled = COALESCE($7, enabled),
                   supports_vision = CASE WHEN 'supports_vision' = ANY($22::text[]) THEN NULL ELSE COALESCE($8, supports_vision) END,
                   supports_reasoning = CASE WHEN 'supports_reasoning' = ANY($22::text[]) THEN NULL ELSE COALESCE($9, supports_reasoning) END,
                   supports_function_calling = CASE WHEN 'supports_function_calling' = ANY($22::text[]) THEN NULL ELSE COALESCE($10, supports_function_calling) END,
                   supports_caching = CASE WHEN 'supports_caching' = ANY($22::text[]) THEN NULL ELSE COALESCE($11, supports_caching) END,
                   supports_audio_input = CASE WHEN 'supports_audio_input' = ANY($22::text[]) THEN NULL ELSE COALESCE($12, supports_audio_input) END,
                   supports_audio_output = CASE WHEN 'supports_audio_output' = ANY($22::text[]) THEN NULL ELSE COALESCE($13, supports_audio_output) END,
                   supports_video_input = CASE WHEN 'supports_video_input' = ANY($22::text[]) THEN NULL ELSE COALESCE($14, supports_video_input) END,
                   supports_pdf_input = CASE WHEN 'supports_pdf_input' = ANY($22::text[]) THEN NULL ELSE COALESCE($15, supports_pdf_input) END,
                   supports_response_schema = CASE WHEN 'supports_response_schema' = ANY($22::text[]) THEN NULL ELSE COALESCE($16, supports_response_schema) END,
                   supports_system_messages = CASE WHEN 'supports_system_messages' = ANY($22::text[]) THEN NULL ELSE COALESCE($17, supports_system_messages) END,
                   healing_enabled = CASE WHEN 'healing_enabled' = ANY($22::text[]) THEN NULL ELSE COALESCE($23, healing_enabled) END,
                   -- The whole price list moves as one: a reset re-inherits the
                   -- catalog's map, a supplied map replaces it outright.
                   rates = CASE WHEN 'rates' = ANY($22::text[]) THEN NULL ELSE COALESCE($18, rates) END,
                   catalog_model_id = CASE WHEN $21 THEN $20 ELSE catalog_model_id END,
                   user_overridden_caps = ARRAY(
                       SELECT DISTINCT f FROM unnest(user_overridden_caps || $19::text[]) AS f
                       WHERE NOT (f = ANY($22::text[]))
                   )
               WHERE id = $1
               RETURNING *
           )
           SELECT u.id, u.server_id, s.name as server_name, s.provider,
                  u.upstream_model, "#, server_url_sql!("s"), r#" AS upstream_url,
                  u.context_window, u.max_output_tokens,
                  COALESCE(u.context_window, c.context_window) as resolved_context_window,
                  "#, resolved_max_output_sql!("u", "c"), r#" as resolved_max_output_tokens,
                  COALESCE(u.upstream_api_format, s.upstream_api_format) as upstream_api_format,
                  u.model_type,
                  u.enabled, u.created_at,
                  u.catalog_model_id, c.catalog_match_id as resolved_catalog_model_id,
                  u.user_overridden_caps as user_overridden_fields,
                  (SELECT COUNT(*) FROM downstream_routes dr WHERE dr.model_id = u.id)::bigint as route_count,
                  -- Raw capability values
                  u.supports_vision, u.supports_reasoning, u.supports_function_calling, u.supports_caching,
                  u.supports_audio_input, u.supports_audio_output, u.supports_video_input, u.supports_pdf_input,
                  u.supports_response_schema, u.supports_system_messages,
                  u.healing_enabled,
                  -- Resolved capabilities (COALESCE with catalog)
                  COALESCE(u.supports_vision, c.supports_vision) as resolved_supports_vision,
                  COALESCE(u.supports_reasoning, c.supports_reasoning) as resolved_supports_reasoning,
                  COALESCE(u.supports_function_calling, c.supports_function_calling) as resolved_supports_function_calling,
                  COALESCE(u.supports_caching, c.supports_caching) as resolved_supports_caching,
                  COALESCE(u.supports_audio_input, c.supports_audio_input) as resolved_supports_audio_input,
                  COALESCE(u.supports_audio_output, c.supports_audio_output) as resolved_supports_audio_output,
                  COALESCE(u.supports_video_input, c.supports_video_input) as resolved_supports_video_input,
                  COALESCE(u.supports_pdf_input, c.supports_pdf_input) as resolved_supports_pdf_input,
                  COALESCE(u.supports_response_schema, c.supports_response_schema) as resolved_supports_response_schema,
                  COALESCE(u.supports_system_messages, c.supports_system_messages) as resolved_supports_system_messages,
                  -- Pricing: stored override, the map in force, and the catalog's
                  -- own map (inherited whole, never mixed).
                  u.rates,
                  COALESCE(u.rates, catp.rates, '{}'::jsonb) as resolved_rates,
                  catp.rates as catalog_rates
           FROM updated u
           JOIN upstream_servers s ON s.id = u.server_id
--{catalog_join}"#),
        "u",
        "s",
    ),
    ))
    .bind(id)
    .bind(&req.upstream_model)
    .bind(req.context_window)
    .bind(req.max_output_tokens)
    .bind(&req.upstream_api_format)
    .bind(&req.model_type)
    .bind(req.enabled)
    .bind(req.supports_vision)
    .bind(req.supports_reasoning)
    .bind(req.supports_function_calling)
    .bind(req.supports_caching)
    .bind(req.supports_audio_input)
    .bind(req.supports_audio_output)
    .bind(req.supports_video_input)
    .bind(req.supports_pdf_input)
    .bind(req.supports_response_schema)
    .bind(req.supports_system_messages)
    // $18: NULL (no map supplied) keeps the stored one — a JSON `null` would
    // overwrite it with a value that inherits nothing.
    .bind(req.rates.as_ref().map(sqlx::types::Json))
    .bind(&touched_fields) // $19
    .bind(req.catalog_model_id.flatten()) // $20
    .bind(req.catalog_model_id.is_some()) // $21: the link was named (a value, or null to clear)
    .bind(&req.reset_fields) // $22
    .bind(req.healing_enabled) // $23
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("update model: {e}");
        ApiError::internal("failed to update model")
    })?
    .ok_or_else(|| ApiError::not_found("model not found", ApiErrorCode::ModelNotFound))?;

    // A model re-enabled after a sync retired it has no endpoint to serve it.
    if req.enabled == Some(true) {
        super::upstream_endpoints::assume_unserved_models(&mut tx, tenant_id, Some(row.server_id))
            .await
            .map_err(|e| {
                tracing::error!("update model endpoint membership: {e}");
                ApiError::internal("failed to update model")
            })?;
    }
    tx.commit().await.map_err(|e| {
        tracing::error!("update model commit: {e}");
        ApiError::internal("failed to update model")
    })?;

    Ok(Json(row.into()))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/models/{id}",
    tag = "Models",
    params(("id" = Uuid, Path, description = "Model ID")),
    responses(
        (status = 200, description = "Model deleted; impact reports any orphaned downstream routes", body = ActionResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_model(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<ActionResponse>, ApiError> {
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("delete model begin: {e}");
        ApiError::internal("failed to delete model")
    })?;

    // Orphan (never destroy) any curated downstream routes to this model, then
    // delete the model row; the FK nulls the flagged routes' `model_id`.
    let impact = super::downstream::orphan_model_routes(&mut tx, std::slice::from_ref(&id))
        .await
        .map_err(|e| {
            tracing::error!("delete model orphan routes: {e}");
            ApiError::internal("failed to delete model")
        })?;

    sqlx::query("DELETE FROM upstream_models WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("delete model: {e}");
            ApiError::internal("failed to delete model")
        })?;

    tx.commit().await.map_err(|e| {
        tracing::error!("delete model commit: {e}");
        ApiError::internal("failed to delete model")
    })?;

    Ok(Json(orphan_action_response("Model deleted", impact)))
}

#[derive(Deserialize, ToSchema)]
pub struct BatchDeleteRequest {
    pub ids: Vec<Uuid>,
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/servers/{id}/models",
    tag = "Models",
    params(("id" = Uuid, Path, description = "Server ID")),
    request_body = BatchDeleteRequest,
    responses(
        (status = 200, description = "Models deleted; impact reports any orphaned downstream routes", body = ActionResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn batch_delete_models(
    mut db: TenantConn,
    Path(server_id): Path<Uuid>,
    Json(req): Json<BatchDeleteRequest>,
) -> Result<Json<ActionResponse>, ApiError> {
    // One transaction so a mid-batch failure rolls back fully — no partial
    // deletion of the selected models.
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("batch delete models begin: {e}");
        ApiError::internal("failed to delete models")
    })?;

    // Scope the delete set to this server's models, then orphan any curated routes
    // to them before deleting (the FK nulls the flagged routes' `model_id`).
    let model_ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM upstream_models WHERE id = ANY($1) AND server_id = $2",
    )
    .bind(&req.ids)
    .bind(server_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("batch delete models fetch: {e}");
        ApiError::internal("failed to delete models")
    })?;

    let impact = super::downstream::orphan_model_routes(&mut tx, &model_ids)
        .await
        .map_err(|e| {
            tracing::error!("batch delete models orphan routes: {e}");
            ApiError::internal("failed to delete models")
        })?;

    sqlx::query("DELETE FROM upstream_models WHERE id = ANY($1) AND server_id = $2")
        .bind(&model_ids)
        .bind(server_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("batch delete models: {e}");
            ApiError::internal("failed to delete models")
        })?;

    tx.commit().await.map_err(|e| {
        tracing::error!("batch delete models commit: {e}");
        ApiError::internal("failed to delete models")
    })?;

    Ok(Json(orphan_action_response("Models deleted", impact)))
}

// ---------------------------------------------------------------------------
// Bulk model update (enable/disable all)
// ---------------------------------------------------------------------------

#[derive(Deserialize, ToSchema)]
pub struct BulkUpdateModelsRequest {
    /// Scope to a single server. If omitted, applies to ALL servers.
    pub server_id: Option<Uuid>,
    /// If provided, only update these model IDs (overrides server_id).
    pub ids: Option<Vec<Uuid>>,
    pub enabled: bool,
}

#[derive(Serialize, ToSchema)]
pub struct BulkUpdateModelsResponse {
    pub models_updated: i64,
    pub routes_deleted: i64,
    pub routes_disabled: i64,
    pub routes_enabled: i64,
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/models/actions/bulk-update",
    tag = "Models",
    request_body = BulkUpdateModelsRequest,
    responses(
        (status = 200, description = "Models updated", body = BulkUpdateModelsResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn bulk_update_models(
    mut db: TenantConn,
    axum::Extension(audit_sink): axum::Extension<crate::middleware::AuditDiffSink>,
    Json(req): Json<BulkUpdateModelsRequest>,
) -> Result<Json<BulkUpdateModelsResponse>, ApiError> {
    let tenant_id = db.tenant_uuid();
    // One transaction over the model UPDATE + every route cascade + mirror
    // re-sync so a mid-sequence failure rolls back fully — never a state where
    // auto_synced routes are deleted but the models stayed enabled.
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("bulk update models begin: {e}");
        ApiError::internal("failed to bulk update models")
    })?;
    // Re-enabling writes endpoint memberships: take the rows of the servers it
    // touches first (in id order), the lock order every endpoint write follows
    // (`upstream_endpoints::lock_server`). `None` = every server of the tenant.
    let touched: Option<Vec<Uuid>> = match (&req.ids, req.server_id) {
        (Some(ids), _) => Some(
            sqlx::query_scalar("SELECT DISTINCT server_id FROM upstream_models WHERE id = ANY($1)")
                .bind(ids)
                .fetch_all(&mut *tx)
                .await
                .map_err(|e| {
                    tracing::error!("bulk update models servers: {e}");
                    ApiError::internal("failed to bulk update models")
                })?,
        ),
        (None, Some(server_id)) => Some(vec![server_id]),
        (None, None) => None,
    };
    if req.enabled {
        sqlx::query("SELECT 1 FROM upstream_servers WHERE $1::uuid[] IS NULL OR id = ANY($1) ORDER BY id FOR NO KEY UPDATE")
            .bind(&touched)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!("bulk update models server lock: {e}");
                ApiError::internal("failed to bulk update models")
            })?;
    }

    // 1. Update upstream models
    let model_rows = if let Some(ids) = &req.ids {
        sqlx::query("UPDATE upstream_models SET enabled = $1 WHERE id = ANY($2)")
            .bind(req.enabled)
            .bind(ids)
            .execute(&mut *tx)
            .await
    } else if let Some(server_id) = req.server_id {
        sqlx::query("UPDATE upstream_models SET enabled = $1 WHERE server_id = $2")
            .bind(req.enabled)
            .bind(server_id)
            .execute(&mut *tx)
            .await
    } else {
        sqlx::query("UPDATE upstream_models SET enabled = $1")
            .bind(req.enabled)
            .execute(&mut *tx)
            .await
    }
    .map_err(|e| {
        tracing::error!("bulk update models: {e}");
        ApiError::internal("failed to bulk update models")
    })?;

    // 2. Cascade to downstream routes using parameterized queries.
    let (mut routes_deleted, mut routes_disabled, mut routes_enabled) = (0i64, 0i64, 0i64);

    if model_rows.rows_affected() > 0 {
        // Collect affected model IDs so cascade queries use ANY($1) with binds.
        let affected_ids: Vec<Uuid> = if let Some(ids) = &req.ids {
            ids.clone()
        } else if let Some(server_id) = req.server_id {
            sqlx::query_scalar("SELECT id FROM upstream_models WHERE server_id = $1")
                .bind(server_id)
                .fetch_all(&mut *tx)
                .await
                .map_err(|e| {
                    tracing::error!("fetch affected model ids: {e}");
                    ApiError::internal("failed to resolve affected models")
                })?
        } else {
            sqlx::query_scalar("SELECT id FROM upstream_models")
                .fetch_all(&mut *tx)
                .await
                .map_err(|e| {
                    tracing::error!("fetch affected model ids: {e}");
                    ApiError::internal("failed to resolve affected models")
                })?
        };

        if !req.enabled {
            // DISABLE cascade:
            // - auto_synced routes → DELETE (ephemeral, will be re-created on sync)
            // - manual routes → disable (preserve user config)
            let del = sqlx::query(
                "DELETE FROM downstream_routes WHERE model_id = ANY($1) AND auto_synced = true",
            )
            .bind(&affected_ids)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!("cascade delete auto_synced routes: {e}");
                ApiError::internal("failed to cascade to downstream routes")
            })?;
            routes_deleted = del.rows_affected() as i64;

            let dis = sqlx::query(
                "UPDATE downstream_routes SET enabled = false WHERE model_id = ANY($1) AND auto_synced = false AND enabled = true",
            )
            .bind(&affected_ids)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!("cascade disable manual routes: {e}");
                ApiError::internal("failed to cascade to downstream routes")
            })?;
            routes_disabled = dis.rows_affected() as i64;
        } else {
            // ENABLE cascade:
            // - manual routes that were disabled → re-enable
            // - auto_synced routes were deleted → re-create via mirror sync
            let en = sqlx::query(
                "UPDATE downstream_routes SET enabled = true WHERE model_id = ANY($1) AND auto_synced = false AND enabled = false",
            )
            .bind(&affected_ids)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!("cascade enable manual routes: {e}");
                ApiError::internal("failed to cascade to downstream routes")
            })?;
            routes_enabled = en.rows_affected() as i64;

            // Re-create auto_synced routes by calling mirror sync for affected servers.
            let affected_servers: Vec<(Uuid, String)> = if let Some(server_id) = req.server_id {
                sqlx::query_as("SELECT id, name FROM upstream_servers WHERE id = $1")
                    .bind(server_id)
                    .fetch_all(&mut *tx)
                    .await
                    .map_err(|e| {
                        tracing::error!("cascade enable: read servers: {e}");
                        ApiError::internal("failed to cascade to downstream routes")
                    })?
            } else if !affected_ids.is_empty() {
                sqlx::query_as(
                    "SELECT DISTINCT s.id, s.name FROM upstream_servers s \
                     JOIN upstream_models m ON m.server_id = s.id WHERE m.id = ANY($1)",
                )
                .bind(&affected_ids)
                .fetch_all(&mut *tx)
                .await
                .map_err(|e| {
                    tracing::error!("cascade enable: read servers: {e}");
                    ApiError::internal("failed to cascade to downstream routes")
                })?
            } else {
                Vec::new()
            };
            for (sid, sname) in &affected_servers {
                mirror_sync_best_effort(&mut tx, *sid, sname, tenant_id).await.map_err(|e| {
                    tracing::error!("cascade enable: mirror savepoint: {e}");
                    ApiError::internal("failed to cascade to downstream routes")
                })?;
            }
        }
    }

    // A model re-enabled after a sync retired it has no endpoint to serve it.
    if req.enabled {
        let servers: Vec<Option<Uuid>> = match &touched {
            Some(ids) => ids.iter().copied().map(Some).collect(),
            None => vec![None],
        };
        for server in servers {
            super::upstream_endpoints::assume_unserved_models(&mut tx, tenant_id, server)
                .await
                .map_err(|e| {
                    tracing::error!("bulk update models endpoint membership: {e}");
                    ApiError::internal("failed to bulk update models")
                })?;
        }
    }
    tx.commit().await.map_err(|e| {
        tracing::error!("bulk update models commit: {e}");
        ApiError::internal("failed to bulk update models")
    })?;

    let resp = BulkUpdateModelsResponse {
        models_updated: model_rows.rows_affected() as i64,
        routes_deleted,
        routes_disabled,
        routes_enabled,
    };
    audit_sink.set(
        serde_json::Value::Null,
        serde_json::json!({
            "enabled": req.enabled,
            "models_updated": resp.models_updated,
            "routes_deleted": resp.routes_deleted,
            "routes_disabled": resp.routes_disabled,
            "routes_enabled": resp.routes_enabled,
        }),
    );
    Ok(Json(resp))
}

// ---------------------------------------------------------------------------
// Model sync (discover + diff)
// ---------------------------------------------------------------------------

#[derive(Serialize, ToSchema, Clone, Default)]
pub struct DiscoveredModel {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_window: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<i64>,
    // Capabilities learned from the provider's model metadata. None = the
    // provider didn't advertise it → falls back to the standard default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supports_vision: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supports_reasoning: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supports_function_calling: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supports_caching: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supports_audio_input: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supports_audio_output: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supports_video_input: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supports_pdf_input: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supports_response_schema: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supports_system_messages: Option<bool>,
    /// Prices the provider published, one entry per billing unit it names, each
    /// normalized to that unit's natural scale (per 1M for token units, per unit
    /// otherwise). `None` = the provider published no price at all, so the model
    /// inherits the catalog's map rather than overriding it with an empty one.
    ///
    /// Reading the unit off the provider's own key is what keeps a transcription
    /// model (billed per second of audio) from being filed as a token-priced one
    /// and then billing nothing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rates: Option<Rates>,
    /// What the engine says it serves under this name (vLLM `root`: the weights
    /// path, or an adapter's path). Compared across a server's endpoints to flag
    /// replicas that may serve different weights under one name; never routed on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    /// The base model of an adapter (vLLM `parent`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
}

#[derive(Serialize, ToSchema, Clone)]
pub struct RemovedModelInfo {
    pub id: Uuid,
    pub upstream_model: String,
    pub route_count: i64,
    pub in_use: bool,
}

#[derive(Serialize, ToSchema)]
pub struct ModelSyncResponse {
    pub discovered: Vec<DiscoveredModel>,
    pub existing: Vec<ModelResponse>,
    pub new_models: Vec<DiscoveredModel>,
    pub removed: Vec<RemovedModelInfo>,
    /// What each enabled endpoint answered, primary first.
    pub endpoints: Vec<super::model_sync::EndpointSyncReport>,
    /// "Sync now" would not make some of `removed`, or would refuse the sync
    /// whole: it judges an answer implausibly short (under half of what the
    /// server, or the endpoint, listed before). The review still offers them — a server
    /// can really shrink — and this says to check the server is fully up
    /// before accepting them.
    pub unattended_refuses: bool,
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/servers/{id}/actions/sync",
    tag = "Servers",
    params(("id" = Uuid, Path, description = "Server ID")),
    responses(
        (status = 200, description = "Model sync results", body = ModelSyncResponse),
        (status = 404, description = "Server not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 502, description = "Upstream provider error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn sync_server_models(
    mut db: TenantConn,
    axum::Extension(audit_sink): axum::Extension<crate::middleware::AuditDiffSink>,
    Path(server_id): Path<Uuid>,
) -> Result<Json<ModelSyncResponse>, ApiError> {
    use super::model_sync::{apply_sync, discover_all, load_sync_server, nobody_answered, sync_error_to_api, SyncMode};
    let tenant_id = db.tenant_uuid();
    let server = load_sync_server(db.conn(), server_id)
        .await
        .map_err(sync_error_to_api)?
        .ok_or_else(|| ApiError::not_found("server not found", ApiErrorCode::ServerNotFound))?;

    // Refresh the trusted-CA cache so a just-imported custom CA applies to this
    // discovery on any replica.
    crate::custom_ca::refresh_from_conn(db.conn()).await;

    // Manual sync = read-only diff the operator reviews; the UI applies it
    // through the model create and delete endpoints. The pipeline computes the
    // worker's diff (real removed-route counts included) but judges no
    // answer's length, so it also offers removals the worker refuses as
    // implausible — `unattended_refuses` says when.
    let answers = discover_all(&server).await;
    if let Some(e) = nobody_answered(&answers) {
        // Deliberately records NOTHING. This path previews a diff and applies
        // none of it, so it has no success to record either — and a surface
        // that can only ever write a failure would mark a healthy server
        // permanently failed the first time an operator opened Review while
        // the upstream blinked, with no way to clear it from here.
        return Err(sync_error_to_api(e));
    }
    let outcome = apply_sync(db.conn(), tenant_id, &server, &answers, SyncMode::Manual)
        .await
        .map_err(sync_error_to_api)?;

    let existing_rows = sqlx::query_as::<_, ModelRow>(
        sqlx::AssertSqlSafe(&*format!("{} WHERE m.server_id = $1 {MODEL_GROUP_BY} ORDER BY m.upstream_model", MODEL_SELECT.as_str()),
    ))
    .bind(server_id)
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("sync server models: {e}");
        ApiError::internal("failed to query existing models")
    })?;
    let existing: Vec<ModelResponse> = existing_rows.into_iter().map(Into::into).collect();

    // Manual sync applies nothing — record the surfaced diff (what an apply would
    // add/remove) so the audit trail shows what the operator was shown.
    audit_sink.set(
        serde_json::Value::Null,
        serde_json::json!({
            "discovered": outcome.discovered.len(),
            "new": outcome.new_models.len(),
            "removed": outcome.removed.len(),
        }),
    );
    Ok(Json(ModelSyncResponse {
        discovered: outcome.discovered,
        existing,
        new_models: outcome.new_models,
        removed: outcome.removed,
        endpoints: outcome.endpoints,
        unattended_refuses: outcome.unattended_refuses,
    }))
}

/// Decrypt an upstream server's stored API key (None when the server has no
/// credential). Shared by the manual sync, the sync-now action, and the worker.
pub(crate) fn decrypt_server_key(encrypted_key: Option<String>) -> Result<Option<String>, ApiError> {
    match encrypted_key {
        Some(encrypted) => {
            let enc_key = streamscope_core::crypto::get_encryption_key()
                .ok_or_else(|| ApiError::server_misconfigured("ENCRYPTION_KEY not configured"))?;
            Ok(Some(streamscope_core::crypto::decrypt(&encrypted, &enc_key).map_err(
                |e| {
                    tracing::error!("decrypt upstream credential: {e}");
                    ApiError::internal("failed to decrypt credential")
                },
            )?))
        }
        None => Ok(None),
    }
}

#[derive(Serialize, ToSchema)]
pub struct SyncNowResponse {
    pub added: u32,
    pub refreshed: u32,
    pub models_removed: u32,
    pub routes_deleted: u32,
    pub routes_disabled: u32,
    pub skipped_overrides: u32,
    /// What each enabled endpoint answered, primary first — an endpoint that
    /// did not answer changed nothing, which is why a sync can change less than
    /// expected.
    pub endpoints: Vec<super::model_sync::EndpointSyncReport>,
}

/// Apply an immediate exact-mirror sync for one server (the "Sync now" button).
/// Same write path the autosync worker runs: add + refresh + remove in one
/// transaction, gated by the plausibility check.
#[utoipa::path(
    post,
    path = "/api/v1/admin/servers/{id}/actions/sync-now",
    tag = "Servers",
    params(("id" = Uuid, Path, description = "Server ID")),
    responses(
        (status = 200, description = "Sync applied", body = SyncNowResponse),
        (status = 404, description = "Server not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 502, description = "Upstream provider error or implausible discovery", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn sync_now(
    mut db: TenantConn,
    axum::Extension(audit_sink): axum::Extension<crate::middleware::AuditDiffSink>,
    Path(server_id): Path<Uuid>,
) -> Result<Json<SyncNowResponse>, ApiError> {
    let tenant_id = db.tenant_uuid();
    // Refresh the trusted-CA cache so a just-imported custom CA applies here.
    crate::custom_ca::refresh_from_conn(db.conn()).await;
    let outcome = match super::model_sync::run_sync(
        db.conn(),
        tenant_id,
        server_id,
        Some(super::model_sync::SyncMode::Explicit),
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(e) => {
            // The caller sees this error, but the ROW must say it too: leaving
            // the previous SUCCESS in place has every other surface — the
            // gateway list, the server page — reporting a server as healthy
            // while its models are whatever they were before the credential
            // was revoked. Not an attempt: the operator asking has not
            // consumed the worker's turn.
            let reason = e.reason();
            let _ = super::model_sync::record_sync_failure(db.conn(), server_id, &reason, false).await;
            return Err(super::model_sync::sync_error_to_api(e));
        }
    };

    let resp = SyncNowResponse {
        added: outcome.added,
        refreshed: outcome.refreshed,
        models_removed: outcome.models_removed,
        routes_deleted: outcome.routes_deleted,
        routes_disabled: outcome.routes_disabled,
        skipped_overrides: outcome.skipped_overrides,
        endpoints: outcome.endpoints,
    };
    audit_sink.set(
        serde_json::Value::Null,
        serde_json::json!({
            "added": resp.added,
            "refreshed": resp.refreshed,
            "models_removed": resp.models_removed,
            "routes_deleted": resp.routes_deleted,
            "routes_disabled": resp.routes_disabled,
            "skipped_overrides": resp.skipped_overrides,
        }),
    );
    Ok(Json(resp))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn encrypt_api_key(api_key: Option<&str>) -> Result<(Option<String>, Option<String>), ApiError> {
    match api_key {
        Some(key) if !key.is_empty() => {
            let enc_key = streamscope_core::crypto::get_encryption_key().ok_or_else(|| {
                tracing::error!("ENCRYPTION_KEY not set — refusing to store credential in plaintext");
                ApiError::server_misconfigured("ENCRYPTION_KEY not configured")
            })?;
            let encrypted = streamscope_core::crypto::encrypt(key, &enc_key).map_err(|e| {
                tracing::error!("failed to encrypt credential: {e}");
                ApiError::internal("failed to encrypt credential")
            })?;
            Ok((Some(encrypted), Some("aes-256-gcm".to_string())))
        }
        _ => Ok((None, None)),
    }
}

/// Providers that publish no model-listing endpoint at all.
///
/// One set, three consumers, because every one of them is asking the same
/// question: the write-time reachability probe skips them (its target does not
/// exist, so it would report a spurious 404 on an otherwise correct base URL),
/// the periodic autosync worker never selects them (`model_sync.rs` BINDS this
/// slice, so the two can never disagree), and the console hides the discovery
/// toggle. A provider belongs here only when its list cannot be read — never
/// because our parsing of it is incomplete.
///
/// Entries MUST be lowercase and unpadded: nothing normalises `provider` on the
/// way in, so all three readers canonicalise it the same way before comparing —
/// the SQL with `lower(btrim(provider))`, the Rust with
/// `trim().to_ascii_lowercase()`, the console with `trim().toLowerCase()`. An
/// entry that is capitalised or padded would match none of them.
pub(super) const PROVIDERS_WITHOUT_MODELS_ENDPOINT: &[&str] = &["perplexity"];

/// Bound on an upstream *error* body read during a probe or discovery call.
///
/// The body is only ever summarised for an operator message
/// ([`summarize_probe_body`] drops HTML outright and truncates the rest), so a
/// small cap loses nothing — and the base URL is tenant-admin-writable, which
/// makes an unbounded read a way to OOM this replica by pointing a provider at
/// a host that answers with a firehose.
pub(crate) const PROBE_ERROR_BODY_CAP: u64 = 64 * 1024;

/// Bound on a model-discovery response body (one page).
///
/// Real `/v1/models` documents are well under a megabyte even for aggregators
/// listing hundreds of models; 8 MiB is generous enough that no honest provider
/// meets it, and small enough that a hostile one cannot exhaust the control
/// plane. A page that crosses it fails discovery rather than being truncated —
/// a truncated list would later reconcile as "these models vanished upstream"
/// and disable live routes.
const MODEL_DISCOVERY_BODY_CAP: u64 = 8 * 1024 * 1024;

/// Read an upstream body under `cap`, as lossy UTF-8. Used for bodies that are
/// summarised into an operator-facing message, where an unreadable or oversized
/// body and an empty one lead to the same place.
pub(crate) async fn read_capped_lossy(resp: reqwest::Response, cap: u64) -> String {
    streamscope_core::http_body::read_body_capped(resp, cap)
        .await
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default()
}

/// Read and parse an upstream JSON body under [`MODEL_DISCOVERY_BODY_CAP`].
async fn read_capped_json(resp: reqwest::Response) -> Result<serde_json::Value, ApiError> {
    let raw = streamscope_core::http_body::read_body_capped(resp, MODEL_DISCOVERY_BODY_CAP)
        .await
        .map_err(|e| ApiError::bad_gateway(format!("unreadable response from provider: {e}")))?;
    let mut body: serde_json::Value = serde_json::from_slice(&raw)
        .map_err(|e| ApiError::bad_gateway(format!("invalid JSON from provider: {e}")))?;
    // Every discovery fetch reads through here, and every discovered string
    // (model id, parent, rates) is written to text and jsonb columns in one
    // sync transaction, where a single U+0000 would roll back the whole
    // server's sync on every autosync pass.
    streamscope_core::pg_text::scrub_nul_json(&mut body);
    Ok(body)
}

/// Whether a provider's model-listing endpoint exists to probe against. `false`
/// for [`PROVIDERS_WITHOUT_MODELS_ENDPOINT`]; the reachability probe is skipped
/// for those so an operator isn't shown a spurious "unreachable" 404 on a correct
/// base URL.
/// Whether saving this server should check anything at all.
///
/// Either there is a model list to GET — the provider publishes one and the
/// transport can address it — or the transport mints a token, in which case the
/// exchange stands in for the reachability check.
pub(super) fn probe_is_worth_making(provider: &str, transport: UpstreamTransport) -> bool {
    transport.mints_token()
        || (provider_has_models_endpoint(provider) && transport.publishes_model_list())
}

fn provider_has_models_endpoint(provider: &str) -> bool {
    // Trimmed as well as folded, and the SQL half does the same: nothing
    // normalises `provider` on the way in, so the three readers agree only if
    // they canonicalise the same way. One that trims while another does not
    // gives a server a control the API clamps straight back off.
    let p = provider.trim().to_ascii_lowercase();
    !PROVIDERS_WITHOUT_MODELS_ENDPOINT.contains(&p.as_str())
}

/// Whether this server's models can be discovered at all — the question the
/// autosync switch actually answers, and the one the console asks before
/// offering it.
///
/// BOTH halves must hold, and they fail for different reasons: a provider may
/// publish no list to read, and a transport may address an endpoint that serves
/// none. Asking only one of them leaves the switch on for a server whose every
/// run — the inline first sync at create included — fails with nothing an
/// operator can do about it.
pub(super) fn can_discover(provider: &str, transport: UpstreamTransport) -> bool {
    provider_has_models_endpoint(provider) && transport.publishes_model_list()
}

/// Validate/normalize an operator-supplied chat-endpoint-path override. Trims
/// surrounding whitespace (an empty result is "no override" → `None`); a
/// non-empty value MUST be a rooted path with no interior whitespace, else the
/// forward would fuse it onto the base host (`{url}chat/completions`) and fail
/// only at request time. `None` in stays `None` out.
fn normalize_chat_endpoint_path(value: Option<String>) -> Result<Option<String>, ApiError> {
    let Some(raw) = value else { return Ok(None) };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if !trimmed.starts_with('/') || trimmed.contains(char::is_whitespace) {
        return Err(ApiError::bad_request(
            "chat_endpoint_path must be a rooted path with no spaces, e.g. /chat/completions",
        ));
    }
    Ok(Some(trimmed.to_string()))
}

/// Everything one server write tells us about how it should be carried.
struct TransportRequest<'a> {
    /// The transport the request named, if any.
    requested: Option<&'a str>,
    provider: &'a str,
    upstream_api_format: &'a str,
    chat_endpoint_path: Option<&'a str>,
    upstream_url: Option<&'a str>,
    /// The credential supplied WITH this write (absent on a keep-current update).
    api_key: Option<&'a str>,
    byok: bool,
    /// What the server already stores — `None` on create.
    existing: Option<StoredCredential>,
}

/// Resolve and validate the transport for a server write.
///
/// The transport decides the URL shape and the credential header, so a
/// combination it cannot express is rejected here rather than silently ignored —
/// an Azure server that also carried a `chat_endpoint_path`, or spoke Gemini,
/// would be addressed at a path that does not exist and fail only at request
/// time, with nothing on the server page to explain it.
///
/// Every rule below is asked of the transport itself rather than named per
/// vendor, so a transport added later is validated by construction instead of by
/// remembering to extend each check.
fn resolve_transport(req: TransportRequest<'_>) -> Result<String, ApiError> {
    let TransportRequest {
        requested,
        provider,
        upstream_api_format,
        chat_endpoint_path,
        upstream_url,
        api_key,
        byok,
        existing,
    } = req;
    let resolved = requested
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .or_else(|| crate::seed_loader::provider_default_transport(provider))
        .unwrap_or_else(|| UpstreamTransport::Default.as_str().to_string());

    // Parsed strictly against the enum's own list — `from_str_relaxed` degrades an
    // unknown value to `default`, which on a write would silently store a server
    // that talks to the wrong endpoint.
    let transport = UpstreamTransport::ALL
        .into_iter()
        .find(|t| t.as_str() == resolved)
        .ok_or_else(|| {
            let known =
                UpstreamTransport::ALL.map(|t| format!("`{}`", t.as_str())).join(", ");
            ApiError::bad_request(format!(
                "`{resolved}` is not a supported transport. Use one of {known}."
            ))
            .code(ApiErrorCode::TransportInvalid)
        })?;

    if transport.owns_url() {
        if !transport.allows_format(upstream_api_format) {
            return Err(transport_format_error(transport));
        }
        if chat_endpoint_path.is_some() {
            return Err(ApiError::bad_request(format!(
                "A {} server's endpoint path is fixed by its transport — leave the chat \
                 endpoint path empty.",
                transport_label(transport)
            ))
            .code(ApiErrorCode::TransportInvalid));
        }
        let base = upstream_url.map(str::trim).filter(|u| !u.is_empty()).ok_or_else(|| {
            ApiError::bad_request(format!(
                "A {} server needs its endpoint URL, e.g. {}",
                transport_label(transport),
                transport_url_example(transport)
            ))
            .code(ApiErrorCode::TransportInvalid)
        })?;
        validate_transport_base_url(transport, base)?;
    }

    // A minting transport holds a credential document and exchanges it for a
    // token. A pass-through server forwards the CLIENT's credential instead, so
    // there is nothing to mint from and the document would never be used.
    if transport.mints_token() && byok {
        return Err(ApiError::bad_request(format!(
            "A pass-through server forwards the client's own credential, so it cannot use \
             {}. Use a transport that sends a key instead.",
            transport_label(transport)
        ))
        .code(ApiErrorCode::TransportInvalid));
    }

    // Validate a supplied credential document up front. Stored unvalidated, the
    // first failure would surface as an opaque upstream error on a user's request
    // rather than on the page that set it.
    let supplied = api_key.filter(|k| !k.is_empty());
    if let Some(key) = supplied
        && let Err(e) = validate_credential_document(transport, key)
    {
        return Err(ApiError::bad_request(format!(
            "{} credential: {}",
            transport_label(transport),
            credential_hint(&e)
        ))
        .code(ApiErrorCode::TransportInvalid));
    }

    // A stored credential belongs to the transport that stored it: a minting
    // transport keeps a DOCUMENT (an Entra client-credentials pair, a Vertex
    // service-account key), every other transport a raw key. Changing the
    // transport without re-supplying one would keep the old credential and use it
    // the new way — either sending a JSON document (its secret included) in a key
    // header, or handing a plain key to the token minter, which fails on every
    // request afterwards. Neither is recoverable by the operator without
    // re-keying, so require the credential with the change.
    if !byok && supplied.is_none() {
        let needs = credential_shape(transport);
        match existing {
            // Create: a minting server has nothing to mint from.
            None if matches!(needs, CredentialShape::Document(_)) => {
                return Err(missing_document_error(transport));
            }
            None => {}
            Some(StoredCredential { transport: stored, has_credential }) => {
                let stored = UpstreamTransport::from_str_relaxed(&stored);
                if credential_shape(stored) != needs {
                    return Err(ApiError::bad_request(
                        "Changing how this server authenticates needs its credential again — \
                         supply the new one with the change.",
                    )
                    .code(ApiErrorCode::TransportInvalid));
                }
                if matches!(needs, CredentialShape::Document(_)) && !has_credential {
                    return Err(missing_document_error(transport));
                }
            }
        }
    }

    // Refused here, not only by the gateway at request time: a server the
    // gateway can never reach must not be saved, even with "Save anyway".
    if let Some(url) = upstream_url.map(str::trim).filter(|u| !u.is_empty()) {
        provider_url_refusal(url)?;
    }

    Ok(resolved)
}

/// What a server's stored credential currently is, for an update.
struct StoredCredential {
    transport: String,
    has_credential: bool,
}

/// The kind of credential a transport stores. Two transports sharing a shape can
/// swap without re-keying; crossing shapes cannot.
///
/// A document is tagged with the transport that stored it, because two
/// *different* documents are still both documents: an Entra client-credentials
/// pair and a Google service-account key are both JSON, and neither can mint
/// from the other's — so swapping between them must ask for the credential too.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum CredentialShape {
    /// A provider key, sent verbatim in a header.
    RawKey,
    /// A document only its own transport can mint from.
    Document(UpstreamTransport),
}

fn credential_shape(transport: UpstreamTransport) -> CredentialShape {
    if transport.credential_is_document() {
        CredentialShape::Document(transport)
    } else {
        CredentialShape::RawKey
    }
}

/// The operator-facing name of a transport, for a message that has to say which
/// server the operator is looking at.
fn transport_label(transport: UpstreamTransport) -> &'static str {
    match transport {
        UpstreamTransport::Default => "gateway",
        UpstreamTransport::AzureOpenAi => "Azure OpenAI",
        UpstreamTransport::AzureOpenAiEntra => "Microsoft Entra ID",
        UpstreamTransport::AwsBedrock => "Amazon Bedrock",
        UpstreamTransport::GoogleVertex => "Google Vertex AI",
    }
}

/// A URL of the shape this transport addresses, shown when one is missing or
/// malformed. Vertex's is the long one on purpose: its base names the project
/// and the location, and an operator who has not seen that will not guess it.
fn transport_url_example(transport: UpstreamTransport) -> &'static str {
    match transport {
        UpstreamTransport::AzureOpenAi | UpstreamTransport::AzureOpenAiEntra => {
            "https://YOUR-RESOURCE.openai.azure.com"
        }
        UpstreamTransport::AwsBedrock => "https://bedrock-runtime.us-east-1.amazonaws.com",
        UpstreamTransport::GoogleVertex => {
            "https://us-central1-aiplatform.googleapis.com/v1/projects/YOUR-PROJECT/locations/us-central1"
        }
        UpstreamTransport::Default => "https://api.example.com",
    }
}

/// The protocols a transport carries, named the way the UI names them.
fn transport_format_error(transport: UpstreamTransport) -> ApiError {
    let spoken = match transport {
        UpstreamTransport::AzureOpenAi | UpstreamTransport::AzureOpenAiEntra => {
            "Chat Completions or Responses"
        }
        UpstreamTransport::AwsBedrock => "Chat Completions or Responses",
        UpstreamTransport::GoogleVertex => "Chat Completions or Gemini",
        UpstreamTransport::Default => "any protocol",
    };
    ApiError::bad_request(format!(
        "A {} server speaks {spoken} — choose one of those protocols.",
        transport_label(transport)
    ))
    .code(ApiErrorCode::TransportInvalid)
}

/// What a minting transport is missing when no credential was supplied.
fn missing_document_error(transport: UpstreamTransport) -> ApiError {
    let doc = match transport {
        UpstreamTransport::GoogleVertex => "its service-account JSON key",
        _ => "its client-credentials document",
    };
    ApiError::bad_request(format!(
        "{} needs {doc} — paste it as the server's credential.",
        transport_label(transport)
    ))
    .code(ApiErrorCode::TransportInvalid)
}

/// Parse a supplied credential the way the proxy will, so a document that cannot
/// mint is refused on the page that set it rather than on a user's request.
fn validate_credential_document(
    transport: UpstreamTransport,
    key: &str,
) -> Result<(), streamscope_core::error::AppError> {
    match transport {
        UpstreamTransport::AzureOpenAiEntra => {
            streamscope_core::proxy::azure_entra::parse_credential(key).map(|_| ())
        }
        UpstreamTransport::GoogleVertex => {
            streamscope_core::proxy::google_sa::parse_credential(key).map(|_| ())
        }
        // A raw key is whatever the provider issued; there is nothing to parse.
        _ => Ok(()),
    }
}

/// Vertex addresses a model from a project/location base, so a base missing
/// either would produce a URL that 404s with nothing on the page to explain it.
fn validate_transport_base_url(
    transport: UpstreamTransport,
    base: &str,
) -> Result<(), ApiError> {
    if transport != UpstreamTransport::GoogleVertex {
        return Ok(());
    }
    let trimmed = base.trim_end_matches('/');
    let names_project_and_location = trimmed.contains("/projects/")
        && trimmed.contains("/locations/")
        && !trimmed.ends_with("/projects")
        && !trimmed.ends_with("/locations");
    if !names_project_and_location {
        return Err(ApiError::bad_request(format!(
            "A Google Vertex AI server is addressed from its project and location, e.g. {}",
            transport_url_example(UpstreamTransport::GoogleVertex)
        ))
        .code(ApiErrorCode::TransportInvalid));
    }
    Ok(())
}

/// The transport a server is stored with.
async fn server_transport(
    conn: &mut Scoped,
    server_id: Uuid,
) -> Result<Option<UpstreamTransport>, ApiError> {
    let row: Option<String> = sqlx::query_scalar("SELECT transport FROM upstream_servers WHERE id = $1")
        .bind(server_id)
        .fetch_optional(conn)
        .await
        .map_err(|e| {
            tracing::error!("read server transport: {e}");
            ApiError::internal("failed to read the server's transport")
        })?;
    Ok(row.map(|t| UpstreamTransport::from_str_relaxed(&t)))
}

/// Render an Entra credential validation failure for an operator.
fn credential_hint(e: &streamscope_core::error::AppError) -> String {
    match e {
        streamscope_core::error::AppError::BadRequest(m) => m.clone(),
        _ => "the credential could not be validated".to_string(),
    }
}

/// Protocol-specific liveness probe path. For chat-completions this is the
/// model-listing endpoint the discovery path also hits: `{base}/models` when a
/// `chat_endpoint_path` override is set (its list is co-located with the
/// overridden chat path), else the canonical `{base}/v1/models`.
fn liveness_probe_path(upstream_api_format: &str, chat_endpoint_path: Option<&str>) -> &'static str {
    match upstream_api_format {
        "google_gemini" => "/v1beta/models",
        // A chat-completions server carrying a `chat_endpoint_path` override lists
        // its models at `{base}/models` (co-located with the overridden chat path,
        // which the base already includes up to), not `{base}/v1/models`.
        _ if chat_endpoint_path.is_some() => "/models",
        _ => "/v1/models",
    }
}

/// Build an HTTPS client carrying the appliance's imported CAs.
///
/// Invariant: the build error MUST propagate. A default client would carry
/// **none** of those roots, so the very next request fails TLS verification and
/// the handler tells an operator to import a CA they have already imported — an
/// unfixable loop. `Client::default()` also panics internally on TLS-init
/// failure.
///
/// Guarded like the gateway's own provider client (the platform's `llm` egress
/// list): a caller vets an IP-literal URL with [`provider_url_refusal`] first.
pub(crate) fn upstream_probe_client() -> Result<reqwest::Client, reqwest::Error> {
    streamscope_core::proxy::client::provider_client_builder(crate::custom_ca::current().as_deref()).build()
}

/// What a provider refused by the egress policy is told, for an address the
/// `llm` list does not list.
pub(crate) const PROVIDER_NOT_LISTED: &str = "This address is internal and the platform's llm egress \
    list does not list it (the cloud metadata endpoint is never reachable) — a platform administrator \
    lists it under Settings → Egress (SYSTEM).";

/// The same, for a redirect from https down to plain http.
pub(crate) const PROVIDER_DOWNGRADED: &str =
    "This server redirected from https down to plain http, which is never followed — give its https address.";

/// A probe's failed send that is the guard's refusal — the address a
/// provider's host name resolved to, or a redirect hop: refused, never
/// "unreachable", which would offer "Save anyway" for a server the gateway
/// will always refuse. Never names the address the name resolved to.
pub(crate) fn egress_refusal(e: &reqwest::Error) -> Option<ApiError> {
    egress_refusal_message(e).map(|m| ApiError::bad_request(m).code(ApiErrorCode::EgressRefused))
}

/// The message of [`egress_refusal`], for a probe reporting in its own shape.
pub(crate) fn egress_refusal_message(e: &reqwest::Error) -> Option<&'static str> {
    use streamscope_mcp_auth::ssrf::Refusal;
    Some(match streamscope_mcp_auth::ssrf::refusal(e)? {
        Refusal::Address => PROVIDER_NOT_LISTED,
        Refusal::Downgrade => PROVIDER_DOWNGRADED,
    })
}

/// The refusal of a provider URL the gateway may not reach (see
/// [`streamscope_core::proxy::client::check_provider_url`]), as the API answers
/// it.
pub(crate) fn provider_url_refusal(url: &str) -> Result<(), ApiError> {
    use streamscope_mcp_auth::ssrf::SsrfError;
    match streamscope_core::proxy::client::check_provider_url(url) {
        Ok(()) => Ok(()),
        Err(SsrfError::InternalAddress) => {
            Err(ApiError::bad_request(PROVIDER_NOT_LISTED).code(ApiErrorCode::EgressRefused))
        }
        Err(_) => Err(ApiError::bad_request("A server URL must be http:// or https:// with a host")
            .code(ApiErrorCode::TransportInvalid)),
    }
}

/// The credential headers a models-list GET must carry when the TRANSPORT names
/// none — i.e. when the header is protocol-decided.
///
/// Invariant: this MUST send what `UpstreamClient::forward` sends a real
/// request of the same protocol. A check authenticated differently from the
/// data plane answers a question nobody asked — and once a refusal fails the
/// save, a wrong header refuses every server of that protocol. Anthropic wants
/// `x-api-key` beside a mandatory `anthropic-version` and does not accept a
/// bearer token.
///
/// Keyed on the FORMAT, like `forward`, and deliberately not on the provider:
/// what this check answers is "would the data plane's credential be accepted",
/// and the data plane picks its header from the upstream's wire. Discovery
/// dispatches on the provider instead, so the two disagree for a server whose
/// provider and format name different wires — a configuration whose real
/// traffic would fail the same way this check now does.
fn protocol_credential_headers(api_key: &str, upstream_api_format: &str) -> Vec<(&'static str, String)> {
    match upstream_api_format {
        "anthropic_messages" => vec![
            ("x-api-key", api_key.to_string()),
            (
                "anthropic-version",
                streamscope_core::proxy::client::ANTHROPIC_API_VERSION.to_string(),
            ),
        ],
        "google_gemini" => vec![("x-goog-api-key", api_key.to_string())],
        _ => vec![("Authorization", format!("Bearer {api_key}"))],
    }
}

/// What one probe response says about a server write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeVerdict {
    /// The address is right and nothing objected.
    Reachable,
    /// The address is right and the upstream refused the credential presented.
    CredentialRejected,
    /// Nothing at this address answers the way this server is configured.
    Unreachable,
}

/// Read a probe status, given whether the write actually presented a
/// credential.
///
/// A 401/403 is the whole reason this is a decision rather than a comparison.
/// With NO credential presented it is the best possible answer: the host and
/// path are right and the endpoint merely wants authentication, which is what
/// a keyless upstream or a credential-keeping update looks like. With one
/// presented it is the provider saying that key is not accepted — and reading
/// that as "reachable" is how a server is created against a credential nothing
/// will ever accept, with the first sign of it a model sync that fails later
/// and elsewhere.
fn probe_verdict(status: u16, credential_presented: bool) -> ProbeVerdict {
    match status {
        200..=299 => ProbeVerdict::Reachable,
        401 | 403 if credential_presented => ProbeVerdict::CredentialRejected,
        401 | 403 => ProbeVerdict::Reachable,
        _ => ProbeVerdict::Unreachable,
    }
}

/// A token exchange that did not produce a token.
///
/// `UpstreamCredentialRejected` only when the identity platform answered and
/// refused the credential; every other failure — the platform not reached, a
/// server-side error, an unreadable answer — is `UpstreamUnreachable`, which
/// makes no claim about the key. Either way the operator may save regardless.
fn mint_failed(transport: UpstreamTransport, e: &streamscope_core::proxy::minted_token::MintFailure) -> ApiError {
    if e.is_declined() {
        return ApiError::bad_request(format!(
            "{} refused this credential: {}. Check it, or use “Save anyway” to store it regardless.",
            transport_label(transport),
            credential_hint(e.error())
        ))
        .code(super::ApiErrorCode::UpstreamCredentialRejected);
    }
    ApiError::bad_request(format!(
        "{} did not issue a token for this credential: {}. The identity platform could not be \
         reached or did not answer usably. Use “Save anyway” to store it regardless.",
        transport_label(transport),
        credential_hint(e.error())
    ))
    .code(super::ApiErrorCode::UpstreamUnreachable)
}

/// Exchange the stored credential for a token, and report the outcome as this
/// server's reachability check. Used where there is no endpoint to GET.
async fn probe_minted_credential(
    base_url: &str,
    api_key: Option<&str>,
    transport: UpstreamTransport,
) -> Result<(), ApiError> {
    let Some(key) = api_key.filter(|k| !k.is_empty()) else {
        // No credential reached this check — a keyless server, or a stored one
        // that would not decrypt. There is nothing to exchange, so there is
        // nothing to report. Every other write carries one: a create is
        // refused without it by `resolve_transport`, and an update presents
        // the credential it will forward with, rotated or carried.
        return Ok(());
    };
    let endpoint =
        streamscope_core::proxy::client::UpstreamEndpoint { url: base_url, api_key: key, transport };
    endpoint.stored_credential_header_classified().await.map(|_| ()).map_err(|e| mint_failed(transport, &e))
}

/// Probe the upstream server at its protocol's models endpoint.
///
/// 404 and network errors fail as unreachable; a 401/403 depends on whether a
/// credential was presented — see [`probe_verdict`]. Both failures carry a code
/// the UI offers a "Save anyway" bypass for.
pub(super) async fn probe_upstream_liveness(
    base_url: &str,
    upstream_api_format: &str,
    api_key: Option<&str>,
    chat_endpoint_path: Option<&str>,
    transport: UpstreamTransport,
) -> Result<(), ApiError> {
    // A transport that publishes no model list has no endpoint this probe could
    // reach. When it mints a token, the exchange itself is the check worth
    // making — and the only one that can tell a well-formed credential the
    // provider rejects from one it accepts, which is otherwise invisible until a
    // user's request fails.
    if !transport.publishes_model_list() {
        if transport.mints_token() {
            return probe_minted_credential(base_url, api_key, transport).await;
        }
        return Ok(());
    }

    let path = liveness_probe_path(upstream_api_format, chat_endpoint_path);
    // The transport owns the URL shape, so the probe hits exactly the endpoint a
    // real request would — a probe on the wrong prefix would 404 a correctly
    // configured server.
    let probe_url = if transport.owns_url() {
        transport.upstream_url(base_url, path)
    } else {
        format!("{}{path}", base_url.trim_end_matches('/'))
    };

    provider_url_refusal(&probe_url)?;
    let client = upstream_probe_client().map_err(|e| {
        tracing::error!("build upstream liveness probe client: {e}");
        // Carries `upstream_unreachable` so the UI still offers "Save anyway" —
        // this failure is the gateway's, and must not block saving the server.
        ApiError::bad_request(
            "The gateway could not build an HTTPS client for this check — retry, \
             or use “Save anyway” to skip it.",
        )
        .code(super::ApiErrorCode::UpstreamUnreachable)
    })?;
    let mut req = client
        .get(&probe_url)
        .timeout(streamscope_core::settings::core_settings().upstream_probe_timeout);
    if let Some(k) = api_key.filter(|k| !k.is_empty()) {
        // Authenticated exactly the way the proxy authenticates a real request.
        // Load-bearing, because a refusal means "this credential is wrong": a
        // check sending the wrong header refuses every server of that
        // protocol. For Entra the probe MINTS a token; that round-trip is the
        // most valuable thing this check can report on such a server, and a bad
        // client-credentials document is otherwise invisible until traffic runs.
        let endpoint = streamscope_core::proxy::client::UpstreamEndpoint {
            url: base_url,
            api_key: k,
            transport,
        };
        req = match endpoint.stored_credential_header_classified().await {
            Ok(Some((name, value))) => req.header(name, value),
            Ok(None) => {
                for (name, value) in protocol_credential_headers(k, upstream_api_format) {
                    req = req.header(name, value);
                }
                req
            }
            Err(e) => return Err(mint_failed(transport, &e)),
        };
    }

    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            if let Some(refused) = egress_refusal(&e) {
                return Err(refused);
            }
            let chain = error_source_chain(&e);
            tracing::error!(
                probe_url = %probe_url,
                err_debug = ?e,
                cause = %chain,
                "upstream liveness probe failed"
            );
            let message = if is_tls_trust_error(&chain) {
                format!(
                    "TLS certificate for {probe_url} is not trusted — its CA is not in the appliance trust store. \
                     Import the CA under Settings → Trusted CAs (super-admin), or use “Save anyway” to skip this check."
                )
            } else {
                format!("Liveness probe to {probe_url} failed: {e}")
            };
            return Err(ApiError::bad_request(message).code(super::ApiErrorCode::UpstreamUnreachable));
        }
    };

    let status = resp.status();
    let verdict = probe_verdict(
        status.as_u16(),
        api_key.is_some_and(|k| !k.is_empty()),
    );
    if verdict == ProbeVerdict::Reachable {
        return Ok(());
    }

    let body = read_capped_lossy(resp, PROBE_ERROR_BODY_CAP).await;
    if verdict == ProbeVerdict::CredentialRejected {
        let snippet = summarize_probe_body(&body);
        return Err(ApiError::bad_request(format!(
            "{probe_url} refused this credential ({status}){}{snippet}. \
             Check the key, or use “Save anyway” to store it regardless — a \
             provider may refuse the model list to a key that works for chat.",
            if snippet.is_empty() { "" } else { ": " }
        ))
        .code(super::ApiErrorCode::UpstreamCredentialRejected));
    }
    let hint = if status.as_u16() == 404
        && transport == UpstreamTransport::Default
        && base_url.trim_end_matches('/').ends_with("/v1")
    {
        // Only the default transport concatenates the base verbatim; the Azure
        // transports normalise a pasted `/openai/v1`, so this hint would be
        // wrong advice there.
        " — the URL already ends with /v1, remove it from the base URL"
    } else if status.as_u16() == 404 {
        " — check the base URL and provider/upstream_api_format match"
    } else {
        ""
    };
    let snippet = summarize_probe_body(&body);
    Err(ApiError::bad_request(format!(
        "Liveness probe to {probe_url} failed: {status}{hint}{}{snippet}",
        if snippet.is_empty() { "" } else { " — " }
    ))
    .code(super::ApiErrorCode::UpstreamUnreachable))
}

/// Produce a short, UI-friendly snippet from an upstream probe body. HTML
/// pages (Next.js error pages, Cloudflare blocks, etc.) are dropped entirely
/// — they are multi-kilobyte and useless to surface in a toast. Plain text
/// / JSON is trimmed and truncated to ~160 chars.
pub(crate) fn summarize_probe_body(body: &str) -> String {
    let trimmed = body.trim();
    if trimmed.is_empty() || trimmed.starts_with('<') {
        return String::new();
    }
    // The summary is stored (a sync status, an audit row's error), and
    // Postgres stores no U+0000.
    let mut one_line: String = trimmed
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    streamscope_core::pg_text::scrub_nul_str(&mut one_line);
    const MAX: usize = 160;
    if one_line.len() <= MAX {
        one_line
    } else {
        let cut = one_line.floor_char_boundary(MAX);
        format!("{}…", &one_line[..cut])
    }
}

/// Turn a non-2xx model-discovery response into an API error.
///
/// Invariant: the upstream body is SUMMARISED, never echoed whole.
/// A server's endpoint URLs are tenant-admin writable and LLM egress is
/// deliberately unguarded (internal LLM upstreams are a legitimate deployment),
/// so echoing the full body would make model discovery a read primitive for
/// whatever that URL reaches. The summary drops HTML outright and caps the rest,
/// which still carries the diagnosis — "provider returned 401: invalid api key".
fn upstream_status_error(status: u16, body: &str) -> ApiError {
    let snippet = summarize_probe_body(body);
    if snippet.is_empty() {
        ApiError::bad_gateway(format!("provider returned {status}"))
    } else {
        ApiError::bad_gateway(format!("provider returned {status}: {snippet}"))
    }
}

/// Whether a flattened error chain points at an untrusted-certificate failure
/// (rustls surfaces `invalid peer certificate: UnknownIssuer`, self-signed, or
/// `certificate`-shaped messages). Drives the actionable "import a custom CA"
/// hint instead of the opaque reqwest `Display`. Match on lowercased text — the
/// concrete error types live below reqwest's public surface.
pub(crate) fn is_tls_trust_error(chain: &str) -> bool {
    let c = chain.to_ascii_lowercase();
    c.contains("unknownissuer")
        || c.contains("invalid peer certificate")
        || c.contains("self-signed")
        || c.contains("self signed")
        || c.contains("certificate")
}

/// Flatten an error and its full `source()` chain into one line. The probe and
/// discovery paths only surface the top-level `Display` to the API caller, so
/// without this the underlying cause (TLS handshake, connect, DNS, …) never
/// reaches the operator log.
pub(crate) fn error_source_chain(err: &dyn std::error::Error) -> String {
    let mut out = err.to_string();
    let mut src = err.source();
    while let Some(s) = src {
        out.push_str(" <- ");
        out.push_str(&s.to_string());
        src = s.source();
    }
    out
}

/// Discover the models an upstream server exposes, parsing whatever capability
/// and pricing metadata the provider publishes. A provider that publishes prices
/// yields real caps/pricing; everyone else falls back to the generic OpenAI-style
/// id+context parser. Metadata left `None` resolves to the standard default
/// downstream.
///
/// Two different things are dispatched on, from the one `provider` key:
/// **transport** (auth header, pagination, URL shape) goes through the routing
/// [`Provider`] enum, while the **response body shape** is a property of the
/// vendor. The enum deliberately folds every OpenAI-compatible vendor it has no
/// transport quirk for into `Custom`, so several vendors that DO publish their
/// own metadata share one variant — hence the second, key-level match. Adding a
/// parser for such a vendor needs no new `Provider` variant.
pub(crate) async fn call_discover_models(
    provider: &str,
    base_url: &str,
    api_key: Option<&str>,
    chat_endpoint_path: Option<&str>,
    transport: UpstreamTransport,
) -> Result<Vec<DiscoveredModel>, ApiError> {
    let brand = Provider::from_str_relaxed(provider);
    // Ollama's native list carries what its OpenAI-compatible one omits; the
    // compatible one stays the answer for a server that has no native API.
    if matches!(brand, Provider::Ollama)
        && !transport.owns_url()
        && let Some(models) = discover_ollama_native(base_url, api_key).await?
    {
        return Ok(models);
    }
    let body = fetch_models_json(&brand, base_url, api_key, chat_endpoint_path, transport).await?;
    let models = match brand {
        Provider::OpenRouter => parse_openrouter_models(&body),
        Provider::GoogleGemini => parse_gemini_models(&body),
        _ => match provider.trim().to_ascii_lowercase().as_str() {
            "novita" => parse_novita_models(&body),
            "chutes" => parse_chutes_models(&body),
            "deepinfra" => parse_deepinfra_models(&body),
            _ => parse_generic_models(&body),
        },
    };
    Ok(models)
}

/// GET the provider's model-list endpoint and return the parsed JSON body.
/// Most providers expose the OpenAI-shaped `/v1/models` in a single response;
/// Google Gemini lists at `/v1beta/models` with `x-goog-api-key` auth (the same
/// path + header the proxy uses for gemini traffic) and is paginated, so it goes
/// through the dedicated `fetch_gemini_models` which follows every page.
async fn fetch_models_json(
    provider: &Provider,
    base_url: &str,
    api_key: Option<&str>,
    chat_endpoint_path: Option<&str>,
    transport: UpstreamTransport,
) -> Result<serde_json::Value, ApiError> {
    let base = base_url.trim_end_matches('/');
    provider_url_refusal(base)?;
    let client = upstream_probe_client().map_err(|e| {
        tracing::error!("build model-discovery client: {e}");
        ApiError::bad_gateway("The gateway could not build an HTTPS client for model discovery.")
    })?;
    if !transport.publishes_model_list() {
        return Err(ApiError::bad_request(format!(
            "A {} server publishes no model list the gateway can read — add the models \
             you want to use.",
            transport_label(transport)
        ))
        .code(super::ApiErrorCode::UpstreamUnreachable));
    }
    // The Gemini Developer API's own list grammar. A transport that owns its URL
    // serves a different one, so it must not be addressed this way.
    if matches!(provider, Provider::GoogleGemini) && !transport.owns_url() {
        return fetch_gemini_models(&client, base, api_key).await;
    }
    // Anthropic's list is OpenAI-SHAPED but neither OpenAI-authenticated nor
    // unpaginated, so it needs its own fetch for the same reason Gemini does.
    // A transport that owns its URL (Bedrock/Vertex) serves a different list and
    // must not be addressed this way.
    if matches!(provider, Provider::Anthropic) && !transport.owns_url() {
        return fetch_anthropic_models(&client, base, api_key).await;
    }

    // A `chat_endpoint_path` override means the OpenAI-compat models list is at
    // `{base}/models` (co-located with the overridden chat path); otherwise the
    // canonical `{base}/v1/models` (or `{base}/models` when the base already ends `/v1`).
    // A non-default transport owns the URL outright — Azure lists at
    // `{endpoint}/openai/v1/models`, in the plain OpenAI `ListModelsResponse`
    // shape the generic parser already reads.
    let models_url = if transport.owns_url() {
        transport.upstream_url(base_url, "/v1/models")
    } else if chat_endpoint_path.is_some() || base.ends_with("/v1") {
        format!("{base}/models")
    } else {
        format!("{base}/v1/models")
    };
    let mut req = client
        .get(&models_url)
        .timeout(streamscope_core::settings::core_settings().upstream_probe_timeout);
    if let Some(k) = api_key.filter(|k| !k.is_empty()) {
        let endpoint = streamscope_core::proxy::client::UpstreamEndpoint {
            url: base_url,
            api_key: k,
            transport,
        };
        req = match endpoint.stored_credential_header().await {
            Ok(Some((name, value))) => req.header(name, value),
            // Anthropic reaches this arm only on a transport that owns its URL
            // (Bedrock/Vertex), which serves a different list under a different
            // credential entirely — its own `fetch_anthropic_models` handles the
            // direct API, headers and pagination included.
            Ok(None) => req.header("Authorization", format!("Bearer {k}")),
            Err(e) => {
                return Err(ApiError::bad_gateway(format!(
                    "{} did not issue a token for this server's credential: {}",
                    transport_label(transport),
                    credential_hint(&e)
                )));
            }
        };
    }
    let resp = req
        .send()
        .await
        .map_err(|e| {
            if let Some(refused) = egress_refusal(&e) {
                return refused;
            }
            let chain = error_source_chain(&e);
            tracing::error!(
                models_url = %models_url,
                err_debug = ?e,
                cause = %chain,
                "upstream model discovery request failed"
            );
            if is_tls_trust_error(&chain) {
                ApiError::bad_gateway(format!(
                    "TLS certificate for {models_url} is not trusted — import its CA under Settings → Trusted CAs (super-admin)."
                ))
            } else {
                ApiError::bad_gateway(format!("failed to reach provider: {e}"))
            }
        })?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = read_capped_lossy(resp, PROBE_ERROR_BODY_CAP).await;
        return Err(upstream_status_error(status, &body));
    }

    read_capped_json(resp).await
}

/// How a paginated model list says whether there is more to read.
#[derive(Debug, Clone, PartialEq, Eq)]
enum NextPage {
    /// The listing ended here.
    Done,
    /// Ask for this cursor next.
    Cursor(String),
    /// The upstream says there is more and gave nothing that would reach it —
    /// no cursor, a cursor that does not advance, or a walk that ran past its
    /// page ceiling.
    Stranded,
}

/// Refuse a list the walk could not finish reading.
///
/// A partial list is not a smaller answer, it is a WRONG one: reconciliation
/// reads every model it did not see as retired upstream and disables the live
/// routes pointing at them. Returning what was read is the one outcome that
/// looks like success, so an unfinished walk fails the sync instead — leaving
/// the models already configured exactly where they are.
fn partial_list_error(provider: &str) -> ApiError {
    ApiError::bad_gateway(format!(
        "{provider} reported more models than this read could reach — refusing a partial list, \
         because reconciling one would retire the models it did not see."
    ))
}

/// Fetch Google Gemini's `/v1beta/models` list, following `nextPageToken` across
/// every page into one merged `{ "models": [...] }` body. Gemini's ListModels is
/// paginated (default 50 / page); a truncated list would later be reconciled as
/// "these models vanished upstream" and disable live routes, so completeness here
/// is load-bearing, not cosmetic. `pageSize=1000` (Gemini's max) keeps it to a
/// single page for any realistic provider; the page loop is bounded as a runaway
/// guard.
async fn fetch_gemini_models(
    client: &reqwest::Client,
    base: &str,
    api_key: Option<&str>,
) -> Result<serde_json::Value, ApiError> {
    let list_url = if base.ends_with("/v1beta") {
        format!("{base}/models")
    } else {
        format!("{base}/v1beta/models")
    };
    let key = api_key.filter(|k| !k.is_empty());

    let mut all: Vec<serde_json::Value> = Vec::new();
    let mut page_token: Option<String> = None;
    // 1000/page × 50 pages = 50k models — a ceiling no real provider reaches.
    for _ in 0..50 {
        let mut query: Vec<(&str, &str)> = vec![("pageSize", "1000")];
        if let Some(t) = &page_token {
            query.push(("pageToken", t));
        }
        let url = reqwest::Url::parse_with_params(&list_url, &query)
            .map_err(|e| ApiError::bad_gateway(format!("invalid discovery URL: {e}")))?;
        let mut req = client
            .get(url)
            .timeout(streamscope_core::settings::core_settings().upstream_probe_timeout);
        if let Some(k) = key {
            req = req.header("x-goog-api-key", k);
        }
        let resp = req.send().await.map_err(|e| {
            if let Some(refused) = egress_refusal(&e) {
                return refused;
            }
            let chain = error_source_chain(&e);
            tracing::error!(
                models_url = %list_url,
                err_debug = ?e,
                cause = %chain,
                "gemini model discovery request failed"
            );
            if is_tls_trust_error(&chain) {
                ApiError::bad_gateway(format!(
                    "TLS certificate for {list_url} is not trusted — import its CA under Settings → Trusted CAs (super-admin)."
                ))
            } else {
                ApiError::bad_gateway(format!("failed to reach provider: {e}"))
            }
        })?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = read_capped_lossy(resp, PROBE_ERROR_BODY_CAP).await;
            return Err(upstream_status_error(status, &body));
        }

        let body: serde_json::Value = read_capped_json(resp).await?;
        if let Some(arr) = body.get("models").and_then(|m| m.as_array()) {
            all.extend(arr.iter().cloned());
        }
        match gemini_next_page(&body, page_token.as_deref()) {
            NextPage::Cursor(t) => page_token = Some(t),
            NextPage::Done => return Ok(serde_json::json!({ "models": all })),
            NextPage::Stranded => return Err(partial_list_error("Gemini")),
        }
    }

    // Fell out of the page ceiling with the listing still unfinished.
    Err(partial_list_error("Gemini"))
}

/// Gemini names the next page with `nextPageToken`; its ABSENCE is how the
/// listing ends, so there is no separate "more?" flag to read.
///
/// A token identical to the one just used is the same hazard Anthropic's
/// repeated `last_id` is — the walk would merge one page over and over — and
/// like a stranded Anthropic walk it must fail the sync rather than hand back
/// a short list the plausibility gate will let through.
fn gemini_next_page(body: &serde_json::Value, current: Option<&str>) -> NextPage {
    match body.get("nextPageToken").and_then(|t| t.as_str()) {
        None | Some("") => NextPage::Done,
        Some(t) if Some(t) == current => NextPage::Stranded,
        Some(t) => NextPage::Cursor(t.to_string()),
    }
}

/// Fetch Anthropic's `/v1/models`, following `has_more`/`last_id` across every
/// page into one merged `{ "data": [...] }` body.
///
/// Anthropic's list defaults to **20 items per page** (max 1000). A single
/// unpaged GET therefore returns a truncated catalog the moment an account can
/// see more than twenty models — and a truncated list is not a cosmetic loss:
/// reconciliation reads the models it did not see as "these vanished upstream"
/// and disables their live routes. Completeness here is load-bearing, exactly as
/// it is for Gemini's paginated list.
///
/// Anthropic names its own auth: the API key rides `x-api-key` (a bearer is
/// refused — that spelling is reserved for OAuth there) and every request must
/// carry `anthropic-version`.
async fn fetch_anthropic_models(
    client: &reqwest::Client,
    base: &str,
    api_key: Option<&str>,
) -> Result<serde_json::Value, ApiError> {
    let list_url = if base.ends_with("/v1") {
        format!("{base}/models")
    } else {
        format!("{base}/v1/models")
    };
    let key = api_key.filter(|k| !k.is_empty());

    let mut all: Vec<serde_json::Value> = Vec::new();
    let mut after_id: Option<String> = None;
    // 1000/page × 50 pages — a ceiling no real account reaches.
    for _ in 0..50 {
        let mut query: Vec<(&str, &str)> = vec![("limit", "1000")];
        if let Some(a) = &after_id {
            query.push(("after_id", a));
        }
        let url = reqwest::Url::parse_with_params(&list_url, &query)
            .map_err(|e| ApiError::bad_gateway(format!("invalid discovery URL: {e}")))?;
        let mut req = client
            .get(url)
            .timeout(streamscope_core::settings::core_settings().upstream_probe_timeout);
        if let Some(k) = key {
            req = req
                .header("x-api-key", k)
                .header(
                    "anthropic-version",
                    streamscope_core::proxy::client::ANTHROPIC_API_VERSION,
                );
        }
        let resp = req.send().await.map_err(|e| {
            if let Some(refused) = egress_refusal(&e) {
                return refused;
            }
            let chain = error_source_chain(&e);
            tracing::error!(
                models_url = %list_url,
                err_debug = ?e,
                cause = %chain,
                "anthropic model discovery request failed"
            );
            if is_tls_trust_error(&chain) {
                ApiError::bad_gateway(format!(
                    "TLS certificate for {list_url} is not trusted — import its CA under Settings → Trusted CAs (super-admin)."
                ))
            } else {
                ApiError::bad_gateway(format!("failed to reach provider: {e}"))
            }
        })?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = read_capped_lossy(resp, PROBE_ERROR_BODY_CAP).await;
            return Err(upstream_status_error(status, &body));
        }

        let body: serde_json::Value = read_capped_json(resp).await?;
        if let Some(arr) = body.get("data").and_then(|d| d.as_array()) {
            all.extend(arr.iter().cloned());
        }
        match anthropic_next_cursor(&body, after_id.as_deref()) {
            NextPage::Cursor(cursor) => after_id = Some(cursor),
            NextPage::Done => return Ok(serde_json::json!({ "data": all })),
            NextPage::Stranded => return Err(partial_list_error("Anthropic")),
        }
    }

    // Fell out of the page ceiling with the listing still unfinished.
    Err(partial_list_error("Anthropic"))
}

/// Whether Anthropic's listing continues past this page, and with what.
///
/// `has_more` is the only thing that ends it: `last_id` rides EVERY page, the
/// final one included, so reading the cursor alone would never stop.
///
/// Two shapes claim another page while naming nothing that reaches it — no
/// usable `last_id`, or one identical to the cursor that produced this page —
/// and both are `Stranded` rather than `Done`. Continuing on either re-reads
/// the page just read until the ceiling stops it, fifty merged copies later.
///
/// **Stranded is an ERROR, never a short list**, because a short list is the
/// outcome that looks like success. The plausibility gate does not catch one:
/// it refuses a discovery below `max(1, existing / 2)`, so a server with three
/// models whose walk stops after two passes it and the third model is
/// RETIRED — its live routes disabled. Small catalogs are exactly where
/// Anthropic sits.
fn anthropic_next_cursor(body: &serde_json::Value, current: Option<&str>) -> NextPage {
    if body.get("has_more").and_then(|h| h.as_bool()) != Some(true) {
        return NextPage::Done;
    }
    match body.get("last_id").and_then(|l| l.as_str()) {
        Some(last) if !last.is_empty() && Some(last) != current => {
            NextPage::Cursor(last.to_string())
        }
        // More pages claimed, and nothing that would reach them.
        _ => NextPage::Stranded,
    }
}

/// Ollama's OpenAI-compatible `/v1/models` names the models and nothing else.
/// Its native API publishes the rest (Ollama source, `api/types.go`):
/// - `GET /api/tags` — every installed model with its `capabilities`, which
///   Ollama derives from the model itself (`completion`, `tools`, `insert`,
///   `vision`, `embedding`, `thinking`, `image`, `audio`);
/// - `GET /api/ps` — each LOADED model's `context_length`: the window Ollama
///   actually serves it with (`num_ctx`).
///
/// The trained length (`/api/tags` `details.context_length`, `/api/show`
/// `model_info`) is never read. Ollama serves `num_ctx`, which defaults by VRAM
/// tier (4k / 32k / 256k) or `OLLAMA_CONTEXT_LENGTH`, so the trained length
/// overstates the window — a model that is not loaded right now states none,
/// and the window it had when last seen loaded is kept by the sync.
///
/// `Ok(None)` unless `/api/tags` answers with Ollama's own list — a 404, an
/// auth or proxy refusal, no answer at all, or a 2xx that is not the list: the
/// key says `ollama` but only the OpenAI-compatible surface is reachable, and
/// the generic path reads (or reports on) that. `/api/ps` is advisory — a
/// server that answers tags but not ps still has its capabilities, just no
/// served windows.
async fn discover_ollama_native(
    base_url: &str,
    api_key: Option<&str>,
) -> Result<Option<Vec<DiscoveredModel>>, ApiError> {
    let base = base_url.trim_end_matches('/');
    let root = base.strip_suffix("/v1").unwrap_or(base);
    provider_url_refusal(root)?;
    let client = upstream_probe_client().map_err(|e| {
        tracing::error!("build model-discovery client: {e}");
        ApiError::bad_gateway("The gateway could not build an HTTPS client for model discovery.")
    })?;
    let get = |path: &str| {
        let mut req = client
            .get(format!("{root}{path}"))
            .timeout(streamscope_core::settings::core_settings().upstream_probe_timeout);
        if let Some(k) = api_key.filter(|k| !k.is_empty()) {
            req = req.bearer_auth(k);
        }
        req
    };

    let tags = match get("/api/tags").send().await {
        Ok(resp) if resp.status().is_success() => resp,
        Ok(resp) => {
            tracing::debug!(status = resp.status().as_u16(), %root, "no native Ollama list; reading the compatible one");
            return Ok(None);
        }
        Err(e) => {
            tracing::debug!(error = %e, %root, "native Ollama list unreachable; reading the compatible one");
            return Ok(None);
        }
    };
    let Ok(tags) = read_capped_json(tags).await else {
        return Ok(None);
    };
    if !tags.get("models").is_some_and(serde_json::Value::is_array) {
        return Ok(None);
    }

    let running = match get("/api/ps").send().await {
        Ok(resp) if resp.status().is_success() => read_capped_json(resp).await.ok(),
        _ => None,
    };
    Ok(Some(parse_ollama_models(&tags, running.as_ref())))
}

/// Parse Ollama's native `/api/tags` list, joined with `/api/ps` for the served
/// window of each loaded model. Ollama computes the `capabilities` list from the
/// model, so a non-empty list is complete and a missing `vision` is a real "no
/// vision". `image` (image generation), `embedding` and `insert` (fill-in-the-
/// middle) describe other surfaces and claim nothing about a chat model.
fn parse_ollama_models(
    tags: &serde_json::Value,
    running: Option<&serde_json::Value>,
) -> Vec<DiscoveredModel> {
    let served: std::collections::HashMap<&str, i64> = running
        .and_then(|r| r.get("models"))
        .and_then(|m| m.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|m| {
                    Some((m.get("name")?.as_str()?, m.get("context_length")?.as_i64()?))
                })
                .collect()
        })
        .unwrap_or_default();
    tags.get("models")
        .and_then(|m| m.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|m| {
                    let name = m.get("name")?.as_str()?;
                    let caps = json_str_list(m, "capabilities");
                    Some(DiscoveredModel {
                        id: name.to_string(),
                        context_window: served.get(name).copied(),
                        supports_vision: flag_from_list(&caps, &["vision"]),
                        supports_function_calling: flag_from_list(&caps, &["tools"]),
                        supports_reasoning: flag_from_list(&caps, &["thinking"]),
                        supports_audio_input: flag_from_list(&caps, &["audio"]),
                        ..Default::default()
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The context-window spellings an OpenAI-shaped model list is known to use, in
/// precedence order. The OpenAI `Model` schema carries NO context field, so each
/// compatible server invented one; a name enters this list only with a server to
/// point at, because a guessed spelling silently imports a number that means
/// something else.
///
/// `context_window` (ours) · `context_length` (OpenRouter and the llama-family
/// compat shims) · `max_model_len` (vLLM `ModelCard`) · `max_input_tokens`
/// (Anthropic's models list) · `max_context_length` (Mistral `BaseModelCard`,
/// the whole window). `meta.n_ctx` (llama.cpp) is tried after all of them — it
/// is the *served* window, so a top-level declaration outranks it.
const CONTEXT_WINDOW_KEYS: [&str; 5] = [
    "context_window",
    "context_length",
    "max_model_len",
    "max_input_tokens",
    "max_context_length",
];

/// The context window an OpenAI-shaped model entry declares, under whichever
/// name its server uses. Each candidate is read through to a NUMBER before the
/// next is tried: an explicit `null` under one key is a present key, so chaining
/// on `.get()` alone would stop at it and report no window.
fn entry_context_window(m: &serde_json::Value) -> Option<i64> {
    CONTEXT_WINDOW_KEYS
        .into_iter()
        .find_map(|k| m.get(k).and_then(|v| v.as_i64()))
        .or_else(|| m.get("meta").and_then(|meta| meta.get("n_ctx")).and_then(|v| v.as_i64()))
}

/// The output cap an entry declares. `max_tokens` means the output ceiling on
/// Anthropic's list but has meant the CONTEXT length on older OpenAI-compat
/// shims, so it is read ONLY beside `max_input_tokens` — the field that
/// identifies the Anthropic shape and leaves `max_tokens` unambiguous. Reading
/// it unconditionally would import a context-sized number as the output cap,
/// which no test of ours would notice.
fn entry_max_output_tokens(m: &serde_json::Value) -> Option<i64> {
    m.get("max_output_tokens")
        .and_then(|v| v.as_i64())
        .or_else(|| {
            m.get("max_input_tokens")
                .is_some()
                .then(|| m.get("max_tokens").and_then(|v| v.as_i64()))
                .flatten()
        })
}

/// Fold every capability grammar an OpenAI-shaped list entry can carry onto the
/// discovered model. Each grammar is recognised by its own STRUCTURE, never by
/// the provider key: the servers that publish them sit behind whichever key the
/// operator picked (`custom`, `vllm`, `ollama`, …) — llama-swap in front of
/// llama.cpp speaks OpenRouter's `architecture` grammar plus its own capability
/// map under any of them — so gating a reader on the key is what left such a
/// server's models discovered with a window and no capabilities.
///
/// One rule for every reader, the same as the vendor parsers: **only claim what
/// the server published**. `None` means "not advertised" and inherits the
/// catalog/standard default; `false` is written only where the grammar makes an
/// absence mean "unsupported". The first grammar to claim a flag wins, so a
/// later one never overwrites a published answer with a derived one.
fn apply_published_capabilities(m: &serde_json::Value, model: &mut DiscoveredModel) {
    apply_capability_map(m, model);
    apply_architecture_modalities(m, model);
    apply_listed_parameters(m, model);
}

/// Set `slot` from `claim` unless an earlier grammar already answered it.
fn fill(slot: &mut Option<bool>, claim: Option<bool>) {
    if slot.is_none() {
        *slot = claim;
    }
}

/// The `capabilities` object, in either of the two leaf grammars that exist
/// (a leaf in neither is skipped, never guessed at):
///
/// - **Anthropic** (`GET /v1/models`, `ModelCapabilities`): every leaf is a
///   `CapabilitySupport` — `{ "supported": bool }` — and every known key is
///   always present, so a published `false` is a real claim.
/// - **A flat map of bare booleans**, in two readings. llama-swap
///   (`internal/server/api.go` `modelRecord`) emits it TRUE-only — a
///   capability the model lacks is simply absent — so there a bare leaf only
///   ever claims support. Mistral (`GET /v1/models`, `ModelCapabilities`)
///   emits `true` and `false` alike and always carries `completion_chat`, the
///   leaf that marks its map: there a published `false` is a claim too. An
///   ABSENT key is never read as `false` in either (Mistral's schema defaults
///   every key to false, but a key added after the server's release would then
///   deny a capability nobody denied).
///
/// The Anthropic omissions are deliberate and each is a mapping that looks
/// available and is wrong:
/// - **caching** — `context_management` is server-side context editing
///   (clear-thinking / clear-tool-uses / compact), NOT prompt caching. They are
///   different products; reading one as the other would advertise cache support
///   off a feature that has nothing to do with it.
/// - **function_calling / system_messages** — not in Anthropic's tree at all.
///   Both default to `true` for a text LLM, so inheriting is already correct and
///   claiming it from silence would only make the claim unfalsifiable.
/// - **audio / video input, audio output** — not in the tree. Absent is not
///   "unsupported": the catalog cross-reference fills these.
///
/// Mistral's audio keys name three products: `audio` (audio input to chat),
/// `audio_transcription` (a transcription model — audio in) and
/// `audio_speech` (text-to-speech — audio out). Audio input is claimed when
/// either input key says so, and denied only when every one published denies
/// it.
fn apply_capability_map(m: &serde_json::Value, model: &mut DiscoveredModel) {
    let Some(caps) = m.get("capabilities").and_then(|c| c.as_object()) else {
        return;
    };
    let supported = |key: &str| -> Option<bool> {
        caps.get(key)
            .and_then(|node| node.get("supported"))
            .and_then(|v| v.as_bool())
    };
    // Mistral's map is recognised by its own leaf `completion_chat`, which no
    // TRUE-only map carries; only there is a bare `false` a claim.
    let full_map = caps.get("completion_chat").is_some_and(serde_json::Value::is_boolean);
    let flat = |key: &str| -> Option<bool> {
        caps.get(key).and_then(|v| v.as_bool()).filter(|on| *on || full_map)
    };
    let flat_any = |keys: &[&str]| -> Option<bool> {
        keys.iter().filter_map(|k| flat(k)).reduce(|a, b| a || b)
    };
    fill(&mut model.supports_vision, supported("image_input").or_else(|| flat("vision")));
    fill(&mut model.supports_pdf_input, supported("pdf_input"));
    fill(&mut model.supports_response_schema, supported("structured_outputs"));
    fill(&mut model.supports_reasoning, supported("thinking").or_else(|| flat("reasoning")));
    fill(&mut model.supports_function_calling, flat("function_calling"));
    fill(&mut model.supports_audio_input, flat_any(&["audio", "audio_transcription"]));
    fill(&mut model.supports_audio_output, flat("audio_speech"));
}

/// `architecture.input_modalities` / `output_modalities` — OpenRouter's grammar,
/// also emitted by llama-swap and by llama.cpp's router mode. A NON-EMPTY list
/// states every modality the model takes, so a missing `image` is a real "no
/// vision"; an absent or empty list claims nothing.
fn apply_architecture_modalities(m: &serde_json::Value, model: &mut DiscoveredModel) {
    let Some(arch) = m.get("architecture") else {
        return;
    };
    let input = json_str_list(arch, "input_modalities");
    let output = json_str_list(arch, "output_modalities");
    fill(&mut model.supports_vision, flag_from_list(&input, &["image"]));
    fill(&mut model.supports_pdf_input, flag_from_list(&input, &["file", "pdf"]));
    fill(&mut model.supports_audio_input, flag_from_list(&input, &["audio"]));
    fill(&mut model.supports_video_input, flag_from_list(&input, &["video"]));
    fill(&mut model.supports_audio_output, flag_from_list(&output, &["audio"]));
}

/// `supported_parameters`, read POSITIVELY only. OpenRouter documents its list
/// as a full enumeration (its own parser reads a gap as `false`), but llama-swap
/// emits just `["tools", "tool_choice"]` — a partial list — so here a missing
/// entry proves nothing and only a listed one is a claim.
fn apply_listed_parameters(m: &serde_json::Value, model: &mut DiscoveredModel) {
    let params = json_str_list(m, "supported_parameters");
    let listed = |any_of: &[&str]| -> Option<bool> {
        any_of.iter().any(|w| params.iter().any(|p| p == w)).then_some(true)
    };
    fill(&mut model.supports_function_calling, listed(&["tools", "tool_choice"]));
    fill(&mut model.supports_reasoning, listed(&["reasoning", "include_reasoning", "reasoning_effort"]));
    fill(&mut model.supports_response_schema, listed(&["response_format", "structured_outputs"]));
}

/// OpenAI-style discovery: id, context window, output cap, and every capability
/// grammar the entry publishes. Handles the `data[]` list (OpenAI, Anthropic,
/// vLLM, llama.cpp, llama-swap, most compat servers) and, when a server answers
/// with nothing but a bare `models[]` array, its names.
fn parse_generic_models(body: &serde_json::Value) -> Vec<DiscoveredModel> {
    body.get("data")
        .and_then(|d| d.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|m| {
                    let id = m.get("id")?.as_str()?.to_string();
                    let text = |k: &str| m.get(k).and_then(|v| v.as_str()).map(str::to_string);
                    let mut model = DiscoveredModel {
                        id,
                        context_window: entry_context_window(m),
                        max_output_tokens: entry_max_output_tokens(m),
                        root: text("root"),
                        parent: text("parent"),
                        ..Default::default()
                    };
                    apply_published_capabilities(m, &mut model);
                    Some(model)
                })
                .collect()
        })
        .or_else(|| {
            body.get("models").and_then(|d| d.as_array()).map(|arr| {
                arr.iter()
                    .filter_map(|m| {
                        let id = m.get("name")?.as_str()?.to_string();
                        Some(DiscoveredModel {
                            id,
                            ..Default::default()
                        })
                    })
                    .collect()
            })
        })
        .unwrap_or_default()
}

/// Google Gemini discovery: `/v1beta/models` returns `{ models: [{ name:
/// "models/gemini-2.5-flash", inputTokenLimit, outputTokenLimit,
/// supportedGenerationMethods: [...], thinking, … }] }`. The id is the `name`
/// with its `models/` prefix stripped (the bare id the routing layer stores);
/// token limits map to the context window + max output. Capability flags are
/// asserted only from what the methods list actually advertises (left `None` to
/// inherit the catalog/default otherwise — modality flags like vision/audio
/// aren't in ListModels, so the catalog cross-reference fills those), mirroring
/// the OpenRouter parser's "only claim what the provider published" rule.
fn parse_gemini_models(body: &serde_json::Value) -> Vec<DiscoveredModel> {
    body.get("models")
        .and_then(|d| d.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|m| {
                    let raw = m.get("name")?.as_str()?;
                    let id = raw.strip_prefix("models/").unwrap_or(raw).to_string();
                    if id.is_empty() {
                        return None;
                    }
                    let context_window = m.get("inputTokenLimit").and_then(|v| v.as_i64());
                    let max_output_tokens = m.get("outputTokenLimit").and_then(|v| v.as_i64());

                    // supportedGenerationMethods → capability signals. A
                    // `generateContent` model is a chat model: Gemini chat models
                    // support tool/function calling and JSON-schema structured
                    // output; an embedding-only model (e.g. `embedContent`) does
                    // not. `createCachedContent` advertises context caching.
                    let methods: Vec<&str> = m
                        .get("supportedGenerationMethods")
                        .and_then(|v| v.as_array())
                        .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
                        .unwrap_or_default();
                    let methods_known = !methods.is_empty();
                    let has = |needle: &str| methods.contains(&needle);
                    let is_chat = has("generateContent");
                    let supports_function_calling = methods_known.then_some(is_chat);
                    let supports_response_schema = methods_known.then_some(is_chat);
                    let supports_caching = methods_known.then(|| has("createCachedContent"));
                    // `thinking: true` marks the reasoning (2.5-thinking) models.
                    let supports_reasoning = m.get("thinking").and_then(|v| v.as_bool());

                    Some(DiscoveredModel {
                        id,
                        context_window,
                        max_output_tokens,
                        supports_function_calling,
                        supports_response_schema,
                        supports_caching,
                        supports_reasoning,
                        ..Default::default()
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Assemble the price map for a discovered model from the units the provider
/// actually published.
///
/// A unit the provider left out is simply absent: an absent rate is a price
/// nobody knows, never a zero (a zero would report the traffic as free and, since
/// budget accrual skips a zero cost, turn an enforcing cap into a no-op). `None`
/// when nothing at all was published, so the model inherits the catalog's map
/// instead of overriding it with an empty one.
///
/// Every provider parsed here quotes in USD; a provider quoting otherwise carries
/// its currency into this call rather than having its numbers relabelled.
fn discovered_rates(units: impl IntoIterator<Item = (Unit, Option<f64>)>) -> Option<Rates> {
    let units: std::collections::BTreeMap<Unit, Rate> = units
        .into_iter()
        .filter_map(|(unit, rate)| rate.map(|r| (unit, Rate::Flat(r))))
        .collect();
    (!units.is_empty()).then(|| Rates::from_units(units, Currency::USD))
}

/// OpenRouter publishes rich per-model metadata at `/api/v1/models`: modalities
/// (`architecture.input_modalities`/`output_modalities`), `supported_parameters`,
/// and per-token string `pricing`. We map all of it so models import with real
/// capabilities and pricing instead of the standard fallback.
fn parse_openrouter_models(body: &serde_json::Value) -> Vec<DiscoveredModel> {
    let Some(arr) = body.get("data").and_then(|d| d.as_array()) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|m| {
            let id = m.get("id")?.as_str()?.to_string();
            let context_window = m.get("context_length").and_then(|v| v.as_i64());
            let max_output_tokens = m
                .get("top_provider")
                .and_then(|tp| tp.get("max_completion_tokens"))
                .and_then(|v| v.as_i64());

            // supported_parameters → tool/reasoning/schema flags. OpenRouter
            // documents the list as a full enumeration, so a non-empty list
            // missing an entry is a real "unsupported".
            let params = json_str_list(m, "supported_parameters");
            let supports_function_calling = flag_from_list(&params, &["tools", "tool_choice"]);
            let supports_reasoning = flag_from_list(&params, &["reasoning", "include_reasoning"]);
            let supports_response_schema =
                flag_from_list(&params, &["response_format", "structured_outputs"]);

            // pricing.* are USD strings; "0"/absent → None. Token-priced fields
            // (prompt/completion/cache) are per-token → ×1e6 for per-1M; per-unit
            // fields (image/request) are already absolute → no scaling.
            let price_raw = |key: &str| -> Option<f64> {
                let raw = m.get("pricing")?.get(key)?.as_str()?;
                let v: f64 = raw.parse().ok()?;
                (v > 0.0).then_some(v)
            };
            let price_per_1m = |key: &str| -> Option<f64> { price_raw(key).map(|v| v * 1_000_000.0) };
            let cache_read = price_per_1m("input_cache_read");
            let supports_caching = cache_read.is_some().then_some(true);

            let mut model = DiscoveredModel {
                id,
                context_window,
                max_output_tokens,
                supports_reasoning,
                supports_function_calling,
                supports_caching,
                supports_response_schema,
                supports_system_messages: None,
                rates: discovered_rates([
                    (Unit::InputToken, price_per_1m("prompt")),
                    (Unit::OutputToken, price_per_1m("completion")),
                    (Unit::CacheWriteToken, price_per_1m("input_cache_write")),
                    (Unit::CacheReadToken, cache_read),
                    (Unit::ImageOutput, price_raw("image")),
                ]),
                // Hosted catalogs name no weights path or adapter base.
                root: None,
                parent: None,
                ..Default::default()
            };
            // Modalities → input/output flags: the same grammar every server
            // emitting `architecture` uses, read by the one shared reader.
            apply_architecture_modalities(m, &mut model);
            Some(model)
        })
        .collect()
}

/// Read a boolean capability out of a vendor's flat feature/tag list.
///
/// `None` when the list is empty — an absent list is "the provider didn't say",
/// which must inherit the catalog rather than assert a negative. A non-empty
/// list is treated as complete, so a feature missing from it means `false`.
/// Only use this for lists the vendor documents as exhaustive (an explicit
/// modality or feature array); a loose descriptive tag set must not be read as
/// a denial — see [`parse_deepinfra_models`].
fn flag_from_list(list: &[String], any_of: &[&str]) -> Option<bool> {
    (!list.is_empty()).then(|| any_of.iter().any(|w| list.iter().any(|x| x == w)))
}

/// Collect a JSON string array into owned strings; missing/!array → empty.
fn json_str_list(v: &serde_json::Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(|x| x.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default()
}

/// Novita reports a per-1M price as an integer in units of 1e-4 USD — `2690`
/// means $0.269 per 1M tokens. Cross-checked against the catalog's own novita
/// rows, which agree to the factor exactly across every overlapping model.
///
/// This scale is the whole risk of the parser: a wrong divisor still parses, is
/// still a plausible-looking number, and misprices every request by a power of
/// ten. `novita_price_scale_is_pinned_to_real_rates` pins it against verbatim
/// live entries with independently known prices.
const NOVITA_PRICE_UNIT_USD: f64 = 1e-4;

/// Novita publishes `input_token_price_per_m` / `output_token_price_per_m` (see
/// [`NOVITA_PRICE_UNIT_USD`] for the scale), a `pricing.input_cache_read` entry,
/// `context_size` / `max_output_tokens`, an exhaustive `features` list and
/// explicit modality arrays.
///
/// A price of `0` is **not** free: novita reports zero both for its tiered-billing
/// models (whose real rate depends on context length) and for unreleased ones, so
/// zero maps to `None` — unknown, inherit the catalog — exactly as OpenRouter's
/// zero does.
fn parse_novita_models(body: &serde_json::Value) -> Vec<DiscoveredModel> {
    let Some(arr) = body.get("data").and_then(|d| d.as_array()) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|m| {
            let id = m.get("id")?.as_str()?.to_string();
            let scaled = |v: Option<&serde_json::Value>| -> Option<f64> {
                let raw = v?.as_f64()?;
                (raw > 0.0).then_some(raw * NOVITA_PRICE_UNIT_USD)
            };
            let cache_read = scaled(
                m.get("pricing")
                    .and_then(|p| p.get("input_cache_read"))
                    .and_then(|c| c.get("price_per_m")),
            );

            let features = json_str_list(m, "features");
            let input_mods = json_str_list(m, "input_modalities");
            let output_mods = json_str_list(m, "output_modalities");

            Some(DiscoveredModel {
                id,
                context_window: m.get("context_size").and_then(|v| v.as_i64()),
                max_output_tokens: m.get("max_output_tokens").and_then(|v| v.as_i64()),
                supports_vision: flag_from_list(&input_mods, &["image"]),
                supports_audio_input: flag_from_list(&input_mods, &["audio"]),
                supports_video_input: flag_from_list(&input_mods, &["video"]),
                supports_pdf_input: flag_from_list(&input_mods, &["file", "pdf"]),
                supports_audio_output: flag_from_list(&output_mods, &["audio"]),
                supports_function_calling: flag_from_list(&features, &["function-calling"]),
                supports_response_schema: flag_from_list(&features, &["structured-outputs"]),
                supports_reasoning: flag_from_list(&features, &["reasoning"]),
                supports_caching: cache_read.is_some().then_some(true),
                supports_system_messages: None,
                rates: discovered_rates([
                    (Unit::InputToken, scaled(m.get("input_token_price_per_m"))),
                    (Unit::OutputToken, scaled(m.get("output_token_price_per_m"))),
                    (Unit::CacheReadToken, cache_read),
                ]),
                // Hosted catalogs name no weights path or adapter base.
                root: None,
                parent: None,
            })
        })
        .collect()
}

/// Chutes publishes `price.{input,output,input_cache_read}.usd` already in USD
/// per 1M tokens — no scaling — alongside `context_length`, `max_output_length`,
/// an exhaustive `supported_features` list and explicit modality arrays.
///
/// It also carries a flat `pricing.{prompt,completion}` mirror of the same
/// numbers; we read the structured `price` object because it is the one that
/// names its unit (`usd`, beside a `tao` figure in its own token) — the flat
/// mirror would be indistinguishable from OpenRouter's per-TOKEN field of the
/// same name, which needs a 1e6 scale.
fn parse_chutes_models(body: &serde_json::Value) -> Vec<DiscoveredModel> {
    let Some(arr) = body.get("data").and_then(|d| d.as_array()) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|m| {
            let id = m.get("id")?.as_str()?.to_string();
            let usd = |key: &str| -> Option<f64> {
                let v = m.get("price")?.get(key)?.get("usd")?.as_f64()?;
                (v > 0.0).then_some(v)
            };
            let cache_read = usd("input_cache_read");

            let features = json_str_list(m, "supported_features");
            let input_mods = json_str_list(m, "input_modalities");
            let output_mods = json_str_list(m, "output_modalities");

            Some(DiscoveredModel {
                id,
                // Read each candidate through to a number before falling back:
                // an explicit `"context_length": null` is a PRESENT key, so a
                // fallback chained on `.get()` alone would stop at it and never
                // reach `max_model_len`.
                context_window: m
                    .get("context_length")
                    .and_then(|v| v.as_i64())
                    .or_else(|| m.get("max_model_len").and_then(|v| v.as_i64())),
                max_output_tokens: m.get("max_output_length").and_then(|v| v.as_i64()),
                supports_vision: flag_from_list(&input_mods, &["image"]),
                supports_audio_input: flag_from_list(&input_mods, &["audio"]),
                supports_video_input: flag_from_list(&input_mods, &["video"]),
                supports_pdf_input: flag_from_list(&input_mods, &["file", "pdf"]),
                supports_audio_output: flag_from_list(&output_mods, &["audio"]),
                supports_function_calling: flag_from_list(&features, &["tools"]),
                supports_response_schema: flag_from_list(
                    &features,
                    &["structured_outputs", "json_mode"],
                ),
                supports_reasoning: flag_from_list(&features, &["reasoning"]),
                supports_caching: cache_read.is_some().then_some(true),
                supports_system_messages: None,
                rates: discovered_rates([
                    (Unit::InputToken, usd("input")),
                    (Unit::OutputToken, usd("output")),
                    (Unit::CacheReadToken, cache_read),
                ]),
                // Hosted catalogs name no weights path or adapter base.
                root: None,
                parent: None,
            })
        })
        .collect()
}

/// DeepInfra nests everything under `metadata`: `context_length`, `max_tokens`,
/// and a `pricing` object whose KEY NAMES the unit — `input_tokens` /
/// `output_tokens` / `cache_read_tokens` are USD per 1M, `per_image_unit` is USD
/// per image, `input_seconds` is USD per second of audio. Reading the unit off
/// the key is what keeps a transcription model (priced per second) from being
/// mistaken for a token-priced one.
///
/// Capabilities come from `metadata.tags`, which — unlike OpenRouter's modality
/// arrays or Chutes' feature list — is a loose descriptive label set, not an
/// exhaustive capability declaration. So tags assert only positives: a missing
/// tag inherits the catalog instead of denying the capability, because denying
/// one here makes the proxy reject requests the model actually serves.
fn parse_deepinfra_models(body: &serde_json::Value) -> Vec<DiscoveredModel> {
    let Some(arr) = body.get("data").and_then(|d| d.as_array()) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|m| {
            let id = m.get("id")?.as_str()?.to_string();
            let meta = m.get("metadata");
            let price = |key: &str| -> Option<f64> {
                let v = meta?.get("pricing")?.get(key)?.as_f64()?;
                (v > 0.0).then_some(v)
            };
            let meta_i64 = |key: &str| meta.and_then(|x| x.get(key)).and_then(|v| v.as_i64());

            let tags = meta.map(|x| json_str_list(x, "tags")).unwrap_or_default();
            let tagged = |want: &[&str]| -> Option<bool> {
                want.iter()
                    .any(|w| tags.iter().any(|t| t == w))
                    .then_some(true)
            };
            let cache_read = price("cache_read_tokens");

            Some(DiscoveredModel {
                id,
                context_window: meta_i64("context_length"),
                max_output_tokens: meta_i64("max_tokens"),
                supports_vision: tagged(&["vision", "vlm"]),
                supports_reasoning: tagged(&["reasoning"]),
                supports_caching: tagged(&["prompt_cache"]).or(cache_read.is_some().then_some(true)),
                supports_audio_input: tagged(&["stt"]),
                supports_audio_output: tagged(&["tts"]),
                supports_video_input: None,
                supports_pdf_input: None,
                supports_function_calling: None,
                supports_response_schema: None,
                supports_system_messages: None,
                rates: discovered_rates([
                    (Unit::InputToken, price("input_tokens")),
                    (Unit::OutputToken, price("output_tokens")),
                    (Unit::CacheReadToken, cache_read),
                    (Unit::ImageOutput, price("per_image_unit")),
                    (Unit::AudioSecond, price("input_seconds")),
                ]),
                // Hosted catalogs name no weights path or adapter base.
                root: None,
                parent: None,
            })
        })
        .collect()
}

#[cfg(test)]
mod openrouter_parser_tests {
    use super::*;

    // Verbatim entries from a live `https://openrouter.ai/api/v1/models` response,
    // trimmed to the fields the parser reads. Locks the parser against the real
    // OpenRouter schema (modalities, supported_parameters, per-token pricing).
    fn body() -> serde_json::Value {
        serde_json::json!({ "data": [
            {
                "id": "anthropic/claude-opus-4.8-fast",
                "context_length": 1000000,
                "top_provider": { "context_length": 1000000, "max_completion_tokens": 128000, "is_moderated": true },
                "architecture": { "input_modalities": ["text", "image", "file"], "output_modalities": ["text"] },
                "supported_parameters": ["include_reasoning","max_tokens","reasoning","response_format","stop","structured_outputs","tool_choice","tools","verbosity"],
                "pricing": { "prompt": "0.00001", "completion": "0.00005", "web_search": "0.01", "input_cache_read": "0.000001", "input_cache_write": "0.0000125" }
            },
            {
                "id": "qwen/qwen3.7-max",
                "context_length": 1000000,
                "top_provider": { "context_length": 1000000, "max_completion_tokens": 65536, "is_moderated": false },
                "architecture": { "input_modalities": ["text"], "output_modalities": ["text"] },
                "supported_parameters": ["include_reasoning","logprobs","max_tokens","reasoning","response_format","structured_outputs","tool_choice","tools","top_p"],
                "pricing": { "prompt": "0.00000125", "completion": "0.00000375", "input_cache_read": "0.00000025", "input_cache_write": "0.0000015625" }
            },
            {
                "id": "google/gemini-3.5-flash",
                "context_length": 1048576,
                "top_provider": { "context_length": 1048576, "max_completion_tokens": 65536, "is_moderated": false },
                "architecture": { "input_modalities": ["text", "image", "video", "file", "audio"], "output_modalities": ["text"] },
                "supported_parameters": ["include_reasoning","max_tokens","reasoning","response_format","stop","structured_outputs","tool_choice","tools","top_p"],
                "pricing": { "prompt": "0.0000015", "completion": "0.000009", "image": "0.0000015", "audio": "0.000003", "web_search": "0.014", "internal_reasoning": "0.000009", "input_cache_read": "0.00000015", "input_cache_write": "0.00000008333333333333334" }
            }
        ]})
    }

    fn approx(a: Option<f64>, b: f64) {
        let v = a.expect("price present");
        assert!((v - b).abs() < 1e-6, "expected ~{b}, got {v}");
    }

    /// The rate the parser recorded for one billing unit, or `None` when it
    /// recorded none.
    fn rate(m: &DiscoveredModel, unit: Unit) -> Option<f64> {
        match m.rates.as_ref()?.units.get(&unit)? {
            Rate::Flat(v) => Some(*v),
            Rate::Tiered { rate, .. } => Some(*rate),
        }
    }

    /// One entry per spelling, each read on its own — the OpenAI model object
    /// declares no context field, so every compatible server named it itself and
    /// a spelling we do not read imports as "no window".
    #[test]
    fn every_known_context_window_spelling_is_read() {
        for key in ["context_window", "context_length", "max_model_len", "max_input_tokens", "max_context_length"] {
            let body = serde_json::json!({
                "data": [{ "id": "m", key: 64_000 }]
            });
            let models = parse_generic_models(&body);
            assert_eq!(models[0].context_window, Some(64_000), "spelling `{key}`");
        }
        // llama.cpp nests the SERVED window; read after the top-level names.
        let body = serde_json::json!({
            "data": [{ "id": "m", "meta": { "n_ctx": 32_768 } }]
        });
        assert_eq!(parse_generic_models(&body)[0].context_window, Some(32_768));
        // Negative control: an entry declaring none stays unknown rather than
        // acquiring a number from somewhere.
        let bare = serde_json::json!({ "data": [{ "id": "m" }] });
        assert_eq!(parse_generic_models(&bare)[0].context_window, None);
    }

    /// vLLM's `/v1/models` card (`ModelCard`, vLLM main 2026-09): a base model
    /// carries `root` = the weights path and `max_model_len`; a LoRA adapter
    /// carries `root` = the adapter path, `parent` = its base, and no window.
    #[test]
    fn a_vllm_card_carries_its_root_and_an_adapter_its_parent() {
        let body = serde_json::json!({
            "object": "list",
            "data": [
                { "id": "llama-70b", "object": "model", "owned_by": "vllm",
                  "root": "/models/llama-3.3-70b", "parent": null, "max_model_len": 32768 },
                { "id": "sql-lora", "object": "model", "owned_by": "vllm",
                  "root": "/adapters/sql", "parent": "llama-70b" },
            ]
        });
        let models = parse_generic_models(&body);
        assert_eq!(models[0].root.as_deref(), Some("/models/llama-3.3-70b"));
        assert_eq!(models[0].parent, None);
        assert_eq!(models[0].context_window, Some(32_768));
        assert_eq!(models[1].root.as_deref(), Some("/adapters/sql"));
        assert_eq!(models[1].parent.as_deref(), Some("llama-70b"));
        assert_eq!(models[1].context_window, None);
    }

    /// A top-level declaration outranks llama.cpp's served `meta.n_ctx`, and an
    /// explicit `null` is a PRESENT key — chaining on `.get()` alone would stop
    /// at it and report no window at all.
    #[test]
    fn a_null_spelling_falls_through_to_the_next_candidate() {
        let body = serde_json::json!({
            "data": [{
                "id": "m",
                "context_window": serde_json::Value::Null,
                "context_length": 48_000,
                "meta": { "n_ctx": 8_000 },
            }]
        });
        assert_eq!(parse_generic_models(&body)[0].context_window, Some(48_000));
    }

    /// `max_tokens` is the OUTPUT ceiling on Anthropic's list but has meant the
    /// CONTEXT length on older OpenAI-compat shims, so it is read only beside
    /// `max_input_tokens` — the field that identifies the Anthropic shape.
    #[test]
    fn a_bare_max_tokens_is_never_read_as_the_output_cap() {
        let ambiguous = serde_json::json!({
            "data": [{ "id": "m", "context_length": 32_000, "max_tokens": 32_000 }]
        });
        assert_eq!(parse_generic_models(&ambiguous)[0].max_output_tokens, None);

        // Positive control: beside `max_input_tokens` it is unambiguous, so the
        // gate cannot pass by never reading `max_tokens` at all.
        let anthropic = serde_json::json!({
            "data": [{ "id": "m", "max_input_tokens": 200_000, "max_tokens": 64_000 }]
        });
        let m = &parse_generic_models(&anthropic)[0];
        assert_eq!(m.context_window, Some(200_000));
        assert_eq!(m.max_output_tokens, Some(64_000));
    }

    /// Anthropic publishes a capability tree; each leaf is a `{supported: bool}`
    /// wrapper, never a bare bool. Only what it actually states is claimed —
    /// everything else stays `None` and inherits.
    #[test]
    fn anthropic_capabilities_claim_only_what_is_published() {
        let body = serde_json::json!({
            "data": [{
                "id": "claude-opus-5",
                "max_input_tokens": 200_000,
                "capabilities": {
                    "image_input": { "supported": true },
                    "pdf_input": { "supported": true },
                    "structured_outputs": { "supported": false },
                    "thinking": { "supported": true, "types": { "enabled": { "supported": true } } },
                    "context_management": { "supported": true },
                    "citations": { "supported": true },
                }
            }]
        });
        let m = &parse_generic_models(&body)[0];
        assert_eq!(m.supports_vision, Some(true));
        assert_eq!(m.supports_pdf_input, Some(true));
        // A published `false` is a real claim and must be carried as one.
        assert_eq!(m.supports_response_schema, Some(false));
        assert_eq!(m.supports_reasoning, Some(true));
        // `context_management` is server-side context editing, NOT prompt
        // caching — reading one as the other would advertise cache support off
        // an unrelated feature.
        assert_eq!(m.supports_caching, None);
        // Absent from the tree entirely ⇒ inherit, never assert false.
        assert_eq!(m.supports_function_calling, None);
        assert_eq!(m.supports_audio_input, None);
        assert_eq!(m.supports_system_messages, None);
    }

    /// Every other server reaching this parser publishes no tree, and an absent
    /// key must leave every flag inheriting rather than asserting `false`.
    #[test]
    fn a_server_with_no_capability_tree_claims_nothing() {
        let body = serde_json::json!({ "data": [{ "id": "m", "context_window": 8_000 }] });
        let m = &parse_generic_models(&body)[0];
        assert_eq!(m.supports_vision, None);
        assert_eq!(m.supports_reasoning, None);
        assert_eq!(m.supports_pdf_input, None);
        assert_eq!(m.supports_response_schema, None);
    }

    /// A llama-swap entry, verbatim from a live `/v1/models` (llama-swap in
    /// front of llama.cpp, model LOADED). It speaks three grammars at once — its
    /// own true-only capability map, OpenRouter's `architecture`, and a PARTIAL
    /// `supported_parameters` — under whatever provider key the operator chose.
    #[test]
    fn a_llama_swap_entry_reads_every_grammar_it_publishes() {
        let body = serde_json::json!({ "object": "list", "data": [{
            "id": "bonsai2-unlocked", "object": "model", "created": 1_790_432_630u64,
            "owned_by": "llama-swap", "name": "Bonsai 2 27B + vision",
            "architecture": {
                "input_modalities": ["text", "image", "video"],
                "modality": "text+image+video->text",
                "output_modalities": ["text"]
            },
            "capabilities": { "function_calling": true, "vision": true },
            "supported_parameters": ["tools", "tool_choice"],
            "context_length": 131_072, "context_window": 131_072,
            "meta": { "llamaswap": { "type": "model" }, "n_ctx": 131_072 },
            "status": { "value": "loaded" }
        }]});
        let m = &parse_generic_models(&body)[0];
        assert_eq!(m.context_window, Some(131_072));
        assert_eq!(m.supports_vision, Some(true));
        assert_eq!(m.supports_function_calling, Some(true));
        assert_eq!(m.supports_video_input, Some(true));
        // A non-empty modality list is complete: what it leaves out is a "no".
        assert_eq!(m.supports_audio_input, Some(false));
        assert_eq!(m.supports_pdf_input, Some(false));
        assert_eq!(m.supports_audio_output, Some(false));
        // `supported_parameters` here is a PARTIAL list, so what it omits proves
        // nothing: reasoning and structured output stay inheriting.
        assert_eq!(m.supports_reasoning, None);
        assert_eq!(m.supports_response_schema, None);
    }

    /// Mistral's `/v1/models` entries (spec `BaseModelCard`, shape as the
    /// published example): a flat capability map of `true` AND `false`, and the
    /// window under `max_context_length`. A published `false` is carried as
    /// one; a key the entry leaves out stays inheriting.
    #[test]
    fn a_mistral_entry_carries_every_published_capability_true_or_false() {
        let body = serde_json::json!({ "object": "list", "data": [
            {
                "id": "magistral-medium-latest", "object": "model", "owned_by": "mistralai",
                "type": "base", "max_context_length": 131_072,
                "capabilities": {
                    "completion_chat": true, "function_calling": true, "reasoning": true,
                    "completion_fim": false, "fine_tuning": false, "vision": true,
                    "classification": false, "audio": false
                }
            },
            {
                "id": "voxtral-mini-latest", "object": "model", "type": "base",
                "max_context_length": 32_768,
                "capabilities": {
                    "completion_chat": false, "audio": false, "audio_transcription": true,
                    "audio_speech": false, "vision": false
                }
            },
            {
                "id": "open-mistral-7b", "object": "model", "type": "base",
                "max_context_length": 32_768,
                "capabilities": { "completion_chat": true, "function_calling": false }
            }
        ]});
        let models = parse_generic_models(&body);
        let (magistral, voxtral, seven) = (&models[0], &models[1], &models[2]);

        assert_eq!(magistral.context_window, Some(131_072));
        assert_eq!(magistral.supports_reasoning, Some(true));
        assert_eq!(magistral.supports_function_calling, Some(true));
        assert_eq!(magistral.supports_vision, Some(true));
        assert_eq!(magistral.supports_audio_input, Some(false));
        assert_eq!(magistral.supports_audio_output, None, "audio_speech absent ⇒ inherit");

        // A transcription model takes audio even though its chat `audio` is off.
        assert_eq!(voxtral.supports_audio_input, Some(true));
        assert_eq!(voxtral.supports_audio_output, Some(false));
        assert_eq!(voxtral.supports_vision, Some(false));

        // Positive control for "absent is not false": a key the entry never
        // published must not be read as a denial.
        assert_eq!(seven.supports_function_calling, Some(false));
        assert_eq!(seven.supports_reasoning, None);
        assert_eq!(seven.supports_vision, None);
        assert_eq!(seven.supports_audio_input, None);
    }

    /// llama-swap publishes metadata only for a model it has loaded; an unloaded
    /// one is a bare id and must claim nothing at all.
    #[test]
    fn an_unloaded_llama_swap_entry_claims_nothing() {
        let body = serde_json::json!({ "data": [{
            "id": "bonsai2-1bit", "object": "model", "owned_by": "llama-swap",
            "status": { "value": "unloaded" }
        }]});
        let m = &parse_generic_models(&body)[0];
        assert_eq!(m.context_window, None);
        assert_eq!(m.supports_vision, None);
        assert_eq!(m.supports_function_calling, None);
        assert_eq!(m.supports_video_input, None);
    }

    /// A bare-boolean leaf is llama-swap's TRUE-only grammar: it claims support
    /// and nothing else. An Anthropic-style leaf still carries its `false`.
    #[test]
    fn a_bare_leaf_only_ever_claims_support() {
        let bare_false = serde_json::json!({ "data": [{
            "id": "m", "capabilities": { "vision": false, "function_calling": false }
        }]});
        let m = &parse_generic_models(&bare_false)[0];
        assert_eq!(m.supports_vision, None);
        assert_eq!(m.supports_function_calling, None);

        let wrapped_false = serde_json::json!({ "data": [{
            "id": "m", "capabilities": { "image_input": { "supported": false } }
        }]});
        assert_eq!(parse_generic_models(&wrapped_false)[0].supports_vision, Some(false));
    }

    /// Outside the OpenRouter parser a parameter list is read positively only;
    /// a listed entry is a claim, a missing one proves nothing.
    #[test]
    fn a_partial_parameter_list_claims_only_what_it_lists() {
        let body = serde_json::json!({ "data": [{
            "id": "m", "supported_parameters": ["response_format", "reasoning_effort"]
        }]});
        let m = &parse_generic_models(&body)[0];
        assert_eq!(m.supports_response_schema, Some(true));
        assert_eq!(m.supports_reasoning, Some(true));
        assert_eq!(m.supports_function_calling, None);
    }

    /// The first grammar to answer a flag keeps it: a published capability map
    /// is not overwritten by what a modality list implies.
    #[test]
    fn the_first_published_grammar_keeps_the_flag() {
        let body = serde_json::json!({ "data": [{
            "id": "m",
            "capabilities": { "image_input": { "supported": false } },
            "architecture": { "input_modalities": ["text", "image"] }
        }]});
        assert_eq!(parse_generic_models(&body)[0].supports_vision, Some(false));
    }

    /// Ollama's native list (source `api/types.go`): capabilities from
    /// `/api/tags`, the SERVED window from `/api/ps` for a loaded model only.
    /// The trained `details.context_length` is never the window — Ollama serves
    /// `num_ctx`, which is usually far smaller.
    #[test]
    fn ollama_native_reads_capabilities_and_only_the_served_window() {
        let tags = serde_json::json!({ "models": [
            { "name": "llama3.2-vision:latest", "model": "llama3.2-vision:latest",
              "details": { "family": "mllama", "context_length": 131_072 },
              "capabilities": ["completion", "vision"] },
            { "name": "qwen3:8b", "model": "qwen3:8b",
              "details": { "family": "qwen3", "context_length": 40_960 },
              "capabilities": ["completion", "tools", "thinking"] },
            { "name": "gemma3n:e4b", "model": "gemma3n:e4b",
              "capabilities": ["completion", "audio"] },
            { "name": "legacy:latest", "model": "legacy:latest" },
        ]});
        let ps = serde_json::json!({ "models": [
            { "name": "qwen3:8b", "model": "qwen3:8b", "context_length": 8_192 }
        ]});
        let models = parse_ollama_models(&tags, Some(&ps));
        let by = |id: &str| models.iter().find(|m| m.id == id).unwrap();

        let vision = by("llama3.2-vision:latest");
        assert_eq!(vision.context_window, None, "not loaded ⇒ no served window; the trained one is never read");
        assert_eq!(vision.supports_vision, Some(true));
        assert_eq!(vision.supports_function_calling, Some(false));
        assert_eq!(vision.supports_reasoning, Some(false));

        let qwen = by("qwen3:8b");
        assert_eq!(qwen.context_window, Some(8_192), "the served num_ctx, not the trained 40960");
        assert_eq!(qwen.supports_function_calling, Some(true));
        assert_eq!(qwen.supports_reasoning, Some(true));
        assert_eq!(qwen.supports_vision, Some(false));
        assert_eq!(qwen.supports_audio_input, Some(false));

        // `audio` is Ollama's `CapabilityAudio` (`types/model/capability.go`).
        assert_eq!(by("gemma3n:e4b").supports_audio_input, Some(true));

        // An Ollama too old to report capabilities claims nothing.
        let legacy = by("legacy:latest");
        assert_eq!(legacy.supports_vision, None);
        assert_eq!(legacy.supports_function_calling, None);

        // Without `/api/ps` the capabilities still arrive, and no window does.
        let no_ps = parse_ollama_models(&tags, None);
        assert!(no_ps.iter().all(|m| m.context_window.is_none()));
        assert_eq!(no_ps.iter().find(|m| m.id == "qwen3:8b").unwrap().supports_function_calling, Some(true));
    }

    #[test]
    fn parses_live_openrouter_caps_and_pricing() {
        let models = parse_openrouter_models(&body());
        assert_eq!(models.len(), 3);
        let by = |id: &str| models.iter().find(|m| m.id == id).unwrap().clone();

        // Multimodal (text+image+file) reasoning model with prompt caching.
        let claude = by("anthropic/claude-opus-4.8-fast");
        assert_eq!(claude.context_window, Some(1_000_000));
        assert_eq!(claude.max_output_tokens, Some(128_000));
        assert_eq!(claude.supports_vision, Some(true));      // image
        assert_eq!(claude.supports_pdf_input, Some(true));    // file
        assert_eq!(claude.supports_audio_input, Some(false));
        assert_eq!(claude.supports_video_input, Some(false));
        assert_eq!(claude.supports_audio_output, Some(false));
        assert_eq!(claude.supports_function_calling, Some(true));
        assert_eq!(claude.supports_reasoning, Some(true));
        assert_eq!(claude.supports_response_schema, Some(true));
        assert_eq!(claude.supports_caching, Some(true));      // input_cache_read present
        approx(rate(&claude, Unit::InputToken), 10.0);        // 0.00001 * 1e6
        approx(rate(&claude, Unit::OutputToken), 50.0);       // 0.00005 * 1e6
        approx(rate(&claude, Unit::CacheReadToken), 1.0);     // 0.000001 * 1e6
        approx(rate(&claude, Unit::CacheWriteToken), 12.5);   // 0.0000125 * 1e6
        assert_eq!(rate(&claude, Unit::ImageOutput), None);   // no image price → no unit

        // Text-only model: every multimodal flag false, tools/reasoning/schema true.
        let qwen = by("qwen/qwen3.7-max");
        assert_eq!(qwen.supports_vision, Some(false));
        assert_eq!(qwen.supports_pdf_input, Some(false));
        assert_eq!(qwen.supports_audio_input, Some(false));
        assert_eq!(qwen.supports_video_input, Some(false));
        assert_eq!(qwen.supports_function_calling, Some(true));
        assert_eq!(qwen.supports_reasoning, Some(true));
        assert_eq!(qwen.supports_response_schema, Some(true));
        assert_eq!(qwen.supports_caching, Some(true));
        approx(rate(&qwen, Unit::InputToken), 1.25);
        approx(rate(&qwen, Unit::OutputToken), 3.75);

        // Full multimodal input (image+video+file+audio) with a per-image price.
        let gemini = by("google/gemini-3.5-flash");
        assert_eq!(gemini.supports_vision, Some(true));
        assert_eq!(gemini.supports_video_input, Some(true));
        assert_eq!(gemini.supports_pdf_input, Some(true));
        assert_eq!(gemini.supports_audio_input, Some(true));
        assert_eq!(gemini.supports_audio_output, Some(false)); // audio not in output_modalities
        approx(rate(&gemini, Unit::InputToken), 1.5);
        approx(rate(&gemini, Unit::OutputToken), 9.0);
        // Per-image price is an absolute USD figure — NOT scaled by 1e6.
        approx(rate(&gemini, Unit::ImageOutput), 0.0000015);
        approx(rate(&gemini, Unit::CacheReadToken), 0.15);
    }
}

/// Every vendor that publishes a price publishes it in its own unit, and a wrong
/// scale is invisible: the value still parses, still looks like money, and simply
/// bills by a power of ten. These fixtures are verbatim entries from each live
/// endpoint, trimmed to the fields the parser reads, and each price assertion is
/// pinned to an independently-known rate for that model.
#[cfg(test)]
mod live_price_parser_tests {
    use super::*;

    fn approx(a: Option<f64>, b: f64) {
        let v = a.expect("price present");
        assert!((v - b).abs() < 1e-9, "expected ~{b}, got {v}");
    }

    /// The rate the parser recorded for one billing unit, or `None` when it
    /// recorded none.
    fn rate(m: &DiscoveredModel, unit: Unit) -> Option<f64> {
        match m.rates.as_ref()?.units.get(&unit)? {
            Rate::Flat(v) => Some(*v),
            Rate::Tiered { rate, .. } => Some(*rate),
        }
    }

    /// Verbatim from `https://api.novita.ai/v3/openai/models`.
    fn novita_body() -> serde_json::Value {
        serde_json::json!({ "data": [
            {
                "id": "deepseek/deepseek-v3.2",
                "input_token_price_per_m": 2690,
                "output_token_price_per_m": 4000,
                "pricing": {
                    "prompt": { "origin_price_per_m": 2690, "price_per_m": 2690 },
                    "completion": { "origin_price_per_m": 4000, "price_per_m": 4000 },
                    "input_cache_read": { "origin_price_per_m": 1345, "price_per_m": 1345 }
                },
                "is_tiered_billing": false,
                "context_size": 163840,
                "max_output_tokens": 65536,
                "model_type": "chat",
                "features": ["serverless", "function-calling", "structured-outputs", "reasoning"],
                "input_modalities": ["text"],
                "output_modalities": ["text"]
            },
            {
                "id": "qwen/qwen3-vl-235b-a22b-thinking",
                "input_token_price_per_m": 9800,
                "output_token_price_per_m": 39500,
                "pricing": {
                    "prompt": { "price_per_m": 9800 },
                    "completion": { "price_per_m": 39500 }
                },
                "is_tiered_billing": false,
                "context_size": 262144,
                "max_output_tokens": 32768,
                "model_type": "chat",
                "features": ["serverless", "function-calling", "reasoning"],
                "input_modalities": ["text", "image"],
                "output_modalities": ["text"]
            },
            {
                "id": "qwen/qwen3.5-plus",
                "input_token_price_per_m": 0,
                "output_token_price_per_m": 0,
                "pricing": {},
                "is_tiered_billing": true,
                "context_size": 262144,
                "model_type": "chat",
                "features": [],
                "input_modalities": [],
                "output_modalities": []
            }
        ]})
    }

    /// The scale is the whole risk. Both entries' catalog rows carry the same
    /// rates in USD — `deepseek-v3.2` at $0.269/$0.40 and `qwen3-vl-235b` at
    /// $0.98/$3.95 — so `2690` can only mean $0.269, fixing the unit at 1e-4.
    /// Any other divisor moves every assertion here by a power of ten.
    #[test]
    fn novita_price_scale_is_pinned_to_real_rates() {
        let models = parse_novita_models(&novita_body());
        assert_eq!(models.len(), 3);
        let by = |id: &str| models.iter().find(|m| m.id == id).unwrap().clone();

        let ds = by("deepseek/deepseek-v3.2");
        approx(rate(&ds, Unit::InputToken), 0.269);
        approx(rate(&ds, Unit::OutputToken), 0.40);
        approx(rate(&ds, Unit::CacheReadToken), 0.1345);
        assert_eq!(ds.supports_caching, Some(true));
        assert_eq!(ds.context_window, Some(163_840));
        assert_eq!(ds.max_output_tokens, Some(65_536));
        assert_eq!(ds.supports_function_calling, Some(true));
        assert_eq!(ds.supports_reasoning, Some(true));
        assert_eq!(ds.supports_response_schema, Some(true));
        assert_eq!(ds.supports_vision, Some(false)); // modalities known, text only

        let vl = by("qwen/qwen3-vl-235b-a22b-thinking");
        approx(rate(&vl, Unit::InputToken), 0.98);
        approx(rate(&vl, Unit::OutputToken), 3.95);
        assert_eq!(vl.supports_vision, Some(true));
        assert_eq!(vl.supports_response_schema, Some(false)); // features known, absent
        assert_eq!(rate(&vl, Unit::CacheReadToken), None);
        assert_eq!(vl.supports_caching, None);
    }

    /// Novita reports `0` for a tiered-billing model, whose real rate depends on
    /// context length. Reading that as free would bill every request on it at
    /// nothing; it means "not a flat rate", so it must stay unknown and inherit.
    #[test]
    fn novita_zero_price_is_unknown_not_free() {
        let models = parse_novita_models(&novita_body());
        let tiered = models.iter().find(|m| m.id == "qwen/qwen3.5-plus").unwrap();
        // No unit at all was published, so the model inherits the catalog's map
        // rather than overriding it with an empty one.
        assert_eq!(tiered.rates, None);
        // Empty feature/modality lists say nothing — they must not deny.
        assert_eq!(tiered.supports_function_calling, None);
        assert_eq!(tiered.supports_vision, None);
    }

    /// Verbatim from `https://llm.chutes.ai/v1/models`.
    fn chutes_body() -> serde_json::Value {
        serde_json::json!({ "data": [
            {
                "id": "moonshotai/Kimi-K3-TEE",
                "price": {
                    "input": { "tao": 0.0152, "usd": 3.0 },
                    "output": { "tao": 0.0760, "usd": 15.0 },
                    "input_cache_read": { "tao": 0.00152, "usd": 0.3 }
                },
                "pricing": { "prompt": 3.0, "completion": 15.0, "input_cache_read": 0.3 },
                "max_model_len": 1048576,
                "context_length": 1048576,
                "max_output_length": 262144,
                "input_modalities": ["text"],
                "output_modalities": ["text"],
                "supported_features": ["json_mode", "tools", "structured_outputs", "reasoning"]
            },
            {
                "id": "Qwen/Qwen3-32B-TEE",
                "price": {
                    "input": { "tao": 0.0005274994598202647, "usd": 0.104 },
                    "output": { "tao": 0.002109997839281059, "usd": 0.416 }
                },
                "pricing": { "prompt": 0.104, "completion": 0.416 },
                "max_model_len": 40960,
                "context_length": 40960,
                "max_output_length": 40960,
                "input_modalities": ["text"],
                "output_modalities": ["text"],
                "supported_features": ["json_mode", "tools"]
            }
        ]})
    }

    /// Chutes reports plain USD per 1M — no scaling at all. `Kimi-K3` is priced
    /// $3/$15 by every other vendor that serves it, which is exactly the figure
    /// in the response, so a 1e6 scale (OpenRouter's convention, on a field of
    /// the very same name) would be off by a million.
    #[test]
    fn chutes_prices_are_plain_usd_per_1m() {
        let models = parse_chutes_models(&chutes_body());
        assert_eq!(models.len(), 2);
        let by = |id: &str| models.iter().find(|m| m.id == id).unwrap().clone();

        let kimi = by("moonshotai/Kimi-K3-TEE");
        approx(rate(&kimi, Unit::InputToken), 3.0);
        approx(rate(&kimi, Unit::OutputToken), 15.0);
        approx(rate(&kimi, Unit::CacheReadToken), 0.3);
        assert_eq!(kimi.supports_caching, Some(true));
        assert_eq!(kimi.context_window, Some(1_048_576));
        assert_eq!(kimi.max_output_tokens, Some(262_144));
        assert_eq!(kimi.supports_function_calling, Some(true));
        assert_eq!(kimi.supports_reasoning, Some(true));
        assert_eq!(kimi.supports_response_schema, Some(true));
        assert_eq!(kimi.supports_vision, Some(false));

        let qwen = by("Qwen/Qwen3-32B-TEE");
        approx(rate(&qwen, Unit::InputToken), 0.104);
        approx(rate(&qwen, Unit::OutputToken), 0.416);
        assert_eq!(qwen.supports_reasoning, Some(false)); // features known, absent
        assert_eq!(rate(&qwen, Unit::CacheReadToken), None);
        assert_eq!(qwen.supports_caching, None);
    }

    /// Verbatim from `https://api.deepinfra.com/v1/openai/models`.
    fn deepinfra_body() -> serde_json::Value {
        serde_json::json!({ "data": [
            {
                "id": "deepseek-ai/DeepSeek-V3.2",
                "metadata": {
                    "context_length": 163840,
                    "max_tokens": 163840,
                    "pricing": { "input_tokens": 0.26, "output_tokens": 0.38, "cache_read_tokens": 0.13 },
                    "tags": ["chat", "prompt_cache"]
                }
            },
            {
                "id": "mistralai/Voxtral-Mini-3B-2507",
                "metadata": {
                    "context_length": serde_json::Value::Null,
                    "max_tokens": serde_json::Value::Null,
                    "pricing": { "input_seconds": 1.66667e-05 },
                    "tags": ["stt"]
                }
            },
            {
                "id": "Qwen/Qwen3-VL-235B-A22B-Instruct",
                "metadata": {
                    "context_length": 262144,
                    "max_tokens": 262144,
                    "pricing": { "input_tokens": 0.3, "output_tokens": 1.2 },
                    "tags": ["chat", "vlm", "vision", "reasoning"]
                }
            }
        ]})
    }

    /// DeepInfra names the unit in the pricing KEY — the same number under
    /// `input_tokens` and under `input_seconds` means two entirely different
    /// things, and reading a per-second rate as a per-1M-token one is the
    /// difference between billing a transcription and billing nothing.
    #[test]
    fn deepinfra_pricing_key_names_the_unit() {
        let models = parse_deepinfra_models(&deepinfra_body());
        assert_eq!(models.len(), 3);
        let by = |id: &str| models.iter().find(|m| m.id == id).unwrap().clone();

        let ds = by("deepseek-ai/DeepSeek-V3.2");
        approx(rate(&ds, Unit::InputToken), 0.26);
        approx(rate(&ds, Unit::OutputToken), 0.38);
        approx(rate(&ds, Unit::CacheReadToken), 0.13);
        assert_eq!(ds.supports_caching, Some(true));
        assert_eq!(ds.context_window, Some(163_840));

        // Priced per SECOND of audio, not per token: the token rates stay unset
        // so nothing bills it at a rate it does not have.
        let voxtral = by("mistralai/Voxtral-Mini-3B-2507");
        assert_eq!(rate(&voxtral, Unit::InputToken), None);
        assert_eq!(rate(&voxtral, Unit::OutputToken), None);
        approx(rate(&voxtral, Unit::AudioSecond), 1.66667e-05);
        assert_eq!(voxtral.supports_audio_input, Some(true));
        assert_eq!(voxtral.context_window, None);
    }

    /// DeepInfra's `tags` are descriptive labels, not an exhaustive capability
    /// declaration — so a missing tag must inherit the catalog, never deny. A
    /// denial here would make the proxy reject a request the model does serve.
    #[test]
    fn deepinfra_tags_assert_only_positives() {
        let models = parse_deepinfra_models(&deepinfra_body());
        let by = |id: &str| models.iter().find(|m| m.id == id).unwrap().clone();

        let vl = by("Qwen/Qwen3-VL-235B-A22B-Instruct");
        assert_eq!(vl.supports_vision, Some(true));
        assert_eq!(vl.supports_reasoning, Some(true));
        // Untagged capabilities inherit rather than resolving to false.
        assert_eq!(vl.supports_function_calling, None);
        assert_eq!(vl.supports_response_schema, None);
        assert_eq!(vl.supports_pdf_input, None);

        // A chat model with no vision tag does not claim "no vision".
        let ds = by("deepseek-ai/DeepSeek-V3.2");
        assert_eq!(ds.supports_vision, None);
        assert_eq!(ds.supports_reasoning, None);
    }
}

#[cfg(test)]
mod catalog_key_tests {
    use super::{canonical_catalog_key, canonical_provider_key};

    // Pins the canonical key the SQL `canonical_catalog_key(text)` function must
    // reproduce byte-for-byte. A provider-prefixed, dotted name and the bare
    // catalog model must reduce to the same key, so the two forms resolve to one
    // catalog row.
    #[test]
    fn canonical_keys() {
        for (input, expected) in [
            ("custom/qwen3.6", "qwen3-6"),
            ("qwen3.6", "qwen3-6"),
            ("openai/gpt-4o", "gpt-4o"),
            ("gpt-4o:extended", "gpt-4o"),
            ("Qwen3.6-27B", "qwen3-6-27b"),
            ("anthropic/claude-opus-4.8-20240115", "claude-opus-4-8"),
            ("gpt-4o-2024", "gpt-4o-2024"), // not a full -YYYYMMDD stamp: kept
            ("plain-model", "plain-model"),
            // Vendor path strips to the LAST '/', or a Fireworks id keeps
            // `fireworks/models/…` and matches nothing but itself.
            ("accounts/fireworks/models/deepseek-v3", "deepseek-v3"),
            ("meta-llama/Llama-3.3-70B-Instruct-Turbo", "llama-3-3-70b-instruct-turbo"),
            // A Bedrock cross-region inference profile must reduce to the same key
            // as the catalog's unprefixed row, in every region.
            (
                "us.anthropic.claude-sonnet-4-20250514-v1:0",
                "anthropic-claude-sonnet-4-20250514-v1",
            ),
            (
                "anthropic.claude-sonnet-4-20250514-v1:0",
                "anthropic-claude-sonnet-4-20250514-v1",
            ),
            (
                "global.anthropic.claude-haiku-4-5-20251001-v1:0",
                "anthropic-claude-haiku-4-5-20251001-v1",
            ),
            (
                "us-gov.anthropic.claude-3-haiku-20240307-v1:0",
                "anthropic-claude-3-haiku-20240307-v1",
            ),
            // A region-shaped token that is not a region prefix stays put.
            ("useful-model.v2", "useful-model-v2"),
            // An OpenAI fine-tune keeps both halves. Splitting on the first ':'
            // collapses every fine-tune onto the bare token `ft`, letting one
            // arbitrary row price them all; keying on the base alone is wrong the
            // other way, since a fine-tune costs more than the model it derives
            // from, and must not resolve to the base model's cheaper row.
            ("ft:gpt-3.5-turbo:acme::7p4lURel", "ft:gpt-3-5-turbo"),
            ("ft:gpt-4o-mini-2024-07-18:my-org::AbCdEf", "ft:gpt-4o-mini-2024-07-18"),
            ("ft:gpt-4o-2024-08-06", "ft:gpt-4o-2024-08-06"),
            ("gpt-4o-2024-08-06", "gpt-4o-2024-08-06"),
        ] {
            assert_eq!(canonical_catalog_key(input), expected, "input {input}");
        }
    }

    // Pins the canonical provider key the SQL `canonical_provider_key(text)`
    // function must reproduce byte-for-byte. Both sides of every provider
    // comparison run through it, so a fold that lands on the wrong token silently
    // stops a catalog row from ever pricing a server.
    #[test]
    fn canonical_provider_keys() {
        for (input, expected) in [
            ("openai", "openai"),
            ("open_ai", "openai"),
            ("OpenAI", "openai"),
            // The catalog seed's own vocabulary must reach the provider vocabulary:
            // `google` is an icon-only vendor row, never a selectable upstream.
            ("google", "google_gemini"),
            ("google_gemini", "google_gemini"),
            ("gemini", "google_gemini"),
            ("azure_openai", "azure_openai"),
            ("azure-openai", "azure_openai"),
            ("azure", "azure_openai"),
            ("aws_bedrock", "aws_bedrock"),
            ("bedrock", "aws_bedrock"),
            ("google_vertex", "google_vertex"),
            ("vertex", "google_vertex"),
            ("togetherai", "together"),
            ("fireworks-ai", "fireworks"),
            ("moonshotai", "moonshot"),
            ("nim", "nvidia"),
            ("ollama-cloud", "ollama"),
            // An unmodelled provider keeps a distinct identity rather than
            // collapsing into a catch-all with every other unknown.
            ("meta", "llama"),
            ("meta_llama", "llama"),
            ("llama", "llama"),
            ("sambanova", "sambanova"),
            ("inference_net", "inferencenet"),
            ("qwen", "qwen"),
            ("", ""),
        ] {
            assert_eq!(canonical_provider_key(input), expected, "input {input}");
        }
    }
}

#[cfg(test)]
mod endpoint_path_tests {
    use super::{can_discover, liveness_probe_path, normalize_chat_endpoint_path, provider_has_models_endpoint, UpstreamTransport};

    #[test]
    fn models_list_url_honours_the_override() {
        // A chat_endpoint_path override lists at `{base}/models`, not `{base}/v1/models`.
        assert_eq!(liveness_probe_path("chat_completions", Some("/chat/completions")), "/models");
        assert_eq!(liveness_probe_path("chat_completions", Some("/chat")), "/models");
        // No override → canonical.
        assert_eq!(liveness_probe_path("chat_completions", None), "/v1/models");
        // Gemini is fixed regardless.
        assert_eq!(liveness_probe_path("google_gemini", None), "/v1beta/models");
        assert_eq!(liveness_probe_path("google_gemini", Some("/chat/completions")), "/v1beta/models");
    }

    /// The switch is offered only where BOTH halves hold — the same pair the
    /// console asks before showing it.
    #[test]
    fn discovery_needs_a_listing_provider_and_a_listing_transport() {
        assert!(can_discover("openai", UpstreamTransport::Default));
        // The provider half alone is not enough…
        assert!(!can_discover("openai", UpstreamTransport::GoogleVertex));
        // …and neither is the transport half.
        assert!(!can_discover("perplexity", UpstreamTransport::Default));
        assert!(!can_discover("perplexity", UpstreamTransport::GoogleVertex));
        // Anthropic answers yes to both, which is what puts it back on the
        // periodic re-check.
        assert!(can_discover("anthropic", UpstreamTransport::Default));
    }

    #[test]
    fn only_providers_without_a_models_endpoint_skip_the_probe() {
        // Perplexity's models URL 404s → skip the probe.
        assert!(!provider_has_models_endpoint("perplexity"));
        // Nothing normalises the stored value, so every reader canonicalises
        // the same way — fold AND trim, or the console and the worker disagree
        // about the same row.
        assert!(!provider_has_models_endpoint("Perplexity"));
        assert!(!provider_has_models_endpoint("  PERPLEXITY  "));
        // Anthropic publishes /v1/models, so it is probed AND synced — this set
        // is the single answer to both questions.
        assert!(provider_has_models_endpoint("anthropic"));
        assert!(provider_has_models_endpoint("openai"));
        assert!(provider_has_models_endpoint("deepinfra"));
    }

    #[test]
    fn chat_endpoint_path_is_validated_and_trimmed() {
        // Absent / blank → no override.
        assert_eq!(normalize_chat_endpoint_path(None).unwrap(), None);
        assert_eq!(normalize_chat_endpoint_path(Some("   ".to_string())).unwrap(), None);
        // Valid rooted paths are trimmed.
        assert_eq!(
            normalize_chat_endpoint_path(Some("  /chat/completions ".to_string())).unwrap(),
            Some("/chat/completions".to_string())
        );
        // Missing leading slash would fuse onto the host → rejected.
        assert!(normalize_chat_endpoint_path(Some("chat/completions".to_string())).is_err());
        // Interior whitespace → rejected.
        assert!(normalize_chat_endpoint_path(Some("/chat completions".to_string())).is_err());
    }
}

#[cfg(test)]
mod transport_rule_tests {
    use super::{
        credential_shape, probe_is_worth_making, validate_transport_base_url, CredentialShape,
    };
    use streamscope_core::config::upstream_transport::UpstreamTransport;

    /// Vertex addresses a model from a project/location base, so a base missing
    /// either would build a URL that 404s with nothing on the page to explain it.
    #[test]
    fn a_vertex_base_must_name_a_project_and_a_location() {
        let t = UpstreamTransport::GoogleVertex;
        for good in [
            "https://us-central1-aiplatform.googleapis.com/v1/projects/p/locations/us-central1",
            "https://us-central1-aiplatform.googleapis.com/v1/projects/p/locations/us-central1/",
            "https://aiplatform.googleapis.com/v1/projects/my-proj/locations/global",
        ] {
            assert!(validate_transport_base_url(t, good).is_ok(), "{good}");
        }
        for bad in [
            // The regional host alone names no model.
            "https://us-central1-aiplatform.googleapis.com",
            "https://us-central1-aiplatform.googleapis.com/v1",
            // Half the address.
            "https://us-central1-aiplatform.googleapis.com/v1/projects/p",
            // The segment is present but names nothing.
            "https://us-central1-aiplatform.googleapis.com/v1/projects/p/locations",
            "https://us-central1-aiplatform.googleapis.com/v1/projects/p/locations/",
        ] {
            assert!(validate_transport_base_url(t, bad).is_err(), "{bad}");
        }
    }

    /// Every other transport's base is its own business.
    #[test]
    fn no_other_transport_constrains_its_base() {
        for t in UpstreamTransport::ALL
            .into_iter()
            .filter(|t| *t != UpstreamTransport::GoogleVertex)
        {
            assert!(validate_transport_base_url(t, "https://anything.example").is_ok(), "{t}");
        }
    }

    /// Two documents are not interchangeable just because both are documents:
    /// an Entra client-credentials pair and a Google service-account key are
    /// both JSON, and neither can mint from the other's.
    #[test]
    fn each_document_transport_has_its_own_credential_shape() {
        let entra = credential_shape(UpstreamTransport::AzureOpenAiEntra);
        let vertex = credential_shape(UpstreamTransport::GoogleVertex);
        assert_ne!(entra, vertex, "swapping these must require the credential again");
        assert!(matches!(entra, CredentialShape::Document(_)));
        assert!(matches!(vertex, CredentialShape::Document(_)));

        for t in UpstreamTransport::ALL.into_iter().filter(|t| !t.credential_is_document()) {
            assert_eq!(credential_shape(t), CredentialShape::RawKey, "{t}");
        }
        // Two raw-key transports swap freely — that is the point of the shape.
        assert_eq!(
            credential_shape(UpstreamTransport::AwsBedrock),
            credential_shape(UpstreamTransport::AzureOpenAi)
        );
    }

    /// A save checks something when there is a model list to GET, or when the
    /// transport mints a token — the exchange stands in for reachability.
    #[test]
    fn a_save_checks_a_model_list_or_a_token_exchange() {
        // Vertex has no model list, but minting is checkable.
        assert!(probe_is_worth_making("google_vertex", UpstreamTransport::GoogleVertex));
        // Bedrock publishes one.
        assert!(probe_is_worth_making("aws_bedrock", UpstreamTransport::AwsBedrock));
        // Entra: both reasons hold.
        assert!(probe_is_worth_making("azure_openai", UpstreamTransport::AzureOpenAiEntra));
        // A provider with no models endpoint on an ordinary transport: nothing
        // to check, and probing would surface a spurious 404.
        assert!(!probe_is_worth_making("perplexity", UpstreamTransport::Default));
        // …but a minting transport is still worth checking on such a provider.
        assert!(probe_is_worth_making("perplexity", UpstreamTransport::GoogleVertex));
    }
}

#[cfg(test)]
mod itl_target_tests {
    use super::{itl_target_columns, itl_target_of, MAX_ITL_TARGET_MS};
    use streamscope_core::proxy::adaptive_concurrency::ItlTarget;

    #[test]
    fn a_token_latency_target_reads_back_as_it_was_stored() {
        for target in [ItlTarget::Auto, ItlTarget::Off, ItlTarget::Fixed { ms: 1 }, ItlTarget::Fixed { ms: MAX_ITL_TARGET_MS }] {
            let (mode, ms) = itl_target_columns(target);
            assert_eq!(itl_target_of(mode, ms), target, "{mode} {ms:?}");
        }
        // Only a fixed target stores a figure.
        assert_eq!(itl_target_columns(ItlTarget::Auto), ("auto", None));
        assert_eq!(itl_target_columns(ItlTarget::Off), ("off", None));
        // A mode this build does not know, or the column's absence in a
        // projection, is the default.
        assert_eq!(itl_target_of("", None), ItlTarget::Auto);
        assert_eq!(itl_target_of("adaptive", Some(40)), ItlTarget::Auto);
        // The mode decides: a figure beside another mode is not a target, and
        // a fixed mode without one is the default.
        assert_eq!(itl_target_of("auto", Some(40)), ItlTarget::Auto);
        assert_eq!(itl_target_of("off", Some(40)), ItlTarget::Off);
        assert_eq!(itl_target_of("fixed", None), ItlTarget::Auto);
        assert_eq!(itl_target_of("fixed", Some(0)), ItlTarget::Auto);
    }
}

#[cfg(test)]
mod write_mask_tests {
    use super::{url_for_write, PatchServerRequest, WriteMask};
    use crate::routes::ApiErrorCode;

    /// A write that sets the URL must carry one (or the provider's default);
    /// a write that leaves it alone is never refused for the stored row
    /// lacking one — both sides of the mask.
    #[test]
    fn a_missing_url_is_refused_only_by_a_write_that_sets_it() {
        let err = url_for_write(true, None, "custom").unwrap_err();
        assert_eq!(err.code, ApiErrorCode::UpstreamUrlMissing);
        assert_eq!(url_for_write(false, None, "custom").unwrap(), "");
        // Positive control: a stated URL. (A provider default resolves from the
        // seed directory, which unit tests do not load.)
        assert_eq!(url_for_write(true, Some("http://vllm:8000".into()), "custom").unwrap(), "http://vllm:8000");
        assert!(url_for_write(true, Some("  ".into()), "custom").is_err());
    }

    /// A patch naming nothing but the fields listed, so each case states its
    /// own inputs rather than inheriting a neighbour's.
    fn patch() -> PatchServerRequest {
        PatchServerRequest {
            scheduling_dialect: None,
            max_in_flight: None,
            waiting_threshold: None,
            engine_metrics: None,
            adaptive_concurrency: None,
            adaptive_itl_target: None,
            clear_endpoint_bounds: false,
            name: None,
            provider: None,
            api_key: None,
            upstream_url: None,
            upstream_api_format: None,
            chat_endpoint_path: None,
            transport: None,
            auto_sync_enabled: None,
            enabled: None,
            force: None,
        }
    }

    #[test]
    fn switching_on_or_off_writes_no_column_so_nothing_is_probed() {
        assert!(WriteMask::for_patch(&PatchServerRequest { enabled: Some(false), ..patch() }).writes_nothing());
        // Any column write still counts, so it keeps its probe.
        assert!(!WriteMask::for_patch(&PatchServerRequest { name: Some("n".into()), ..patch() }).writes_nothing());
        assert!(!WriteMask::for_patch(&PatchServerRequest { api_key: Some("sk-x".into()), ..patch() }).writes_nothing());
    }

    #[test]
    fn a_rename_writes_only_the_name() {
        // The whole point of the mask. Before it, this patch rewrote all six
        // replaceable columns with values read a moment earlier, so a
        // concurrent edit to any of them was silently reverted.
        let m = WriteMask::for_patch(&PatchServerRequest {
            name: Some("new".into()),
            ..patch()
        });
        assert!(m.name);
        assert!(!m.provider);
        assert!(!m.upstream_url);
        assert!(!m.upstream_api_format);
        assert!(!m.chat_endpoint_path);
        assert!(!m.transport);
    }

    #[test]
    fn a_provider_change_rewrites_every_column_derived_from_it() {
        // The url, protocol and endpoint-path ladders all fall back to the
        // provider seed. Masking them out on a provider change would leave the
        // server pointing at the previous provider's URL.
        let m = WriteMask::for_patch(&PatchServerRequest {
            provider: Some("anthropic".into()),
            ..patch()
        });
        assert!(m.provider);
        assert!(m.upstream_url);
        assert!(m.upstream_api_format);
        assert!(m.chat_endpoint_path);
        assert!(m.transport);
        // Still not the name — a provider change is not a rename.
        assert!(!m.name);
    }

    #[test]
    fn transport_is_written_whenever_any_input_it_resolves_from_is() {
        // `resolve_transport` reads all of these together and is validated as
        // a whole, so writing half of what it resolved is how a server ends up
        // in a shape nothing ever accepted.
        for (label, p) in [
            ("url", PatchServerRequest { upstream_url: Some(Some("https://x".into())), ..patch() }),
            ("format", PatchServerRequest { upstream_api_format: Some("responses".into()), ..patch() }),
            ("endpoint", PatchServerRequest { chat_endpoint_path: Some(Some("/v1/x".into())), ..patch() }),
            ("key", PatchServerRequest { api_key: Some("sk-x".into()), ..patch() }),
            ("transport", PatchServerRequest { transport: Some("azure_openai".into()), ..patch() }),
        ] {
            assert!(
                WriteMask::for_patch(&p).transport,
                "a patch naming {label} left transport unwritten"
            );
        }
    }

    #[test]
    fn a_patch_that_names_nothing_writes_nothing() {
        // The positive control for the three above: if `for_patch` ever
        // returned all-true, every one of them would still pass.
        let m = WriteMask::for_patch(&patch());
        assert!(!m.name);
        assert!(!m.provider);
        assert!(!m.upstream_url);
        assert!(!m.upstream_api_format);
        assert!(!m.chat_endpoint_path);
        assert!(!m.transport);
    }
}

#[cfg(test)]
mod probe_credential_tests {
    use super::protocol_credential_headers;

    fn names(format: &str) -> Vec<&'static str> {
        protocol_credential_headers("k", format).into_iter().map(|(n, _)| n).collect()
    }

    /// The probe must present what `UpstreamClient::forward` presents.
    /// Anthropic is the strict case: its API requires `anthropic-version` and
    /// does not accept a bearer token, so a probe holding `Authorization` is
    /// refused by every correctly configured Anthropic server.
    #[test]
    fn an_anthropic_wire_is_authenticated_the_way_anthropic_authenticates() {
        assert_eq!(names("anthropic_messages"), vec!["x-api-key", "anthropic-version"]);
        // …and never as a bearer token, which that API rejects.
        assert!(!names("anthropic_messages").contains(&"Authorization"));
        let version = protocol_credential_headers("k", "anthropic_messages")
            .into_iter()
            .find(|(n, _)| *n == "anthropic-version")
            .map(|(_, v)| v);
        assert_eq!(version.as_deref(), Some(streamscope_core::proxy::client::ANTHROPIC_API_VERSION));
    }

    /// One case per protocol the header is decided from, so a new wire cannot
    /// silently inherit the bearer arm.
    #[test]
    fn every_other_wire_keeps_its_own_header() {
        assert_eq!(names("google_gemini"), vec!["x-goog-api-key"]);
        assert_eq!(names("chat_completions"), vec!["Authorization"]);
        assert_eq!(names("responses"), vec!["Authorization"]);
        assert_eq!(
            protocol_credential_headers("sk-1", "chat_completions"),
            vec![("Authorization", "Bearer sk-1".to_string())],
        );
        // The credential itself reaches the header for the non-bearer wires too.
        assert_eq!(
            protocol_credential_headers("sk-1", "google_gemini"),
            vec![("x-goog-api-key", "sk-1".to_string())],
        );
    }
}

#[cfg(test)]
mod probe_verdict_tests {
    use super::{probe_verdict, ProbeVerdict};

    /// The whole decision turns on whether a credential was presented, so both
    /// sides of that are asserted for each refusing status.
    #[test]
    fn a_refusal_is_a_rejected_credential_only_when_one_was_presented() {
        for status in [401, 403] {
            assert_eq!(
                probe_verdict(status, true),
                ProbeVerdict::CredentialRejected,
                "{status} with a key presented is the provider refusing that key"
            );
            assert_eq!(
                probe_verdict(status, false),
                ProbeVerdict::Reachable,
                "{status} with nothing presented only proves the path is right"
            );
        }
    }

    /// One case per class the probe can land in, and the boundaries of the
    /// success band on both sides.
    #[test]
    fn every_other_status_reads_the_same_with_or_without_a_credential() {
        for presented in [true, false] {
            assert_eq!(probe_verdict(200, presented), ProbeVerdict::Reachable);
            assert_eq!(probe_verdict(299, presented), ProbeVerdict::Reachable);
            // Just outside the success band on either side.
            assert_eq!(probe_verdict(199, presented), ProbeVerdict::Unreachable);
            assert_eq!(probe_verdict(300, presented), ProbeVerdict::Unreachable);
            // The wrong path, and an upstream that is failing.
            assert_eq!(probe_verdict(404, presented), ProbeVerdict::Unreachable);
            assert_eq!(probe_verdict(500, presented), ProbeVerdict::Unreachable);
            // A neighbour of the refusing pair, which is NOT about credentials.
            assert_eq!(probe_verdict(402, presented), ProbeVerdict::Unreachable);
            assert_eq!(probe_verdict(429, presented), ProbeVerdict::Unreachable);
        }
    }
}

/// Mirror-sync `server_id`'s downstream routes under a savepoint of `tx`, best
/// effort: a failure (a NameConflict, or a statement error) undoes only the
/// mirror's own writes and is logged, so the caller's writes still commit.
/// Without the savepoint a failed statement would abort `tx`, and its COMMIT
/// would roll back everything. `Ok(None)` is a logged failure.
async fn mirror_sync_best_effort(
    tx: &mut Scoped,
    server_id: Uuid,
    server_name: &str,
    tenant_id: Uuid,
) -> Result<Option<super::downstream::MirrorSyncResult>, sqlx::Error> {
    let mut sp = tx.begin().await?;
    match super::downstream::mirror_sync_downstream(&mut sp, server_id, server_name, tenant_id).await {
        Ok(result) => {
            sp.commit().await?;
            Ok(Some(result))
        }
        Err(e) => {
            sp.rollback().await?;
            tracing::warn!(%server_id, error = %e.reason(), "mirror sync failed for server '{server_name}'");
            Ok(None)
        }
    }
}

#[cfg(test)]
mod anthropic_pagination_tests {
    use super::{anthropic_next_cursor, gemini_next_page, NextPage};
    use serde_json::json;

    fn cursor(next: NextPage) -> Option<String> {
        match next {
            NextPage::Cursor(c) => Some(c),
            _ => None,
        }
    }

    /// The only shape that names a next page, and the boundary on each field
    /// that decides it.
    #[test]
    fn only_a_named_next_page_continues_the_walk() {
        assert_eq!(
            anthropic_next_cursor(&json!({ "data": [], "has_more": true, "last_id": "m2" }), None),
            NextPage::Cursor("m2".to_string()),
        );
        // …and from a page reached by a different cursor.
        assert_eq!(
            anthropic_next_cursor(&json!({ "data": [], "has_more": true, "last_id": "m4" }), Some("m2")),
            NextPage::Cursor("m4".to_string()),
        );
        // `last_id` rides the final page too, so `has_more` alone ends it.
        assert_eq!(
            anthropic_next_cursor(&json!({ "data": [], "has_more": false, "last_id": "m2" }), None),
            NextPage::Done,
        );
        // More pages claimed but no cursor to reach them. NOT `Done`: handing
        // back what was read would be a short list the plausibility gate lets
        // through, and the models it did not see would be retired.
        assert_eq!(
            anthropic_next_cursor(&json!({ "data": [], "has_more": true }), None),
            NextPage::Stranded,
        );
        assert_eq!(
            anthropic_next_cursor(&json!({ "data": [], "has_more": true, "last_id": "" }), None),
            NextPage::Stranded,
        );
        assert_eq!(
            anthropic_next_cursor(&json!({ "data": [], "has_more": true, "last_id": null }), None),
            NextPage::Stranded,
        );
    }

    /// The same hazard wearing its other face: an upstream that keeps handing
    /// back the cursor we just used would have the walk merge one page fifty
    /// times over.
    #[test]
    fn a_cursor_that_does_not_advance_ends_the_walk() {
        assert_eq!(
            anthropic_next_cursor(&json!({ "data": [], "has_more": true, "last_id": "m2" }), Some("m2")),
            NextPage::Stranded,
        );
        // Positive control: the same body advances when it is the FIRST page,
        // so this rule cannot be satisfied by refusing every cursor.
        assert_eq!(
            anthropic_next_cursor(&json!({ "data": [], "has_more": true, "last_id": "m2" }), Some("m1")),
            NextPage::Cursor("m2".to_string()),
        );
    }

    /// Gemini ends its listing by OMITTING the token, so absence is `Done` —
    /// but a token that does not advance strands the walk exactly as
    /// Anthropic's does, and must not be read as the end of the list.
    #[test]
    fn gemini_ends_on_an_absent_token_and_strands_on_a_repeated_one() {
        assert_eq!(gemini_next_page(&json!({ "models": [] }), None), NextPage::Done);
        assert_eq!(
            gemini_next_page(&json!({ "models": [], "nextPageToken": "" }), None),
            NextPage::Done,
        );
        assert_eq!(
            gemini_next_page(&json!({ "models": [], "nextPageToken": "p2" }), None),
            NextPage::Cursor("p2".to_string()),
        );
        assert_eq!(
            gemini_next_page(&json!({ "models": [], "nextPageToken": "p2" }), Some("p2")),
            NextPage::Stranded,
        );
        // Positive control: the same token advances from a different page.
        assert_eq!(
            cursor(gemini_next_page(&json!({ "models": [], "nextPageToken": "p2" }), Some("p1"))),
            Some("p2".to_string()),
        );
    }

    /// A body that answers the question in some other vocabulary is not read as
    /// "keep going" — every unknown shape ends the walk.
    #[test]
    fn an_unrecognised_shape_ends_the_walk() {
        assert_eq!(anthropic_next_cursor(&json!({ "data": [] }), None), NextPage::Done);
        assert_eq!(anthropic_next_cursor(&json!({}), None), NextPage::Done);
        // A truthy non-boolean is not `true`, so it claims no further page.
        assert_eq!(
            anthropic_next_cursor(&json!({ "has_more": "true", "last_id": "m2" }), None),
            NextPage::Done,
        );
        assert_eq!(
            anthropic_next_cursor(&json!({ "has_more": 1, "last_id": "m2" }), None),
            NextPage::Done,
        );
        // …but a cursor that is not a string, beside a real claim of more
        // pages, is a page we cannot reach rather than the end of the list.
        assert_eq!(
            anthropic_next_cursor(&json!({ "has_more": true, "last_id": 7 }), None),
            NextPage::Stranded,
        );
    }
}

#[cfg(test)]
mod probe_summary_tests {
    use super::summarize_probe_body;

    /// The summary is stored in a sync status or an audit row, where Postgres
    /// refuses U+0000.
    #[test]
    fn a_summarised_body_carries_no_nul() {
        assert_eq!(summarize_probe_body("{\"error\":\"bad\u{0}key\"}"), "{\"error\":\"bad\u{FFFD}key\"}");
        assert_eq!(summarize_probe_body("plain error"), "plain error");
    }
}
