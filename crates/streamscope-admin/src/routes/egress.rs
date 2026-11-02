//! Platform internal-egress allowlists — `GET / PATCH
//! /api/v1/admin/global/egress`, the SYSTEM super-admin's Egress page.
//!
//! One list per outbound surface: which private destinations it may reach.
//! Public destinations always pass and the cloud metadata endpoint never does,
//! whatever a list says. A write applies on admin-api at once (this replica)
//! or within a second (the others), and on every gateway through config sync —
//! no restart.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::{Extension, Json, extract::State};
use serde::{Deserialize, Serialize};
use streamscope_mcp_auth::egress::{Allowlist, Surface};
use utoipa::ToSchema;

use crate::AdminState;
use crate::db::Global;
use crate::db::tenant::AdminTenantCtx;
use crate::routes::{ApiError, ApiErrorCode, ApiErrorResponse};

/// Every surface's list. An entry is `*` (every private address), an IP
/// address, a CIDR prefix (`10.0.0.0/8`) or a host name (that exact name);
/// an empty list reaches no private address.
#[derive(Serialize, ToSchema, Clone, Debug, PartialEq, Default)]
pub struct EgressSettings {
    /// LLM providers: gateway requests, liveness probes, model discovery,
    /// replica endpoints, engine gauges.
    pub llm: Vec<String>,
    /// MCP upstream servers and their OAuth discovery.
    pub mcp: Vec<String>,
    /// A2A upstream agents and their cards.
    pub a2a: Vec<String>,
    /// OpenID Connect identity providers.
    pub oidc: Vec<String>,
    /// The built-in web tool's fetches (URLs an end user or a model supplies).
    pub web: Vec<String>,
    /// OAuth client metadata documents a client advertises (CIMD) — reachable
    /// from the unauthenticated registration endpoint.
    pub cimd: Vec<String>,
    /// Upstream token endpoints a minting transport exchanges its credential at.
    pub upstream_token: Vec<String>,
    /// The extension endpoints a tenant sets: the web search backend and the
    /// guardrail classifier.
    pub extensions: Vec<String>,
}

/// `PATCH /api/v1/admin/global/egress` — absent leaves a list, `null` or `[]`
/// empties it, a list replaces it.
#[derive(Deserialize, ToSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct UpdateEgressSettings {
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<Vec<String>>)]
    pub llm: Option<Option<Vec<String>>>,
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<Vec<String>>)]
    pub mcp: Option<Option<Vec<String>>>,
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<Vec<String>>)]
    pub a2a: Option<Option<Vec<String>>>,
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<Vec<String>>)]
    pub oidc: Option<Option<Vec<String>>>,
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<Vec<String>>)]
    pub web: Option<Option<Vec<String>>>,
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<Vec<String>>)]
    pub cimd: Option<Option<Vec<String>>>,
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<Vec<String>>)]
    pub upstream_token: Option<Option<Vec<String>>>,
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<Vec<String>>)]
    pub extensions: Option<Option<Vec<String>>>,
}

impl UpdateEgressSettings {
    /// The surfaces this patch names, with the list each gets (empty = none).
    fn changes(self) -> Vec<(Surface, Vec<String>)> {
        [
            (Surface::Llm, self.llm),
            (Surface::Mcp, self.mcp),
            (Surface::A2a, self.a2a),
            (Surface::Oidc, self.oidc),
            (Surface::Web, self.web),
            (Surface::Cimd, self.cimd),
            (Surface::UpstreamToken, self.upstream_token),
            (Surface::Extensions, self.extensions),
        ]
        .into_iter()
        .filter_map(|(surface, change)| change.map(|list| (surface, list.unwrap_or_default())))
        .collect()
    }
}

impl EgressSettings {
    fn from_map(mut map: BTreeMap<String, Vec<String>>) -> Self {
        let mut take = |s: Surface| map.remove(s.as_str()).unwrap_or_default();
        EgressSettings {
            llm: take(Surface::Llm),
            mcp: take(Surface::Mcp),
            a2a: take(Surface::A2a),
            oidc: take(Surface::Oidc),
            web: take(Surface::Web),
            cimd: take(Surface::Cimd),
            upstream_token: take(Surface::UpstreamToken),
            extensions: take(Surface::Extensions),
        }
    }
}

/// A list as stored: each entry trimmed, blanks and repeats dropped, in the
/// order given; every entry must parse, or the whole write is refused naming
/// the first that does not.
fn normalise(surface: Surface, list: Vec<String>) -> Result<Vec<String>, ApiError> {
    let mut out: Vec<String> = Vec::new();
    for entry in list {
        let entry = entry.trim().to_string();
        if entry.is_empty() || out.contains(&entry) {
            continue;
        }
        Allowlist::parse(std::slice::from_ref(&entry)).map_err(|e| {
            ApiError::bad_request(format!("{}: {e}", surface.as_str())).code(ApiErrorCode::EgressEntryInvalid)
        })?;
        out.push(entry);
    }
    Ok(out)
}

async fn current(state: &AdminState) -> Result<EgressSettings, ApiError> {
    crate::egress::read(&state.db).await.map(EgressSettings::from_map).map_err(|e| {
        tracing::error!("egress: read: {e}");
        ApiError::internal("failed to read the egress lists")
    })
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/global/egress",
    tag = "Settings",
    responses(
        (status = 200, description = "Every surface's internal-egress allowlist", body = EgressSettings),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 403, description = "Super-admin only", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_egress(State(state): State<Arc<AdminState>>) -> Result<Json<EgressSettings>, ApiError> {
    current(&state).await.map(Json)
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/global/egress",
    tag = "Settings",
    request_body = UpdateEgressSettings,
    responses(
        (status = 200, description = "The lists after the change", body = EgressSettings),
        (status = 400, description = "An entry is not `*`, an IP address, a CIDR prefix or a host name", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 403, description = "Super-admin only", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn patch_egress(
    State(state): State<Arc<AdminState>>,
    Extension(ctx): Extension<AdminTenantCtx>,
    Extension(audit_sink): Extension<crate::middleware::AuditDiffSink>,
    Json(body): Json<UpdateEgressSettings>,
) -> Result<Json<EgressSettings>, ApiError> {
    let changes = body
        .changes()
        .into_iter()
        .map(|(surface, list)| normalise(surface, list).map(|list| (surface, list)))
        .collect::<Result<Vec<_>, _>>()?;
    // One transaction: a list half-written would ship to the gateways. The
    // lists the audit diff starts from are read in it, so two concurrent
    // writes each record what they replaced.
    let mut tx = state.db.begin_global(Global::Infra).await.map_err(|e| {
        tracing::error!("egress: begin transaction: {e}");
        ApiError::internal("failed to save the egress lists")
    })?;
    // One write at a time — a row lock cannot serialise writes to a surface
    // that has no row yet.
    sqlx::query("SELECT pg_advisory_xact_lock(737012)").execute(&mut *tx).await.map_err(|e| {
        tracing::error!("egress: lock: {e}");
        ApiError::internal("failed to save the egress lists")
    })?;
    let rows: Vec<(String, Vec<String>)> =
        sqlx::query_as("SELECT surface, entries FROM platform_egress ORDER BY surface")
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!("egress: read: {e}");
                ApiError::internal("failed to read the egress lists")
            })?;
    let before = EgressSettings::from_map(rows.into_iter().collect());
    for (surface, list) in &changes {
        let result = if list.is_empty() {
            sqlx::query("DELETE FROM platform_egress WHERE surface = $1")
                .bind(surface.as_str())
                .execute(&mut *tx)
                .await
        } else {
            sqlx::query(
                "INSERT INTO platform_egress (surface, entries, updated_at, updated_by)
                 VALUES ($1, $2, now(), $3)
                 ON CONFLICT (surface)
                 DO UPDATE SET entries = EXCLUDED.entries, updated_at = now(), updated_by = EXCLUDED.updated_by
                 WHERE platform_egress.entries IS DISTINCT FROM EXCLUDED.entries",
            )
            .bind(surface.as_str())
            .bind(list)
            .bind(ctx.admin_account_id)
            .execute(&mut *tx)
            .await
        };
        result.map_err(|e| {
            tracing::error!("egress: save {}: {e}", surface.as_str());
            ApiError::internal("failed to save the egress lists")
        })?;
    }
    // The lists after the change, read in the same transaction: the diff is
    // this write's alone, whatever commits beside it.
    let rows: Vec<(String, Vec<String>)> =
        sqlx::query_as("SELECT surface, entries FROM platform_egress ORDER BY surface")
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!("egress: read: {e}");
                ApiError::internal("failed to read the egress lists")
            })?;
    let after = EgressSettings::from_map(rows.into_iter().collect());
    tx.commit().await.map_err(|e| {
        tracing::error!("egress: commit: {e}");
        ApiError::internal("failed to save the egress lists")
    })?;

    // The write is recorded whatever happens next: it is committed.
    audit_sink.record(Some(&before), Some(&after));
    // This replica applies the lists before answering, so a call it serves
    // next sees them; the others within a second.
    if crate::egress::refresh(&state.db).await.is_err() {
        // Saved, and on its way to every gateway; this replica applies it on
        // its next successful refresh. Said, rather than answered as applied.
        return Err(ApiError::internal(
            "the lists were saved but could not be applied here yet: they apply within seconds once the database answers",
        ));
    }
    Ok(Json(after))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_patch_names_only_the_surfaces_it_carries() {
        let p: UpdateEgressSettings =
            serde_json::from_str(r#"{"mcp":["10.0.0.0/8"],"oidc":null,"web":[]}"#).unwrap();
        let changes = p.changes();
        assert_eq!(
            changes,
            vec![
                (Surface::Mcp, vec!["10.0.0.0/8".to_string()]),
                (Surface::Oidc, vec![]),
                (Surface::Web, vec![]),
            ]
        );
    }

    #[test]
    fn an_unknown_surface_is_refused() {
        assert!(serde_json::from_str::<UpdateEgressSettings>(r#"{"ldap":["*"]}"#).is_err());
    }

    #[test]
    fn a_list_is_trimmed_deduplicated_and_every_entry_must_parse() {
        assert_eq!(
            normalise(Surface::Llm, vec![" vllm.lan ".into(), "".into(), "vllm.lan".into(), "10.1.0.0/16".into()])
                .unwrap(),
            vec!["vllm.lan".to_string(), "10.1.0.0/16".to_string()]
        );
        assert!(normalise(Surface::Llm, vec!["vllm.lan".into(), "http://vllm.lan".into()]).is_err());
    }
}
