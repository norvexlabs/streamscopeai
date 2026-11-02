//! Per-tenant accounting settings.
//!
//! - `GET  /api/v1/admin/settings/pricing` — the currency the tenant keeps its
//!   books in, the operator's conversion table, and the set of currencies the
//!   tenant's own models are actually priced in.
//! - `PATCH  /api/v1/admin/settings/pricing` — partial update of the tenant's
//!   `system_settings.pricing` JSON.
//!
//! Every budget cap, spend aggregate and audit total is expressed in the
//! accounting currency. A model quoted in another currency is converted at
//! request time and the rate used is stamped on the row, so a later edit to the
//! table cannot restate spend that has already been reported.
//!
//! The table is operator-maintained and never fetched: an air-gapped deployment
//! is a supported shape, and a rate that moved on its own would make last
//! month's figures move with it. A pair with no configured rate leaves the
//! charge unstated and badged rather than converted at a guess — which is why
//! the GET reports `currencies_in_use`, so configuring the table is a checklist
//! rather than guesswork.

use std::collections::{BTreeMap, BTreeSet};

use axum::Json;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use streamscope_core::pricing::{Currency, FxTable, PricingSettings};
use utoipa::ToSchema;

use super::{ApiError, ApiErrorResponse};
use crate::db::tenant::{Scoped, TenantConn};

const PRICING_SETTINGS_KEY: &str = "pricing";

// ---------------------------------------------------------------------------
// Wire shapes
// ---------------------------------------------------------------------------

/// Response for `GET`/`PATCH /api/v1/admin/settings/pricing`.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PricingSettingsResponse {
    /// Currency every budget cap, spend figure and audit total is expressed in.
    pub accounting_currency: String,
    /// Operator-maintained conversion rates, `{from: {to: multiplier}}`. A pair
    /// configured in one direction serves both — the inverse is exact.
    pub fx: BTreeMap<String, BTreeMap<String, f64>>,
    /// Currencies this tenant's own models are priced in, from its catalog and
    /// its per-model overrides. Any entry other than `accounting_currency` needs
    /// a rate, or requests against those models record no spend.
    pub currencies_in_use: Vec<String>,
    /// Currencies from `currencies_in_use` that cannot currently be converted
    /// into the accounting currency. Non-empty means some traffic is being
    /// billed as unstated and badged.
    pub unconvertible: Vec<String>,
}

/// Body for `PATCH /api/v1/admin/settings/pricing`. Both fields are optional;
/// `fx` replaces the table wholesale, because an operator edits a rate table as
/// one document and a per-pair merge would leave stale pairs behind invisibly.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
#[serde(default)]
pub struct UpdatePricingSettingsRequest {
    /// Three-letter ISO 4217 code, case-insensitive.
    pub accounting_currency: Option<String>,
    /// `{from: {to: multiplier}}`.
    pub fx: Option<BTreeMap<String, BTreeMap<String, f64>>>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/api/v1/admin/settings/pricing",
    tag = "Pricing",
    responses(
        (status = 200, description = "Current accounting settings", body = PricingSettingsResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_pricing_settings(
    mut db: TenantConn,
) -> Result<Json<PricingSettingsResponse>, ApiError> {
    let settings = load_settings(db.conn()).await?;
    let in_use = currencies_in_use(db.conn()).await?;
    Ok(Json(build_response(settings, in_use)))
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/settings/pricing",
    tag = "Pricing",
    request_body = UpdatePricingSettingsRequest,
    responses(
        (status = 200, description = "Updated settings", body = PricingSettingsResponse),
        (status = 400, description = "Invalid currency or rate", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_pricing_settings(
    mut db: TenantConn,
    axum::Extension(audit_sink): axum::Extension<crate::middleware::AuditDiffSink>,
    Json(body): Json<UpdatePricingSettingsRequest>,
) -> Result<Json<PricingSettingsResponse>, ApiError> {
    let tenant_id = db.tenant_uuid();

    // Validate before writing: a currency we cannot name must not be stored,
    // because everything downstream would then have to decide what to do with
    // it, and the only safe answer at that point is to stop billing.
    let mut patch = serde_json::Map::new();
    if let Some(code) = body.accounting_currency.as_deref() {
        let parsed = Currency::parse(code).ok_or_else(|| {
            ApiError::bad_request(
                "accounting_currency must be a three-letter ISO 4217 code, e.g. USD or EUR",
            )
        })?;
        patch.insert(
            "accounting_currency".to_string(),
            serde_json::Value::String(parsed.as_str().to_string()),
        );
    }
    if let Some(raw) = body.fx.as_ref() {
        let (table, rejected) = FxTable::from_map(raw);
        if !rejected.is_empty() {
            return Err(ApiError::bad_request(format!(
                "conversion table rejected: {} — each side must be a three-letter \
                 ISO 4217 code and each rate a positive number",
                rejected.join(", ")
            )));
        }
        patch.insert(
            "fx".to_string(),
            serde_json::to_value(&table).map_err(|e| {
                tracing::error!("serialize fx table: {e}");
                ApiError::internal("failed to update settings")
            })?,
        );
    }
    let patch = serde_json::Value::Object(patch);
    let base = super::default_merged::<PricingSettings>(&patch);

    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("begin pricing settings tx: {e}");
        ApiError::internal("failed to update settings")
    })?;
    let (old, new) =
        super::merge_settings_blob(&mut tx, PRICING_SETTINGS_KEY, tenant_id, &base, &patch).await?;
    let current: PricingSettings = serde_json::from_value(new).map_err(|e| {
        tracing::error!("deserialize merged pricing settings: {e}");
        ApiError::internal("failed to update settings")
    })?;

    let before: PricingSettings =
        old.and_then(|v| serde_json::from_value(v).ok()).unwrap_or_default();

    // Changing the ledger's currency changes what the spend counters COUNT. The
    // open day and month windows hold amounts in the previous currency, and
    // adding the next request's amount to them would sum two different units
    // into one number that means neither. Dropping the running totals restarts
    // both windows at zero in the new currency; the per-edge watermarks are
    // untouched, so the next report contributes only traffic since the change
    // rather than replaying the window.
    if before.accounting_currency != current.accounting_currency {
        sqlx::query("DELETE FROM usage_counters WHERE tenant_id = $1 AND metric = $2")
            .bind(tenant_id)
            .bind(streamscope_core::usage::UsageMetric::BudgetMicros.as_str())
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!("reset budget counters on currency change: {e}");
                ApiError::internal("failed to update settings")
            })?;
        tracing::info!(
            tenant_id = %tenant_id,
            from = %before.accounting_currency,
            to = %current.accounting_currency,
            "accounting currency changed; open budget windows restart at zero"
        );
    }

    tx.commit().await.map_err(|e| {
        tracing::error!("commit pricing settings tx: {e}");
        ApiError::internal("failed to update settings")
    })?;

    audit_sink.record(Some(&before), Some(&current));

    let in_use = currencies_in_use(db.conn()).await?;
    Ok(Json(build_response(current, in_use)))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn build_response(settings: PricingSettings, in_use: Vec<String>) -> PricingSettingsResponse {
    let unconvertible = in_use
        .iter()
        .filter(|code| {
            Currency::parse(code)
                .is_none_or(|c| settings.fx.rate(c, settings.accounting_currency).is_none())
        })
        .cloned()
        .collect();
    PricingSettingsResponse {
        accounting_currency: settings.accounting_currency.as_str().to_string(),
        fx: settings.fx.as_map().clone(),
        currencies_in_use: in_use,
        unconvertible,
    }
}

/// The tenant's accounting currency, for surfaces that only need to label a
/// figure. Falls back to the default on any read failure — a notification is
/// worth sending with a possibly-wrong label, and never worth dropping.
pub(crate) async fn accounting_currency(conn: &mut Scoped) -> Currency {
    load_settings(conn)
        .await
        .map(|s| s.accounting_currency)
        .unwrap_or_default()
}

async fn load_settings(conn: &mut Scoped) -> Result<PricingSettings, ApiError> {
    let raw: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT value FROM system_settings WHERE key = $1")
            .bind(PRICING_SETTINGS_KEY)
            .fetch_optional(&mut *conn)
            .await
            .map_err(|e| {
                tracing::error!("load pricing settings: {e}");
                ApiError::internal("failed to load settings")
            })?;
    Ok(raw
        .and_then(|v| serde_json::from_value::<PricingSettings>(v).ok())
        .unwrap_or_default())
}

/// Currencies the tenant's own models quote, across both the catalog and the
/// per-model overrides. RLS confines both reads to this tenant.
async fn currencies_in_use(conn: &mut Scoped) -> Result<Vec<String>, ApiError> {
    let rows = sqlx::query(
        "SELECT DISTINCT c FROM (
             SELECT rates->>'currency' AS c FROM model_catalog
              WHERE NOT suppressed AND rates -> 'units' <> '{}'::jsonb
             UNION ALL
             SELECT rates->>'currency' AS c FROM upstream_models
              WHERE rates IS NOT NULL AND rates -> 'units' <> '{}'::jsonb
         ) s WHERE c IS NOT NULL ORDER BY c",
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("scan model currencies: {e}");
        ApiError::internal("failed to load settings")
    })?;
    let set: BTreeSet<String> = rows.into_iter().filter_map(|r| r.try_get(0).ok()).collect();
    Ok(set.into_iter().collect())
}
