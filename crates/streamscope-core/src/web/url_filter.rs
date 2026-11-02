//! URL-filter chain — a single hookpoint applied to every URL the system
//! considers (search hits + fetch targets), shared by both the MCP virtual
//! server and the v2 substitution surface.
//!
//! Built-in filters live in [`super::filters`]. External hooks
//! (operator-supplied HTTP filter services) plug in via the
//! `ExternalHttpFilter` adapter introduced in phase 2.
//!
//! ## Failure mode
//!
//! Phase 1 hardcodes asymmetric defaults at the call site
//! ([`super::service`]):
//!
//! - **Search**: `fail_open = true`. A filter timeout / error treats the
//!   verdict as `Allow` so a hung policy server can't silently empty the
//!   model's search results.
//! - **Fetch**: `fail_open = false`. A filter failure is a `Deny` with
//!   reason `"filter_chain_failed"` — fetch is the more dangerous side, so
//!   it fails closed.
//!
//! Tenant-tunable `web_search.filter_fail_mode_*` settings land in phase 2
//! together with the external HTTP filter adapter.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;
use utoipa::ToSchema;

/// Whether a single URL may proceed through the pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum FilterVerdict {
    Allow,
    Deny { reason: String },
}

/// Recoverable errors a filter may raise. Surface to the chain runner which
/// applies the configured fail-mode.
#[derive(Debug, Error)]
pub enum FilterError {
    #[error("filter `{filter_id}` timed out after {timeout_ms}ms")]
    Timeout {
        filter_id: &'static str,
        timeout_ms: u64,
    },
    #[error("filter `{filter_id}` errored: {detail}")]
    Errored {
        filter_id: &'static str,
        detail: String,
    },
}

/// Carrier passed to each filter so external implementations can correlate
/// audit and policy data.
#[derive(Debug, Clone, Default)]
pub struct FilterContext {
    /// `"search"` or `"fetch"` — context about what triggered the URL check.
    pub operation: &'static str,
    /// Tenant id; useful for external HTTP filters that need to scope.
    pub tenant_id: Option<uuid::Uuid>,
    /// User id; same.
    pub user_id: Option<uuid::Uuid>,
}

/// Pluggable URL-filter contract. Implementors are stored as
/// `Arc<dyn UrlFilter>` in [`FilterChain`].
pub trait UrlFilter: Send + Sync {
    /// Stable identifier used in audit (`filter_chain[].id` and
    /// `url_results[].filter_id`). MUST be append-only — the admin UI joins
    /// on this string.
    fn id(&self) -> &'static str;

    /// Async evaluation. Returns `Allow` to pass the URL through, `Deny`
    /// (with operator-readable reason) to drop it. Recoverable failures
    /// surface as [`FilterError`] so the chain runner can apply fail-mode.
    fn evaluate<'a>(
        &'a self,
        url: &'a Url,
        ctx: &'a FilterContext,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<FilterVerdict, FilterError>>
                + Send
                + 'a,
        >,
    >;
}

/// Audit record for one URL evaluation: every URL the system *considered*
/// (allowed + denied), with which filter ruled on it.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UrlVerdictRecord {
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Snake-case verdict tag — `"allow"` or `"deny"`.
    pub verdict: String,
    /// `id()` of the filter that produced the deny verdict; `None` when
    /// allowed (no filter denied).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter_id: Option<&'static str>,
    /// Operator-readable reason from the deny variant; `None` when allowed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Ordered chain of [`UrlFilter`]s. First-deny-wins: a chain returns the
/// first `Deny` verdict and short-circuits the rest.
#[derive(Clone, Default)]
pub struct FilterChain {
    filters: Vec<Arc<dyn UrlFilter>>,
}

impl FilterChain {
    pub fn new(filters: Vec<Arc<dyn UrlFilter>>) -> Self {
        Self { filters }
    }

    pub fn is_empty(&self) -> bool {
        self.filters.is_empty()
    }

    pub fn ids(&self) -> Vec<&'static str> {
        self.filters.iter().map(|f| f.id()).collect()
    }

    /// Run the chain against a single URL. The result is suitable for direct
    /// inclusion in `web_audit.url_results`.
    ///
    /// `fail_open` controls the recovery semantic on filter error: `true`
    /// → treat as Allow (used for search by default); `false` → treat as
    /// Deny with reason `"filter_chain_failed"` (default for fetch).
    pub async fn evaluate(
        &self,
        url: &Url,
        ctx: &FilterContext,
        fail_open: bool,
    ) -> FilterVerdict {
        for f in &self.filters {
            match f.evaluate(url, ctx).await {
                Ok(FilterVerdict::Allow) => continue,
                Ok(deny @ FilterVerdict::Deny { .. }) => return deny,
                Err(e) => {
                    if fail_open {
                        tracing::warn!(filter_id = f.id(), "filter failed open: {e}");
                        continue;
                    } else {
                        tracing::warn!(filter_id = f.id(), "filter failed closed: {e}");
                        return FilterVerdict::Deny {
                            reason: format!("filter_chain_failed: {e}"),
                        };
                    }
                }
            }
        }
        FilterVerdict::Allow
    }
}

impl std::fmt::Debug for FilterChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FilterChain")
            .field("filters", &self.ids())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    struct AlwaysAllow;
    impl UrlFilter for AlwaysAllow {
        fn id(&self) -> &'static str {
            "always_allow"
        }
        fn evaluate<'a>(
            &'a self,
            _url: &'a Url,
            _ctx: &'a FilterContext,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<FilterVerdict, FilterError>> + Send + 'a>,
        > {
            Box::pin(async move { Ok(FilterVerdict::Allow) })
        }
    }

    struct AlwaysDeny(&'static str);
    impl UrlFilter for AlwaysDeny {
        fn id(&self) -> &'static str {
            "always_deny"
        }
        fn evaluate<'a>(
            &'a self,
            _url: &'a Url,
            _ctx: &'a FilterContext,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<FilterVerdict, FilterError>> + Send + 'a>,
        > {
            let reason = self.0.to_string();
            Box::pin(async move {
                Ok(FilterVerdict::Deny { reason })
            })
        }
    }

    struct AlwaysErr;
    impl UrlFilter for AlwaysErr {
        fn id(&self) -> &'static str {
            "always_err"
        }
        fn evaluate<'a>(
            &'a self,
            _url: &'a Url,
            _ctx: &'a FilterContext,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<FilterVerdict, FilterError>> + Send + 'a>,
        > {
            Box::pin(async move {
                Err(FilterError::Errored {
                    filter_id: "always_err",
                    detail: "boom".into(),
                })
            })
        }
    }

    fn url() -> Url {
        Url::parse("https://example.com").unwrap()
    }

    #[tokio::test]
    async fn empty_chain_allows() {
        let chain = FilterChain::default();
        let v = chain.evaluate(&url(), &FilterContext::default(), true).await;
        assert_matches!(v, FilterVerdict::Allow);
    }

    #[tokio::test]
    async fn first_deny_wins() {
        let chain = FilterChain::new(vec![
            Arc::new(AlwaysAllow),
            Arc::new(AlwaysDeny("nope")),
            // Should not be reached.
            Arc::new(AlwaysErr),
        ]);
        let v = chain.evaluate(&url(), &FilterContext::default(), true).await;
        match v {
            FilterVerdict::Deny { reason } => assert_eq!(reason, "nope"),
            v => panic!("expected deny, got {v:?}"),
        }
    }

    #[tokio::test]
    async fn fail_open_skips_errors() {
        let chain = FilterChain::new(vec![Arc::new(AlwaysErr), Arc::new(AlwaysAllow)]);
        let v = chain.evaluate(&url(), &FilterContext::default(), true).await;
        assert_matches!(v, FilterVerdict::Allow);
    }

    #[tokio::test]
    async fn fail_closed_denies_on_error() {
        let chain = FilterChain::new(vec![Arc::new(AlwaysErr)]);
        let v = chain.evaluate(&url(), &FilterContext::default(), false).await;
        match v {
            FilterVerdict::Deny { reason } => assert!(reason.contains("filter_chain_failed")),
            v => panic!("expected deny, got {v:?}"),
        }
    }
}
