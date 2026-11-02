//! Backend dispatch — one struct per provider, an enum that fans out.
//!
//! Backends are stateless: they hold the configured endpoint + credential and
//! perform the upstream HTTP call when invoked. The shared
//! [`crate::web::service`] layer handles policy, filtering, and audit.

use crate::web::providers::searxng::SearxngBackend;
use crate::web::settings::WebSettings;
use crate::web::types::{
    SearchRequest, SearchResult, WebError, WebProvider,
};

/// Constructed-from-settings backend. Cheap to build per-request.
#[derive(Debug, Clone)]
pub enum Backend {
    Searxng(SearxngBackend),
    // Brave/Tavily/GoogleCse/Serper land in phase 2.
}

impl Backend {
    /// Build the configured backend from tenant settings + decrypted
    /// credential. Returns [`WebError::NoBackend`] if unconfigured,
    /// [`WebError::MissingCredential`] when a paid backend lacks one.
    ///
    /// `credential` is the per-tenant decrypted API key (None for SearXNG).
    pub fn from_settings(
        settings: &WebSettings,
        credential: Option<&str>,
    ) -> Result<Self, WebError> {
        let Some(provider) = settings.backend else {
            return Err(WebError::NoBackend);
        };
        if provider.requires_credential() && credential.is_none() {
            return Err(WebError::MissingCredential { backend: provider });
        }
        match provider {
            WebProvider::Searxng => Ok(Self::Searxng(SearxngBackend::new(
                settings.endpoint.clone(),
            )?)),
            WebProvider::Brave
            | WebProvider::Tavily
            | WebProvider::GoogleCse
            | WebProvider::Serper => Err(WebError::InvalidConfig(format!(
                "paid backend `{provider}` is not yet implemented — configure `searxng` instead"
            ))),
        }
    }

    pub fn provider(&self) -> WebProvider {
        match self {
            Self::Searxng(_) => WebProvider::Searxng,
        }
    }

    /// Run a search call against the upstream provider. Returns the post-
    /// provider, pre-filter result.
    ///
    /// `(provider_request, provider_response, latency_ms, status)` are
    /// captured into the audit row by the caller.
    pub async fn search(
        &self,
        clients: &crate::extension_http::ExtensionClients,
        req: &SearchRequest,
    ) -> Result<BackendSearchOutcome, WebError> {
        match self {
            Self::Searxng(b) => b.search(clients, req).await,
        }
    }
}

/// What a backend returns to the service layer. Carries enough metadata for
/// `web_audit` to capture provider request + raw response.
#[derive(Debug, Clone)]
pub struct BackendSearchOutcome {
    pub result: SearchResult,
    /// Verbatim provider request payload (URL+query for GET-style backends,
    /// JSON body for POST-style). Credentials redacted before storage by the
    /// provider impl.
    pub provider_request: serde_json::Value,
    /// Verbatim raw provider response body. Capped at the audit layer.
    pub provider_response: serde_json::Value,
    pub upstream_latency_ms: u64,
    pub upstream_status: u16,
    pub bytes_in: u64,
    pub bytes_out: u64,
}
