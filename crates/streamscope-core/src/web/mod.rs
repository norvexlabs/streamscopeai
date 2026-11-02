//! Server-side web search and fetch — pluggable provider backend with a
//! single audit/policy/filter surface, exposed today through the built-in
//! virtual MCP upstream `/mcp/web`.
//!
//! Module layout:
//! - [`types`] — wire-format-agnostic request/response shapes
//! - [`backend`] — `Backend` enum that dispatches to a provider
//! - [`providers`] — one module per provider (Brave, Tavily, Google CSE,
//!   Serper, SearXNG)
//! - [`url_filter`] — pluggable hook chain run against every URL the system
//!   considers (search hits, fetch targets)
//! - [`filters`] — built-in filter implementations
//! - [`fetch`] — generic HTTP fetch with SSRF guard + readability extraction
//! - [`audit`] — the `WebAuditRecord` channel + forwarder trait,
//!   mirroring `audit::mcp::McpAuditRecord`
//! - [`service`] — orchestration: policy → filter → backend call → audit
//!
//! ## Built-in upstream identity
//!
//! Every tenant gets one synthetic row in `mcp_upstream_servers`:
//!
//! - `name = "builtin-web"` (the [`BUILTIN_WEB_UPSTREAM_NAME`] constant; the
//!   tool-policy engine stamps `mcp_server` from this).
//! - `upstream_url = "internal://web"` (the [`BUILTIN_WEB_UPSTREAM_URL`]
//!   sentinel; `mcp::handler::call_cached` short-circuits on this scheme to
//!   dispatch into [`crate::web::service`] instead of HTTP).
//! - `id = Uuid::new_v5(NAMESPACE_WEB, tenant_id.as_bytes())` — stable
//!   per tenant (see [`builtin_upstream_id`]).
//! - `built_in = true` — admin UI hides destructive actions.

pub mod audit;
pub mod backend;
pub mod fetch;
pub mod filters;
pub mod mixed_pending;
pub mod providers;
pub mod service;
pub mod settings;
pub mod types;
pub mod url_filter;

pub use audit::{
    create_web_audit_channel, web_audit_writer_task, WebAuditForwarderTrait,
    WebAuditRecord,
};
pub use backend::Backend;
pub use mixed_pending::{MixedPendingCache, MixedPendingEntry};
pub use service::{dispatch_intercept, DispatchOutcome, WebContext, WebSurface};
pub use settings::{FetchProvider, WebDestinationLists, WebDestinations, WebSettings};
pub use types::{
    FetchRequest, FetchResult, SearchHit, SearchRequest, SearchResult, WebError,
    WebProvider,
};
pub use url_filter::{FilterChain, FilterContext, FilterVerdict, UrlFilter};

/// Constant `mcp_upstream_servers.name` used for the built-in web-search row.
///
/// Tool-policy stamps `mcp_server` from this; downstream rules that target
/// the built-in surface MUST match this exact string.
pub const BUILTIN_WEB_UPSTREAM_NAME: &str = "builtin-web";

/// Sentinel value stored in `mcp_upstream_servers.upstream_url` for built-in
/// gateway-internal upstreams. The proxy's MCP dispatch
/// (`mcp::handler::call_cached` and `mcp::upstream::call_with_bearer_for_streaming`)
/// short-circuits on this scheme into [`crate::web::service`].
///
/// The portion after `internal://` identifies which built-in handler to run.
/// Today the only handler is `web_search`; future built-ins (e.g.
/// `internal://timeseries`) plug in through the same dispatch.
pub const BUILTIN_WEB_UPSTREAM_URL: &str = "internal://web";

/// Default URL slug for the built-in web-search virtual server. Operators
/// can rename via `mcp_virtual_servers.slug` PATCH; the default keeps
/// `/mcp/web` stable across tenants.
pub const BUILTIN_WEB_VIRTUAL_SERVER_SLUG: &str = "web";

/// Stable namespace UUID for `Uuid::new_v5` derivation of per-tenant
/// built-in upstream IDs. Picking a fixed namespace ensures
/// `builtin_upstream_id(tenant_id)` is deterministic across instances.
const NAMESPACE_WEB: uuid::Uuid =
    uuid::Uuid::from_u128(0x9b86_0d8c_7c47_5f4d_82f1_47b1_e0ee_5a6f);

/// `true` when `upstream_url` is a gateway-internal sentinel (e.g.
/// `internal://web`). Both the proxy's MCP dispatch and the admin's portal
/// MCP test endpoint short-circuit on this check — internal upstreams never
/// reach the outbound HTTP layer, so SSRF / scheme guards must not reject
/// them. Returns true purely from URL shape; the dispatcher decides whether
/// it knows the specific sentinel.
pub fn is_internal_upstream_url(url: &str) -> bool {
    url.starts_with("internal://")
}

/// The built-in tools a tenant's settings can serve: `web_fetch` always (the
/// built-in fetcher needs no backend), `web_search` only with a search backend.
/// The single predicate behind `tools/list`, the server's `initialize`
/// instructions and the portal preview — what is advertised is what a call
/// can reach.
pub fn served_web_tools(settings: &WebSettings) -> impl Iterator<Item = &'static BuiltinTool> {
    let backend = settings.is_configured();
    BUILTIN_WEB_TOOLS.iter().filter(move |t| !t.needs_search_backend || backend)
}

/// Name of the built-in search tool — the one tool that needs a backend.
pub const TOOL_WEB_SEARCH: &str = "web_search";
/// Name of the built-in fetch tool — served on every tenant.
pub const TOOL_WEB_FETCH: &str = "web_fetch";

/// Static description of one built-in MCP tool. Mirrors the subset of the
/// MCP tool descriptor that surfaces in portal preview UIs (name +
/// human-readable description).
#[derive(Debug, Clone, Copy)]
pub struct BuiltinTool {
    pub name: &'static str,
    pub description: &'static str,
    /// Served only with a search backend configured ([`served_web_tools`]).
    pub needs_search_backend: bool,
}

/// Every tool the built-in `internal://web` upstream can expose; which of them
/// a tenant is served is [`served_web_tools`]'s answer, never this list's.
const BUILTIN_WEB_TOOLS: [BuiltinTool; 2] = [
    BuiltinTool {
        name: TOOL_WEB_SEARCH,
        description: "Search the public web using the gateway-configured backend. Returns ranked results with title, URL, and snippet.",
        needs_search_backend: true,
    },
    BuiltinTool {
        name: TOOL_WEB_FETCH,
        description: "Fetch a single URL and return the extracted text. http/https only; private and link-local addresses are refused.",
        needs_search_backend: false,
    },
];

/// Compute the deterministic per-tenant `mcp_upstream_servers.id` for the
/// built-in web-search row. Stable across instances and migrations.
pub fn builtin_upstream_id(tenant_id: uuid::Uuid) -> uuid::Uuid {
    uuid::Uuid::new_v5(&NAMESPACE_WEB, tenant_id.as_bytes())
}

/// Decrypt a base64-encoded AES-256-GCM ciphertext produced by
/// [`crate::crypto::encrypt`]. Returns `None` when `ENCRYPTION_KEY` is
/// unset or decryption fails — both signal the credential is unusable
/// and the caller should fall through as if no credential were configured.
pub fn decrypt_upstream_credential(encrypted: &str) -> Option<String> {
    let key = crate::crypto::get_encryption_key()?;
    match crate::crypto::decrypt(encrypted, &key) {
        Ok(plain) => Some(plain),
        Err(e) => {
            tracing::error!("decrypt web-search upstream credential: {e}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_upstream_id_is_stable_and_unique() {
        let t1 = uuid::Uuid::from_u128(1);
        let t2 = uuid::Uuid::from_u128(2);
        let a = builtin_upstream_id(t1);
        let b = builtin_upstream_id(t1);
        let c = builtin_upstream_id(t2);
        assert_eq!(a, b, "deterministic per tenant");
        assert_ne!(a, c, "unique across tenants");
    }

    #[test]
    fn fetch_is_served_without_a_backend_and_search_only_with_one() {
        let names = |s: &WebSettings| served_web_tools(s).map(|t| t.name).collect::<Vec<_>>();
        let mut s = WebSettings::default();
        assert_eq!(names(&s), ["web_fetch"]);
        s.backend = Some(types::WebProvider::Searxng);
        // A SearXNG backend without its endpoint serves no search.
        assert_eq!(names(&s), ["web_fetch"]);
        s.endpoint = Some("https://search.example.com".into());
        assert_eq!(names(&s), ["web_search", "web_fetch"]);
    }
}
