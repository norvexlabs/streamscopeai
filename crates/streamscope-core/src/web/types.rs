//! Wire-format-agnostic types for web search and fetch.
//!
//! These shapes flow through the [`crate::web::service`] pipeline.
//! Provider modules translate to/from upstream wire formats; the MCP virtual
//! server translates from these to MCP `tools/call` content blocks.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use utoipa::ToSchema;

/// Configured web-search backend. Mirrors [`crate::config::model_map::Provider`]
/// in spirit — string enum, snake_case wire format, parser tolerant of
/// shorthand forms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum WebProvider {
    /// SearXNG meta-search (free, self-hosted, no API key). Default for the
    /// dev stack and the only provider shipped in v1.
    Searxng,
    /// Brave Search API. Paid, free tier 2k/mo. Independent index.
    Brave,
    /// Tavily — LLM-optimised search and content extraction. Paid, free tier
    /// 1k/mo.
    Tavily,
    /// Google Custom Search Engine (CSE). 100 queries/day free. Requires both
    /// an API key and a CSE engine ID.
    GoogleCse,
    /// Serper.dev — Google-results proxy. Paid.
    Serper,
}

impl WebProvider {
    /// Stable wire string used for audit (`web_audit.backend`) and the
    /// admin UI dropdown.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Searxng => "searxng",
            Self::Brave => "brave",
            Self::Tavily => "tavily",
            Self::GoogleCse => "google_cse",
            Self::Serper => "serper",
        }
    }

    /// Tolerant parser used by config-sync when reading a tenant's
    /// `web_search.backend` JSONB value. Falls through to `None` on any
    /// unrecognised string — caller decides how to surface.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "searxng" | "searx" => Some(Self::Searxng),
            "brave" => Some(Self::Brave),
            "tavily" => Some(Self::Tavily),
            "google_cse" | "google" | "cse" => Some(Self::GoogleCse),
            "serper" => Some(Self::Serper),
            _ => None,
        }
    }

    /// Whether this provider requires a credential. SearXNG is the only
    /// no-auth backend; everything else needs a key.
    pub fn requires_credential(&self) -> bool {
        !matches!(self, Self::Searxng)
    }
}

impl std::fmt::Display for WebProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

/// Caller-supplied search arguments — the model writes this into the MCP
/// `tools/call.arguments` payload.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SearchRequest {
    pub query: String,
    /// Maximum hits the caller wants. Bounded by tenant `max_results` setting
    /// at the service layer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_results: Option<u32>,
    /// Optional ISO-639-1 language hint passed through to providers that
    /// honour it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
}

/// One ranked hit from the search backend, post URL-filter chain.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SearchHit {
    pub url: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
    /// Provider-supplied published-at timestamp if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published: Option<String>,
}

/// Result returned to the caller. `total_filtered` counts hits dropped by
/// the URL-filter chain so the model can reason about coverage.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SearchResult {
    pub hits: Vec<SearchHit>,
    /// Hits the backend returned that the URL-filter chain denied. Always
    /// `0` when no filter denied anything.
    pub total_filtered: u32,
    /// Echo of the configured backend that ran the call.
    pub backend: WebProvider,
}

impl SearchResult {
    /// The untrusted text the inline guardrail must score for this result.
    ///
    /// **Invariant: everything attacker-influenced that the model reads is
    /// classified.** The model is fed the serialized envelope, so any field
    /// reaching it unscanned is a channel the guardrail is blind to — an
    /// injection in a hit's URL or `published` string would be read by the model
    /// yet never withheld in enforce mode. Prose (title + snippet) leads so the
    /// classifier still sees high-signal content first; the shorter
    /// attacker-controlled metadata follows.
    ///
    /// Built by **exhaustive destructuring**: adding a field to [`SearchResult`]
    /// or [`SearchHit`] fails the build here until it is explicitly scanned, or
    /// explicitly bound as gateway-computed (and therefore trusted).
    pub fn classifiable(&self) -> String {
        let SearchResult { hits, total_filtered: _, backend: _ } = self; // both gateway-computed
        hits.iter()
            .map(|h| {
                let SearchHit { url, title, snippet, published } = h;
                let mut parts = vec![title.clone()];
                if let Some(s) = snippet {
                    parts.push(s.clone());
                }
                parts.push(url.clone());
                if let Some(p) = published {
                    parts.push(p.clone());
                }
                parts.join("\n")
            })
            .collect::<Vec<_>>()
            .join("\n\n")
    }
}

impl FetchResult {
    /// The untrusted text the inline guardrail must score for this fetch. Same
    /// invariant (and same exhaustive-destructuring guard) as
    /// [`SearchResult::classifiable`]: the page body is not the only
    /// attacker-controlled string the model reads — the response `content_type`
    /// header is free-form prose the origin server chooses, and the final URL and
    /// every redirect hop are picked by the attacker's own `Location` headers.
    pub fn classifiable(&self) -> String {
        let FetchResult {
            url,
            final_url,
            content_type,
            status: _,     // gateway-observed numeric
            extracted_text,
            redirect_chain,
            extracted_size: _, // gateway-computed
            raw_size: _,       // gateway-computed
        } = self;
        let mut parts = vec![extracted_text.clone(), url.clone(), final_url.clone(), content_type.clone()];
        parts.extend(redirect_chain.iter().cloned());
        parts.join("\n")
    }
}

/// Caller-supplied fetch arguments.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct FetchRequest {
    pub url: String,
    /// Override the tenant's `fetch_max_bytes` cap (must be ≤ tenant cap).
    /// Larger values are clamped silently at the service layer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<u64>,
}

/// Fetch result. The extracted text is what the model sees in the MCP
/// content block; the raw bytes flow into `audit_media_blobs` for audit
/// reproducibility.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct FetchResult {
    pub url: String,
    /// Final URL after redirects (may differ from `url`).
    pub final_url: String,
    pub content_type: String,
    pub status: u16,
    /// Markdown-ish extracted text (HTML tag-stripped + entity decode +
    /// whitespace normalised). For non-HTML responses this is the raw body
    /// up to `max_bytes`.
    pub extracted_text: String,
    /// Hop-by-hop redirect URLs the fetcher traversed (excluding the final
    /// URL). Empty when no redirects occurred.
    pub redirect_chain: Vec<String>,
    /// `extracted_text.len()`.
    pub extracted_size: usize,
    /// Original response body byte count (pre-extraction).
    pub raw_size: usize,
}

/// Typed errors surfaced from any layer of the websearch pipeline. The MCP
/// virtual server maps these to JSON-RPC error objects; the audit pipeline
/// uses the discriminator string for `web_audit.error_category`.
#[derive(Debug, Error, Clone)]
pub enum WebError {
    #[error("no backend configured for tenant")]
    NoBackend,
    #[error("missing credential for backend `{backend}`")]
    MissingCredential { backend: WebProvider },
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("URL parse failed: {0}")]
    InvalidUrl(String),
    #[error("URL refused by SSRF guard: {0}")]
    SsrfRefused(String),
    #[error("URL scheme `{0}` not allowed (http/https only)")]
    SchemeRefused(String),
    #[error("URL denied by filter `{filter_id}`: {reason}")]
    UrlFilterDenied {
        filter_id: String,
        reason: String,
        url: String,
    },
    #[error("upstream provider error (status={status:?}): {detail}")]
    UpstreamError {
        status: Option<u16>,
        detail: String,
    },
    #[error("upstream rate limit (status=429): {detail}")]
    RateLimited { detail: String },
    #[error("response exceeds tenant cap of {limit_bytes} bytes")]
    Oversized { limit_bytes: u64 },
    #[error("HTTP transport error: {0}")]
    Transport(String),
    #[error("internal error: {0}")]
    Internal(String),
    #[error("call cancelled")]
    Cancelled,
    /// A call the gateway intercepted for a substitution that a
    /// response-phase tool-call rule blocked: never run.
    #[error("blocked by policy: {0}")]
    PolicyBlocked(String),
}

impl WebError {
    /// Stable string for `web_audit.error_category`. Append-only —
    /// never rename existing values; the admin UI joins on these.
    pub fn category(&self) -> &'static str {
        match self {
            Self::NoBackend => "config_missing",
            Self::MissingCredential { .. } => "config_missing",
            Self::InvalidConfig(_) => "config_invalid",
            Self::InvalidUrl(_) => "invalid_url",
            Self::SsrfRefused(_) => "ssrf_refused",
            Self::SchemeRefused(_) => "scheme_refused",
            Self::UrlFilterDenied { .. } => "url_filter_denied",
            Self::UpstreamError { .. } => "upstream_error",
            Self::RateLimited { .. } => "rate_limited",
            Self::Oversized { .. } => "oversized",
            Self::Transport(_) => "transport_error",
            Self::Internal(_) => "internal_error",
            Self::Cancelled => "cancelled",
            Self::PolicyBlocked(_) => "policy_blocked",
        }
    }

    /// JSON-RPC error code surfaced to MCP callers. Mirrors the MCP layer's
    /// numbering (`-32xxx`); reuses existing codes where the semantics line
    /// up.
    pub fn rpc_code(&self) -> i32 {
        match self {
            Self::NoBackend | Self::MissingCredential { .. } | Self::InvalidConfig(_) => -32500,
            Self::SsrfRefused(_) | Self::SchemeRefused(_) => -32505,
            Self::UrlFilterDenied { .. } => -32506,
            Self::RateLimited { .. } => -32429,
            // Upstream / transport / internal — generic upstream-error code.
            Self::UpstreamError { .. } | Self::Transport(_) | Self::Internal(_) => -32003,
            // Caller-input errors — use the same code MCP uses for invalid
            // params (-32602) since these are client-supplied.
            Self::InvalidUrl(_) | Self::Oversized { .. } => -32602,
            // Cancelled — surface as a generic upstream-error code; MCP
            // callers don't see this today (cancel is substitution-only),
            // but mapping defensively keeps the discriminator consistent
            // if a future MCP-side caller threads a token.
            Self::Cancelled => -32003,
            Self::PolicyBlocked(_) => -32506,
        }
    }

    /// The text a substitution answers the model's call with when this
    /// error ends it: the stable category, so no upstream or parse detail
    /// reaches the conversation — except a policy block, whose rule
    /// description tells the model why, as the client is told on a block.
    pub fn tool_result_text(&self) -> String {
        match self {
            Self::PolicyBlocked(_) => format!("error: {self}"),
            _ => format!("error: {}", self.category()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_parse_round_trip() {
        for v in [
            WebProvider::Searxng,
            WebProvider::Brave,
            WebProvider::Tavily,
            WebProvider::GoogleCse,
            WebProvider::Serper,
        ] {
            let parsed = WebProvider::parse(v.code());
            assert_eq!(parsed, Some(v), "round-trip for {}", v.code());
        }
    }

    #[test]
    fn provider_parse_aliases() {
        assert_eq!(
            WebProvider::parse("SEARX"),
            Some(WebProvider::Searxng)
        );
        assert_eq!(
            WebProvider::parse("google"),
            Some(WebProvider::GoogleCse)
        );
        assert_eq!(WebProvider::parse("nonsense"), None);
    }

    #[test]
    fn searxng_does_not_require_credential() {
        assert!(!WebProvider::Searxng.requires_credential());
    }

    #[test]
    fn paid_providers_require_credential() {
        for p in [
            WebProvider::Brave,
            WebProvider::Tavily,
            WebProvider::GoogleCse,
            WebProvider::Serper,
        ] {
            assert!(p.requires_credential(), "{p:?} should need a key");
        }
    }

    #[test]
    fn error_categories_are_stable() {
        let e = WebError::SsrfRefused("loopback".into());
        assert_eq!(e.category(), "ssrf_refused");
        assert_eq!(e.rpc_code(), -32505);
    }

    /// The guardrail can only withhold what it scanned, so every
    /// attacker-influenced string the model reads in the folded envelope must
    /// appear in the classifiable text. A hit's URL and `published` are
    /// attacker-chosen (they own the indexed page), not just its prose.
    #[test]
    fn search_classifiable_covers_every_untrusted_field() {
        let r = SearchResult {
            hits: vec![SearchHit {
                url: "https://evil.example/PAYLOAD_URL".into(),
                title: "PAYLOAD_TITLE".into(),
                snippet: Some("PAYLOAD_SNIPPET".into()),
                published: Some("PAYLOAD_PUBLISHED".into()),
            }],
            total_filtered: 0,
            backend: WebProvider::Searxng,
        };
        let c = r.classifiable();
        for marker in ["PAYLOAD_TITLE", "PAYLOAD_SNIPPET", "PAYLOAD_URL", "PAYLOAD_PUBLISHED"] {
            assert!(c.contains(marker), "{marker} reaches the model unscanned:\n{c}");
        }
    }

    /// Same invariant on the fetch envelope. `content_type` is a free-form
    /// response header the origin server chooses, and the final URL / redirect
    /// hops come from its own `Location` headers — all prose channels into the
    /// model that the page body alone does not cover.
    #[test]
    fn fetch_classifiable_covers_every_untrusted_field() {
        let r = FetchResult {
            url: "https://evil.example/PAYLOAD_URL".into(),
            final_url: "https://evil.example/PAYLOAD_FINAL".into(),
            content_type: "text/html; PAYLOAD_CTYPE".into(),
            status: 200,
            extracted_text: "PAYLOAD_BODY".into(),
            redirect_chain: vec!["https://evil.example/PAYLOAD_HOP".into()],
            extracted_size: 12,
            raw_size: 34,
        };
        let c = r.classifiable();
        for marker in
            ["PAYLOAD_BODY", "PAYLOAD_URL", "PAYLOAD_FINAL", "PAYLOAD_CTYPE", "PAYLOAD_HOP"]
        {
            assert!(c.contains(marker), "{marker} reaches the model unscanned:\n{c}");
        }
    }
}
