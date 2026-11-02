//! SearXNG backend — meta-search aggregator. Free, self-hosted, no API key.
//!
//! Wire format: `GET {endpoint}/search?q=...&format=json&...`. The response
//! is a JSON object with a `results: [...]` array. Each result carries
//! `url`, `title`, `content` (snippet), and optionally `engine`,
//! `publishedDate`, `category`, etc.
//!
//! No auth header. The endpoint is the tenant's `web.endpoint` (e.g.
//! `https://search.example.com`), reached through the shared SSRF guard
//! ([`crate::extension_http`]): an internal address only when the platform's
//! `extensions` egress list lists it, never a redirect.

use std::time::Instant;

use serde::Deserialize;
use url::Url;

use crate::web::backend::BackendSearchOutcome;
use crate::web::types::{
    SearchHit, SearchRequest, SearchResult, WebError, WebProvider,
};

/// Cap for buffering a search-backend response. Result JSON is small; this
/// bounds a hostile/misconfigured backend so it can't OOM the shared edge.
const SEARXNG_MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct SearxngBackend {
    endpoint: Url,
}

impl SearxngBackend {
    pub fn new(endpoint: Option<String>) -> Result<Self, WebError> {
        let raw = endpoint.ok_or_else(|| {
            WebError::InvalidConfig(
                "searxng requires `web_search.endpoint` (e.g. https://search.example.com)".into(),
            )
        })?;
        let parsed = Url::parse(raw.trim_end_matches('/'))
            .map_err(|e| WebError::InvalidConfig(format!("invalid searxng endpoint: {e}")))?;
        Ok(Self { endpoint: parsed })
    }

    pub async fn search(
        &self,
        clients: &crate::extension_http::ExtensionClients,
        req: &SearchRequest,
    ) -> Result<BackendSearchOutcome, WebError> {
        let client = clients
            .for_endpoint(self.endpoint.as_str())
            .map_err(crate::web::fetch::map_ssrf)?;
        let mut url = self
            .endpoint
            .join("search")
            .map_err(|e| WebError::InvalidConfig(format!("join /search failed: {e}")))?;
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("q", &req.query);
            q.append_pair("format", "json");
            if let Some(lang) = &req.language {
                q.append_pair("language", lang);
            }
        }

        let started = Instant::now();
        let resp = client
            .get(url.clone())
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| match clients.take_refusal(&url) {
                Some(refusal) => crate::web::fetch::map_ssrf(refusal),
                None => WebError::Transport(e.to_string()),
            })?;

        let status = resp.status();
        let bytes = crate::http_body::read_body_capped(resp, SEARXNG_MAX_RESPONSE_BYTES)
            .await
            .map_err(|e| match e {
                crate::http_body::CappedReadError::Oversized { limit_bytes } => {
                    WebError::Oversized { limit_bytes }
                }
                crate::http_body::CappedReadError::Transport(e) => {
                    WebError::Transport(format!("read body: {e}"))
                }
            })?;
        let latency = started.elapsed().as_millis() as u64;

        if !status.is_success() {
            let detail = String::from_utf8_lossy(&bytes).to_string();
            if status.as_u16() == 429 {
                return Err(WebError::RateLimited { detail });
            }
            return Err(WebError::UpstreamError {
                status: Some(status.as_u16()),
                detail,
            });
        }

        // Two `from_slice` passes — one untyped for `provider_response` audit
        // capture, one typed for the result list — avoid cloning the full
        // Value tree we'd get from `from_value(raw.clone())`. Untyped runs
        // first so a syntactically broken body surfaces as "invalid JSON"
        // rather than the typed parser's less specific shape error.
        let raw: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| {
            WebError::UpstreamError {
                status: Some(status.as_u16()),
                detail: format!("invalid JSON: {e}"),
            }
        })?;
        let parsed: SearxngResponse = serde_json::from_slice(&bytes).map_err(|e| {
            WebError::UpstreamError {
                status: Some(status.as_u16()),
                detail: format!("unexpected response shape: {e}"),
            }
        })?;

        let cap = req.max_results.unwrap_or(u32::MAX) as usize;
        let hits: Vec<SearchHit> = parsed
            .results
            .into_iter()
            .take(cap)
            .map(|r| SearchHit {
                url: r.url,
                title: r.title.unwrap_or_default(),
                snippet: r.content,
                published: r.published_date,
            })
            .collect();

        let result = SearchResult {
            backend: WebProvider::Searxng,
            total_filtered: 0, // filter chain runs in the service layer
            hits,
        };

        let bytes_out = req.query.len() as u64 + 64; // approx
        let bytes_in = bytes.len() as u64;

        Ok(BackendSearchOutcome {
            result,
            provider_request: serde_json::json!({
                "method": "GET",
                "url": url.as_str(),
                "headers": {
                    "Accept": "application/json"
                }
            }),
            provider_response: raw,
            upstream_latency_ms: latency,
            upstream_status: status.as_u16(),
            bytes_in,
            bytes_out,
        })
    }
}

/// Subset of the SearXNG JSON response we extract. Unknown fields are
/// preserved in `provider_response` so audit retains the verbatim body.
#[derive(Debug, Deserialize)]
struct SearxngResponse {
    #[serde(default)]
    results: Vec<SearxngResult>,
}

#[derive(Debug, Deserialize)]
struct SearxngResult {
    url: String,
    title: Option<String>,
    /// SearXNG's "snippet" field is named `content`.
    #[serde(default)]
    content: Option<String>,
    #[serde(default, rename = "publishedDate")]
    published_date: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    #[test]
    fn requires_endpoint() {
        assert_matches!(
            SearxngBackend::new(None),
            Err(WebError::InvalidConfig(_))
        );
    }

    #[test]
    fn rejects_invalid_endpoint() {
        assert_matches!(
            SearxngBackend::new(Some("not a url".into())),
            Err(WebError::InvalidConfig(_))
        );
    }

    #[test]
    fn accepts_valid_endpoint_with_trailing_slash() {
        let b = SearxngBackend::new(Some("http://searxng:8080/".into())).unwrap();
        assert_eq!(b.endpoint.host_str(), Some("searxng"));
        assert_eq!(b.endpoint.port(), Some(8080));
        // `Url::join("search")` against the parsed root produces the right
        // endpoint regardless of how `as_str()` formats the trailing slash.
        let joined = b.endpoint.join("search").unwrap();
        assert_eq!(joined.as_str(), "http://searxng:8080/search");
    }

    #[test]
    fn parses_minimal_response() {
        let body = serde_json::json!({
            "results": [
                { "url": "https://example.com", "title": "Example", "content": "snippet" },
                { "url": "https://no-snippet.com", "title": "B" },
            ]
        });
        let parsed: SearxngResponse = serde_json::from_value(body).unwrap();
        assert_eq!(parsed.results.len(), 2);
        assert_eq!(parsed.results[0].url, "https://example.com");
        assert_eq!(parsed.results[0].content.as_deref(), Some("snippet"));
        assert!(parsed.results[1].content.is_none());
    }
}
