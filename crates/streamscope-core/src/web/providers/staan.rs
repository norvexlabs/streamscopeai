//! Staan backend — an EU web search API, reached with the tenant's key.
//!
//! Wire format: `GET {base}/v2/search/web?q=…[&market=…]` with
//! `Authorization: Bearer <key>`. The response's `web.results[]` carry `url`,
//! `title`, `snippet` and, sometimes, `published_date`; one call answers
//! Staan's page of 10 hits.
//!
//! The base is the platform's `WEB_SEARCH_STAAN_URL` (Staan's API origin,
//! [`DEFAULT_BASE`]), never a tenant setting: the tenant's key goes only
//! there. It is reached through the shared SSRF guard
//! ([`crate::extension_http`]) on the `extensions` egress surface, which every
//! search backend shares (SearXNG included): an internal base is listed there.

use std::time::Instant;

use serde::Deserialize;
use url::Url;

use crate::web::backend::BackendSearchOutcome;
use crate::web::types::{SearchHit, SearchRequest, SearchResult, StaanMarket, WebError, WebProvider};

/// Staan's API origin, the default of `WEB_SEARCH_STAAN_URL`.
pub const DEFAULT_BASE: &str = "https://api.staan.ai";

/// The longest query Staan accepts, in characters.
pub const MAX_QUERY_CHARS: usize = 400;

/// Cap for buffering a search response. Result JSON is small; this bounds a
/// hostile or misconfigured endpoint so it can't OOM the shared edge.
const STAAN_MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;

/// What the audit row shows for the key: the header is recorded as sent, its
/// value never.
const REDACTED_BEARER: &str = "Bearer [redacted]";

#[derive(Clone)]
pub struct StaanBackend {
    base: Url,
    key: String,
    market: Option<StaanMarket>,
}

/// Never prints the key.
impl std::fmt::Debug for StaanBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaanBackend")
            .field("base", &self.base.as_str())
            .field("market", &self.market)
            .finish_non_exhaustive()
    }
}

impl StaanBackend {
    pub fn new(base: &str, key: &str, market: Option<StaanMarket>) -> Result<Self, WebError> {
        let mut base = Url::parse(base.trim())
            .ok()
            .filter(|u| matches!(u.scheme(), "http" | "https") && u.has_host() && u.username().is_empty() && u.password().is_none())
            .ok_or_else(|| {
                WebError::InvalidConfig(
                    "the platform setting WEB_SEARCH_STAAN_URL is not an http(s) URL without credentials".into(),
                )
            })?;
        // `join` replaces the last path segment unless the path ends in `/`.
        if !base.path().ends_with('/') {
            let path = format!("{}/", base.path());
            base.set_path(&path);
        }
        Ok(Self { base, key: key.to_string(), market })
    }

    /// The request URL: the query, and the market — the tenant's, else the
    /// one the caller's language hint names, else none (Staan's default).
    fn search_url(&self, req: &SearchRequest) -> Result<Url, WebError> {
        if req.query.chars().count() > MAX_QUERY_CHARS {
            return Err(WebError::InvalidArguments(format!(
                "`query` is longer than {MAX_QUERY_CHARS} characters"
            )));
        }
        let mut url = self
            .base
            .join("v2/search/web")
            .map_err(|e| WebError::InvalidConfig(format!("join /v2/search/web failed: {e}")))?;
        let market = self.market.or_else(|| req.language.as_deref().and_then(StaanMarket::for_language));
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("q", &req.query);
            if let Some(m) = market {
                q.append_pair("market", m.code());
            }
        }
        Ok(url)
    }

    pub async fn search(
        &self,
        clients: &crate::extension_http::ExtensionClients,
        req: &SearchRequest,
    ) -> Result<BackendSearchOutcome, WebError> {
        let url = self.search_url(req)?;
        let client = clients.for_endpoint(self.base.as_str()).map_err(crate::web::fetch::map_ssrf)?;

        let started = Instant::now();
        let resp = client
            .get(url.clone())
            .header(reqwest::header::ACCEPT, "application/json")
            .bearer_auth(&self.key)
            .send()
            .await
            .map_err(|e| match clients.take_refusal(&url) {
                Some(refusal) => crate::web::fetch::map_ssrf(refusal),
                None => WebError::Transport(e.to_string()),
            })?;

        let status = resp.status();
        let bytes = crate::http_body::read_body_capped(resp, STAAN_MAX_RESPONSE_BYTES)
            .await
            .map_err(|e| match e {
                crate::http_body::CappedReadError::Oversized { limit_bytes } => WebError::Oversized { limit_bytes },
                crate::http_body::CappedReadError::Transport(e) => WebError::Transport(format!("read body: {e}")),
            })?;
        let latency = started.elapsed().as_millis() as u64;

        if !status.is_success() {
            return Err(status_error(status.as_u16(), &bytes, &self.key));
        }
        let (result, raw) = parse_response(&bytes, status.as_u16(), req.max_results)?;

        Ok(BackendSearchOutcome {
            result,
            provider_request: serde_json::json!({
                "method": "GET",
                "url": url.as_str(),
                "headers": {
                    "Accept": "application/json",
                    "Authorization": REDACTED_BEARER,
                }
            }),
            provider_response: raw,
            upstream_latency_ms: latency,
            upstream_status: status.as_u16(),
            bytes_in: bytes.len() as u64,
            bytes_out: url.as_str().len() as u64,
        })
    }
}

/// The most of a refusal's body kept in the error detail (and so the audit
/// row): enough for Staan's error JSON, not a whole page an override serves.
const MAX_ERROR_DETAIL_BYTES: usize = 2048;

/// The failure a non-2xx answer is. A refused key says so (an administrator's
/// fix, never the model's) and keeps nothing of the body, which may echo the
/// key it refused; any other keeps the body with the key it was sent scrubbed
/// out (a proxy's debug page echoes headers); a 429 is a rate limit.
fn status_error(status: u16, body: &[u8], key: &str) -> WebError {
    if matches!(status, 401 | 403) {
        return WebError::UpstreamError { status: Some(status), detail: "Staan refused the API key".into() };
    }
    let text = String::from_utf8_lossy(body);
    let text = if key.is_empty() { text } else { text.replace(key, "[redacted]").into() };
    let cut = text.floor_char_boundary(MAX_ERROR_DETAIL_BYTES);
    let detail = if cut < text.len() { format!("{}… ({} bytes)", &text[..cut], body.len()) } else { text.into_owned() };
    match status {
        429 => WebError::RateLimited { detail },
        _ => WebError::UpstreamError { status: Some(status), detail },
    }
}

/// The hits of a 2xx body, at most `max_results`, and the body itself for the
/// audit row.
fn parse_response(
    bytes: &[u8],
    status: u16,
    max_results: Option<u32>,
) -> Result<(SearchResult, serde_json::Value), WebError> {
    // Untyped first so a syntactically broken body reads as "invalid JSON"
    // rather than the typed parser's less specific shape error.
    let raw: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|e| WebError::UpstreamError { status: Some(status), detail: format!("invalid JSON: {e}") })?;
    let parsed: StaanResponse = serde_json::from_slice(bytes).map_err(|e| WebError::UpstreamError {
        status: Some(status),
        detail: format!("unexpected response shape: {e}"),
    })?;
    let cap = max_results.unwrap_or(u32::MAX) as usize;
    // A hit is read field by field: one entry that does not decode (no `url`,
    // a field of another type) is left out, never the whole page — the body
    // the audit row keeps still holds it.
    let hits = parsed
        .web
        .and_then(|w| w.results)
        .unwrap_or_default()
        .iter()
        .filter_map(hit)
        .take(cap)
        .collect();
    Ok((SearchResult { backend: WebProvider::Staan, total_filtered: 0, hits }, raw))
}

/// The part of Staan's response the hits are read from. Every other field
/// stays in `provider_response`, the verbatim body the audit row keeps.
#[derive(Debug, Deserialize)]
struct StaanResponse {
    #[serde(default)]
    web: Option<StaanWeb>,
}

#[derive(Debug, Deserialize)]
struct StaanWeb {
    #[serde(default)]
    results: Option<Vec<serde_json::Value>>,
}

/// One result as a hit: its `url` is required and must be an http(s) URL (a
/// `javascript:` or `data:` one is no page, and the console renders hits as
/// links); every other field is kept only when it is a string.
fn hit(r: &serde_json::Value) -> Option<SearchHit> {
    let text = |k: &str| r.get(k).and_then(serde_json::Value::as_str).map(str::to_string);
    let url = text("url").filter(|u| Url::parse(u).is_ok_and(|p| matches!(p.scheme(), "http" | "https")))?;
    Some(SearchHit {
        url,
        title: text("title").unwrap_or_default(),
        snippet: text("snippet").filter(|s| !s.is_empty()),
        published: text("published_date"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    fn req(query: &str, language: Option<&str>) -> SearchRequest {
        SearchRequest { query: query.into(), max_results: None, language: language.map(Into::into) }
    }

    fn backend(base: &str, market: Option<StaanMarket>) -> StaanBackend {
        StaanBackend::new(base, "stn_secret", market).unwrap()
    }

    #[test]
    fn the_request_goes_to_the_configured_base() {
        let url = backend(DEFAULT_BASE, None).search_url(&req("rust", None)).unwrap();
        assert_eq!(url.as_str(), "https://api.staan.ai/v2/search/web?q=rust");
        // A base with a path prefix, with or without a trailing slash.
        for base in ["http://mock:3333/staan", "http://mock:3333/staan/"] {
            let url = backend(base, None).search_url(&req("rust", None)).unwrap();
            assert_eq!(url.as_str(), "http://mock:3333/staan/v2/search/web?q=rust", "{base}");
        }
        for bad in ["not a url", "staan-proxy.internal:8443", "ftp://api.staan.ai", "https://svc:secret@proxy.example"] {
            assert_matches!(StaanBackend::new(bad, "k", None), Err(WebError::InvalidConfig(_)), "{bad}");
        }
    }

    #[test]
    fn the_market_is_the_tenants_else_the_languages_else_none() {
        let market = |b: &StaanBackend, language: Option<&str>| {
            let url = b.search_url(&req("q", language)).unwrap();
            url.query_pairs().find(|(k, _)| k == "market").map(|(_, v)| v.into_owned())
        };
        let unset = backend(DEFAULT_BASE, None);
        assert_eq!(market(&unset, None), None);
        assert_eq!(market(&unset, Some("FR")), Some("fr-fr".into()));
        assert_eq!(market(&unset, Some("de")), Some("de-de".into()));
        assert_eq!(market(&unset, Some("en")), Some("en-us".into()));
        // A market's own tag, in either spelling.
        assert_eq!(market(&unset, Some("en-GB")), Some("en-gb".into()));
        assert_eq!(market(&unset, Some("en_ie")), Some("en-ie".into()));
        // A language with no market of its own leaves Staan's default.
        assert_eq!(market(&unset, Some("es")), None);
        // A region Staan has no market for falls back to its language's.
        assert_eq!(market(&unset, Some("fr-BE")), Some("fr-fr".into()));
        assert_eq!(market(&unset, Some("en-xx")), Some("en-us".into()));
        assert_eq!(market(&unset, Some("es-ES")), None);
        // The tenant's market wins over a caller's hint.
        let gb = backend(DEFAULT_BASE, Some(StaanMarket::EnGb));
        assert_eq!(market(&gb, None), Some("en-gb".into()));
        assert_eq!(market(&gb, Some("fr")), Some("en-gb".into()));
    }

    #[test]
    fn a_query_over_staans_limit_is_refused_before_any_call() {
        let b = backend(DEFAULT_BASE, None);
        // Counted in characters, not bytes: 400 two-byte characters pass.
        assert!(b.search_url(&req(&"é".repeat(MAX_QUERY_CHARS), None)).is_ok());
        assert_matches!(
            b.search_url(&req(&"a".repeat(MAX_QUERY_CHARS + 1), None)),
            Err(WebError::InvalidArguments(_))
        );
    }

    #[test]
    fn the_key_never_reaches_the_url_or_the_debug_form() {
        let b = backend(DEFAULT_BASE, Some(StaanMarket::FrFr));
        assert!(!b.search_url(&req("q", None)).unwrap().as_str().contains("stn_secret"));
        let debug = format!("{b:?}");
        assert!(!debug.contains("stn_secret"), "{debug}");
        assert!(debug.contains("api.staan.ai"), "{debug}");
    }

    #[test]
    fn parses_the_documented_response() {
        let body = serde_json::json!({
            "search_id": "0190f0a0-0000-7000-8000-000000000000",
            "query": { "q": "rust", "market": "en-us", "count": 10, "offset": 0 },
            "web": { "results": [
                { "title": "Rust", "url": "https://www.rust-lang.org/", "snippet": "A language",
                  "display_url": "rust-lang.org", "hostname": "www.rust-lang.org",
                  "published_date": "2026-01-02T00:00:00Z" },
                { "title": "Book", "url": "https://doc.rust-lang.org/book/", "snippet": "",
                  "display_url": "doc.rust-lang.org", "hostname": "doc.rust-lang.org" },
                { "title": "Third", "url": "https://example.com/", "snippet": "x",
                  "display_url": "example.com", "hostname": "example.com" }
            ]}
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let (result, raw) = parse_response(&bytes, 200, Some(2)).unwrap();
        assert_eq!(raw, body);
        assert_eq!(result.backend, WebProvider::Staan);
        assert_eq!(result.hits.len(), 2);
        let first = &result.hits[0];
        assert_eq!(
            (first.url.as_str(), first.title.as_str(), first.snippet.as_deref(), first.published.as_deref()),
            ("https://www.rust-lang.org/", "Rust", Some("A language"), Some("2026-01-02T00:00:00Z"))
        );
        // An empty snippet is no snippet.
        assert_eq!(result.hits[1].snippet, None);
    }

    /// The first two results of a real answer (`q=weather forecast`,
    /// `market=en-gb`), verbatim: a 32-hex `search_id`, a `favicon_url`, no
    /// `published_date`.
    const RECORDED_EN_GB: &str = r##"{"search_id": "406b1cbf92302e8ec5a5099081786b80", "query": {"q": "weather forecast", "market": "en-gb", "count": 10, "offset": 0}, "web": {"results": [{"title": "UK Forecast", "url": "https://weather.metoffice.gov.uk/forecast/uk", "snippet": "United Kingdom (National) weather - Met Office ... Cold and generally cloudy, with rain focussed in the north. ... UK weather ... Mostly dry and cloudy, with limited sunny breaks. ... Wet and windy weather this week with wintry hazards possible A changeable week of weather is expected across the UK, with heavy rain in the southwest on Tuesday followed by a colder interlude and a risk of hill snow later in the week. ... View the weather with our interactive map", "display_url": "https://weather.metoffice.gov.uk/forecast/uk", "hostname": "weather.metoffice.gov.uk", "favicon_url": "https://s.qwant.com/v1/fav/E9pWF1hKa2zEwgYY2_RmY-j8w71vStG-p1MXD9-pe5hv1hiaE5IbeGBzPaSKokDzgHm-i3bzZjppDwzD2IUz_w:f57b609d64291580641cf6e2ac180774"}, {"title": "Weather", "url": "https://weather.metoffice.gov.uk/forecast/gcpuvk7px", "snippet": "… UK long range weather forecast Sunday 29 Nov - Tuesday 8 Dec ... As such, western or northwestern areas are likely to be wettest, with potential for strong winds at times too. Southeastern areas are most likely to remain drier overall. ... London & South East England weather forecast ... Dry with bright spells. Occasional rain towards the south coast. ... This is because small differences in weather conditions can have a greater impact over time.", "display_url": "https://weather.metoffice.gov.uk/forecast/gcpuvk7px", "hostname": "weather.metoffice.gov.uk", "favicon_url": "https://s.qwant.com/v1/fav/E9pWF1hKa2zEwgYY2_RmY-j8w71vStG-p1MXD9-pe5hv1hiaE5IbeGBzPaSKokDzgHm-i3bzZjppDwzD2IUz_w:f57b609d64291580641cf6e2ac180774"}]}}"##;

    #[test]
    fn parses_a_recorded_answer() {
        let (result, raw) = parse_response(RECORDED_EN_GB.as_bytes(), 200, Some(10)).unwrap();
        assert_eq!(raw["query"]["market"], "en-gb");
        let got: Vec<_> = result.hits.iter().map(|h| (h.url.as_str(), h.title.as_str(), h.published.is_none())).collect();
        assert_eq!(
            got,
            [
                ("https://weather.metoffice.gov.uk/forecast/uk", "UK Forecast", true),
                ("https://weather.metoffice.gov.uk/forecast/gcpuvk7px", "Weather", true),
            ]
        );
        assert!(result.hits.iter().all(|h| h.snippet.as_deref().is_some_and(|s| !s.is_empty())));
    }

    #[test]
    fn a_body_without_results_is_no_hits_and_a_broken_one_is_an_error() {
        let (result, _) = parse_response(br#"{"search_id":"x","web":{}}"#, 200, None).unwrap();
        assert!(result.hits.is_empty());
        let (result, _) = parse_response(br#"{"search_id":"x"}"#, 200, None).unwrap();
        assert!(result.hits.is_empty());
        let (result, _) = parse_response(br#"{"web":{"results":null}}"#, 200, None).unwrap();
        assert!(result.hits.is_empty());
        assert_matches!(parse_response(b"<html>", 200, None), Err(WebError::UpstreamError { .. }));
        assert_matches!(parse_response(br#"{"web":"x"}"#, 200, None), Err(WebError::UpstreamError { .. }));
    }

    #[test]
    fn a_result_that_does_not_decode_is_left_out_and_the_others_kept() {
        let body = br#"{"web":{"results":[
            {"title":"no url"},
            {"url":"https://a.example/","title":"A","published_date":20260101},
            {"url":7},
            {"url":"javascript:alert(1)","title":"script"},
            {"url":"data:text/html,x","title":"data"},
            {"url":"https://b.example/","title":"B","snippet":"s"}
        ]}}"#;
        let (result, _) = parse_response(body, 200, Some(10)).unwrap();
        let got: Vec<_> = result.hits.iter().map(|h| (h.url.as_str(), h.published.as_deref())).collect();
        assert_eq!(got, [("https://a.example/", None), ("https://b.example/", None)]);
        // The cap counts the hits kept, not the entries read.
        let (result, _) = parse_response(body, 200, Some(1)).unwrap();
        assert_eq!(result.hits.len(), 1);
    }

    #[test]
    fn each_refusal_is_its_own_failure() {
        assert_matches!(status_error(429, b"slow down", "stn_k"), WebError::RateLimited { .. });
        for status in [401, 403] {
            // Nothing of a body that may echo the refused key.
            assert_matches!(
                status_error(status, br#"{"error":"invalid key stn_live_123"}"#, "stn_k"),
                WebError::UpstreamError { status: Some(s), ref detail }
                    if s == status && detail == "Staan refused the API key"
            );
        }
        // A large refusal is cut, on a character boundary, and says how big it was.
        let page = "é".repeat(MAX_ERROR_DETAIL_BYTES);
        let WebError::UpstreamError { detail, .. } = status_error(404, page.as_bytes(), "stn_k") else { panic!() };
        assert!(detail.len() < MAX_ERROR_DETAIL_BYTES + 32, "{}", detail.len());
        assert!(detail.ends_with(&format!("… ({} bytes)", page.len())), "{detail}");
        assert_matches!(status_error(404, b"short", "stn_k"), WebError::UpstreamError { ref detail, .. } if detail == "short");
        // The key sent is scrubbed from any body kept.
        assert_matches!(
            status_error(502, b"Authorization: Bearer stn_k echo", "stn_k"),
            WebError::UpstreamError { ref detail, .. } if detail == "Authorization: Bearer [redacted] echo"
        );
        for status in [400, 404, 500, 503] {
            assert_matches!(
                status_error(status, b"x", "stn_k"),
                WebError::UpstreamError { status: Some(s), ref detail } if s == status && !detail.contains("API key")
            );
        }
    }
}
