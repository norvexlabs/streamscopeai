//! Wire-format-agnostic types for web search and fetch.
//!
//! These shapes flow through the [`crate::web::service`] pipeline.
//! Provider modules translate to/from upstream wire formats; the MCP virtual
//! server translates from these to MCP `tools/call` content blocks.

use crate::config::tool_rules::WebInterceptKind;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use utoipa::ToSchema;

/// Configured web-search backend. Mirrors [`crate::config::model_map::Provider`]
/// in spirit — string enum, snake_case wire format, parser tolerant of
/// shorthand forms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum WebProvider {
    /// SearXNG meta-search (free, self-hosted, no API key): the tenant's own
    /// instance, at its `endpoint`.
    Searxng,
    /// Staan web search API (EU, keyed): `GET /v2/search/web` with the tenant's
    /// key as a bearer token.
    Staan,
}

impl WebProvider {
    /// Stable wire string used for audit (`web_audit.backend`) and the
    /// admin UI dropdown.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Searxng => "searxng",
            Self::Staan => "staan",
        }
    }

    /// Tolerant parser used by config-sync when reading a tenant's
    /// `web_search.backend` JSONB value. Falls through to `None` on any
    /// unrecognised string — caller decides how to surface.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "searxng" | "searx" => Some(Self::Searxng),
            "staan" => Some(Self::Staan),
            _ => None,
        }
    }

    /// Whether this provider requires a credential: Staan's key; SearXNG has
    /// none.
    pub fn requires_credential(&self) -> bool {
        !matches!(self, Self::Searxng)
    }
}

/// Staan's search market: the locale its results are ranked for, the closed
/// set its API reference lists for `market`. An unset market sends none, and
/// Staan applies its own default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub enum StaanMarket {
    #[serde(rename = "fr-fr")]
    FrFr,
    #[serde(rename = "de-de")]
    DeDe,
    #[serde(rename = "en-us")]
    EnUs,
    #[serde(rename = "en-gb")]
    EnGb,
    #[serde(rename = "en-fr")]
    EnFr,
    #[serde(rename = "en-ca")]
    EnCa,
    #[serde(rename = "en-au")]
    EnAu,
    #[serde(rename = "en-in")]
    EnIn,
    #[serde(rename = "en-ie")]
    EnIe,
    #[serde(rename = "en-nz")]
    EnNz,
    #[serde(rename = "en-sg")]
    EnSg,
    #[serde(rename = "en-za")]
    EnZa,
}

impl StaanMarket {
    /// The wire value Staan reads.
    pub fn code(self) -> &'static str {
        match self {
            Self::FrFr => "fr-fr",
            Self::DeDe => "de-de",
            Self::EnUs => "en-us",
            Self::EnGb => "en-gb",
            Self::EnFr => "en-fr",
            Self::EnCa => "en-ca",
            Self::EnAu => "en-au",
            Self::EnIn => "en-in",
            Self::EnIe => "en-ie",
            Self::EnNz => "en-nz",
            Self::EnSg => "en-sg",
            Self::EnZa => "en-za",
        }
    }

    /// The market a caller's language hint names: a market's own tag
    /// (`en-GB`, `en_gb`), else the hint's language (`fr-BE` → French) when
    /// it has one market — French and German have one each, English takes the
    /// United States one. Any other hint names none.
    pub fn for_language(language: &str) -> Option<Self> {
        let tag = language.trim().to_ascii_lowercase().replace('_', "-");
        if let Ok(market) = serde_json::from_value(serde_json::Value::String(tag.clone())) {
            return Some(market);
        }
        match tag.split('-').next().unwrap_or_default() {
            "fr" => Some(Self::FrFr),
            "de" => Some(Self::DeDe),
            "en" => Some(Self::EnUs),
            _ => None,
        }
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
            start_index: _,    // gateway-computed
            total_length: _,   // gateway-computed
            next_start_index: _, // gateway-computed
            notice: _,         // gateway-written
        } = self;
        let mut parts = vec![extracted_text.clone(), url.clone(), final_url.clone(), content_type.clone()];
        parts.extend(redirect_chain.iter().cloned());
        parts.join("\n")
    }
}

/// Caller-supplied fetch arguments. Every field but `url` is optional with
/// the whole page as its default, so a definition declaring `url` alone (an
/// administrator's substitution rule) keeps working; a field the executor does
/// not know is ignored.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct FetchRequest {
    pub url: String,
    /// The most characters (Unicode scalar values) of the page's text to
    /// return. Absent: everything from `start_index` on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_length: Option<u64>,
    /// The character of the page's text to start from — the `next_start_index`
    /// of a result that was cut. Absent: 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_index: Option<u64>,
}

/// Whether the caller of a fetch can ask for the rest of a cut page: its tool
/// definition declares `start_index`. A cut result names where to resume only
/// then — a model told to pass an argument its tool does not have cannot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Paging {
    Offered,
    NotOffered,
}

/// The optional arguments the definition a model calls declares: what a
/// failed call may tell it to pass ([`WebError::model_text`]) and whether a
/// cut page may name where to resume ([`Self::paging`]). A model told to pass
/// an argument its tool does not have cannot. The default declares none.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeclaredArgs {
    pub max_length: bool,
    pub start_index: bool,
    pub max_results: bool,
}

impl DeclaredArgs {
    /// The built-in web server's own definitions, which declare every one.
    pub const ALL: Self = Self { max_length: true, start_index: true, max_results: true };

    /// The arguments a JSON Schema's `properties` declares as the whole number
    /// the executor reads ([`declared_integer`]), for every argument
    /// [`WebInterceptKind::optional_integer_args`] lists; one of another type
    /// is not declared, since a model passing it as written would fail the
    /// call.
    pub fn of_schema(parameters: &serde_json::Value) -> Self {
        let mut declared = Self::default();
        for kind in [WebInterceptKind::Fetch, WebInterceptKind::Search] {
            for &name in kind.optional_integer_args() {
                if let Some(slot) = declared.slot(name) {
                    *slot = declared_integer(parameters, name) == Some(true);
                }
            }
        }
        declared
    }

    /// Whether `name` — one of [`WebInterceptKind::optional_integer_args`] —
    /// is declared: read through [`Self::slot`], the one map from a name to
    /// its field, so a name it holds is never one this misses.
    pub fn declares(&self, name: &str) -> bool {
        let mut held = *self;
        held.slot(name).is_some_and(|declared| *declared)
    }

    /// The field holding `name`; `None` for a name no executor reads.
    fn slot(&mut self, name: &str) -> Option<&mut bool> {
        match name {
            "max_length" => Some(&mut self.max_length),
            "start_index" => Some(&mut self.start_index),
            "max_results" => Some(&mut self.max_results),
            _ => None,
        }
    }

    pub fn paging(self) -> Paging {
        if self.start_index { Paging::Offered } else { Paging::NotOffered }
    }
}

/// What a JSON Schema's `parameters` says of `key` as the whole number the
/// executor's unsigned fields ([`FetchRequest`], [`SearchRequest`]) decode:
/// - `Some(true)`: typed `integer` — by a plain `type` naming `integer` and
///   nothing but `null` beside it (`"integer"`, `["integer", "null"]`: a
///   `null` reads as the argument left out), or, with no plain `type`, by an
///   `anyOf`/`oneOf` whose members are typed the same way and include an
///   `integer` one;
/// - `Some(false)`: a plain `type` naming no `integer` (`"string"`,
///   `"number"`, which may be fractional) — a type the executor can never
///   decode;
/// - `None`: no claim either way — `key` absent, untyped (a description
///   only, or an empty `type` array), or a union some of whose members the executor would refuse at
///   call time (`["integer", "string"]`).
pub fn declared_integer(parameters: &serde_json::Value, key: &str) -> Option<bool> {
    let property = parameters.get("properties")?.get(key)?;
    if let Some(ty) = property.get("type") {
        return match type_names(ty)? {
            names if names.is_empty() => None,
            names if !names.contains(&"integer") => Some(false),
            names if names.iter().all(|t| *t == "integer" || *t == "null") => Some(true),
            _ => None,
        };
    }
    let members = ["anyOf", "oneOf"].iter().find_map(|k| property.get(*k)?.as_array())?;
    let mut names = Vec::new();
    for member in members {
        names.extend(type_names(member.get("type")?)?);
    }
    (names.contains(&"integer") && names.iter().all(|t| *t == "integer" || *t == "null")).then_some(true)
}

/// The type names a JSON Schema `type` holds (a string or an array of them);
/// `None` for any other shape.
fn type_names(ty: &serde_json::Value) -> Option<Vec<&str>> {
    match ty {
        serde_json::Value::String(t) => Some(vec![t.as_str()]),
        serde_json::Value::Array(types) => types.iter().map(serde_json::Value::as_str).collect(),
        _ => None,
    }
}

impl FetchResult {
    /// Cut `extracted_text` to the `[start_index, start_index + max_length)`
    /// characters `req` asks for, recording where the slice sits in the whole
    /// text and, when more follows, a notice saying so. A start at or past the
    /// end is no error: an empty slice whose notice says nothing is left (a
    /// page may have shrunk since the call that gave the index).
    pub fn take_slice(&mut self, req: &FetchRequest, paging: Paging) {
        let total = self.extracted_text.chars().count();
        let start = usize::try_from(req.start_index.unwrap_or(0)).unwrap_or(usize::MAX).min(total);
        let len = req.max_length.map_or(usize::MAX, |n| usize::try_from(n).unwrap_or(usize::MAX));
        let end = start.saturating_add(len).min(total);
        if start > 0 || end < total {
            self.extracted_text = self.extracted_text.chars().skip(start).take(end - start).collect();
        }
        self.extracted_size = self.extracted_text.len();
        self.start_index = start;
        self.total_length = total;
        self.next_start_index = None;
        self.notice = if start >= total && total > 0 {
            Some(format!("No more content: the page has {total} characters."))
        } else if end < total {
            match paging {
                Paging::Offered => {
                    self.next_start_index = Some(end);
                    Some(format!(
                        "The page was cut at character {end} of {total}; call again with start_index {end} for the rest."
                    ))
                }
                Paging::NotOffered => Some(format!("The page was cut at character {end} of {total}.")),
            }
        } else {
            None
        };
    }
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
    /// whitespace normalised), or a text body as it came: the slice of it
    /// the request asked for ([`FetchResult::take_slice`]).
    pub extracted_text: String,
    /// Hop-by-hop redirect URLs the fetcher traversed (excluding the final
    /// URL). Empty when no redirects occurred.
    pub redirect_chain: Vec<String>,
    /// `extracted_text.len()`: the bytes of the slice returned.
    pub extracted_size: usize,
    /// Original response body byte count (pre-extraction).
    pub raw_size: usize,
    /// The character of the whole text the slice starts at.
    #[serde(default)]
    pub start_index: usize,
    /// The whole text's length, in characters.
    #[serde(default)]
    pub total_length: usize,
    /// Where the rest starts, when the slice was cut and the caller can ask
    /// for it ([`Paging::Offered`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_start_index: Option<usize>,
    /// The gateway's note on the slice: cut (and where to resume), or nothing
    /// left. Absent for a whole page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notice: Option<String>,
}

/// Typed errors surfaced from any layer of the websearch pipeline. A model is
/// told one through [`WebError::model_text`]; the audit pipeline uses the
/// discriminator string for `web_audit.error_category`.
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
    /// The call's arguments do not parse as the tool's (a missing `url` or
    /// `query`, a value of the wrong type). The text is the parser's, about
    /// the caller's own arguments.
    #[error("invalid arguments: {0}")]
    InvalidArguments(String),
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
            // The caller's own arguments, never the administrator's
            // configuration: a count of misconfigurations must not count a
            // model's typo.
            Self::InvalidArguments(_) => "invalid_arguments",
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

    /// What the model is told this failure is, in the vocabulary a model knows
    /// a web tool's failures by (Anthropic's web fetch and web search error
    /// codes) — never the audit category, which names the gateway's own
    /// mechanisms. `op` is the call: a search refusing its own backend's
    /// address is the platform's failure, a fetch refusing an address is the
    /// model's to fix.
    pub fn model_code(&self, op: crate::config::tool_rules::WebInterceptKind) -> ModelErrorCode {
        use crate::config::tool_rules::WebInterceptKind::{Fetch, Search};
        match (self, op) {
            (Self::InvalidArguments(_), _) => ModelErrorCode::InvalidToolInput,
            (Self::InvalidUrl(_) | Self::SchemeRefused(_), Fetch) => ModelErrorCode::InvalidToolInput,
            (Self::SsrfRefused(_) | Self::UrlFilterDenied { .. }, Fetch) => ModelErrorCode::UrlNotAllowed,
            (Self::UpstreamError { .. } | Self::Transport(_), Fetch) => ModelErrorCode::UrlNotAccessible,
            (Self::Oversized { .. }, Fetch) => ModelErrorCode::ContentTooLarge,
            (Self::RateLimited { .. }, _) => ModelErrorCode::TooManyRequests,
            (Self::PolicyBlocked(_), Fetch) => ModelErrorCode::UrlNotAllowed,
            (Self::PolicyBlocked(_), Search) => ModelErrorCode::InvalidToolInput,
            (
                Self::InvalidUrl(_)
                | Self::SchemeRefused(_)
                | Self::SsrfRefused(_)
                | Self::UrlFilterDenied { .. }
                | Self::UpstreamError { .. }
                | Self::Transport(_)
                | Self::Oversized { .. },
                Search,
            )
            | (
                Self::NoBackend
                | Self::MissingCredential { .. }
                | Self::InvalidConfig(_)
                | Self::Internal(_)
                | Self::Cancelled,
                _,
            ) => ModelErrorCode::Unavailable,
        }
    }

    /// The text a model's failed web call is answered with — on `/mcp/web`
    /// (an `isError` result) and by a substitution (an error tool result):
    /// the [`Self::model_code`] first, then what to do about it. No upstream,
    /// network or database detail reaches the conversation; only the
    /// parser's words about the model's own arguments, and a policy block's
    /// rule description (as the client is told on a block).
    /// Invalid arguments name only the optional arguments `declared` holds:
    /// the definition the model called; the parser's words are cut to
    /// [`MODEL_DETAIL_MAX_BYTES`] (they quote the offending value whole).
    pub fn model_text(&self, op: WebInterceptKind, declared: DeclaredArgs) -> String {
        use WebInterceptKind::{Fetch, Search};
        let code = self.model_code(op);
        let bounded = |detail: &str| -> String {
            if detail.len() <= MODEL_DETAIL_MAX_BYTES {
                return detail.to_string();
            }
            format!("{}…", &detail[..detail.floor_char_boundary(MODEL_DETAIL_MAX_BYTES)])
        };
        let optional = |kind: WebInterceptKind| {
            let named: Vec<String> =
                kind.optional_integer_args().iter().filter(|n| declared.declares(n)).map(|n| format!("`{n}`")).collect();
            match named.as_slice() {
                [] => String::new(),
                [one] => format!(", and optionally {one} as a whole number"),
                many => format!(", and optionally {} as whole numbers", many.join(" and ")),
            }
        };
        let what = match (self, op) {
            (Self::InvalidArguments(detail), Fetch) => format!(
                "the arguments do not match the tool ({}); pass an absolute http(s) `url`{}.",
                bounded(detail),
                optional(Fetch)
            ),
            (Self::InvalidArguments(detail), Search) => format!(
                "the arguments do not match the tool ({}); pass the search terms as `query`{}.",
                bounded(detail),
                optional(Search)
            ),
            (Self::PolicyBlocked(_), _) => self.to_string(),
            _ => match code {
                ModelErrorCode::InvalidToolInput => {
                    "the URL is not an absolute http or https address; pass one such as https://example.com/page.".to_string()
                }
                ModelErrorCode::UrlNotAllowed => {
                    "this address may not be fetched from here (a private network, or one an administrator does not allow); fetch a public page instead.".to_string()
                }
                ModelErrorCode::UrlNotAccessible => {
                    "the page could not be reached (the site did not answer, or the connection failed); try again later or try another source.".to_string()
                }
                ModelErrorCode::ContentTooLarge => {
                    "the page is larger than the most that may be fetched from here, whatever the arguments; use another source.".to_string()
                }
                ModelErrorCode::TooManyRequests => {
                    "too many web requests right now; wait a moment before trying again.".to_string()
                }
                ModelErrorCode::Unavailable => match op {
                    Search => "web search is not available right now; answer without it, or try again later.".to_string(),
                    Fetch => "fetching pages is not available right now; answer without it, or try again later.".to_string(),
                },
            },
        };
        format!("{}: {what}", code.as_str())
    }
}

/// The most of an invalid-arguments detail (the argument parser's words)
/// [`WebError::model_text`] carries into the conversation; past it the detail
/// is cut at a char boundary and ends with `…`.
const MODEL_DETAIL_MAX_BYTES: usize = 300;

/// The failure of a web call as a model is told it: Anthropic's web fetch and
/// web search error codes, the vocabulary models are trained on. A closed set —
/// a protocol whose own set is narrower maps from it
/// (`translate::anthropic_web_search_error_code`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelErrorCode {
    InvalidToolInput,
    UrlNotAllowed,
    UrlNotAccessible,
    ContentTooLarge,
    TooManyRequests,
    Unavailable,
}

impl ModelErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidToolInput => "invalid_tool_input",
            Self::UrlNotAllowed => "url_not_allowed",
            Self::UrlNotAccessible => "url_not_accessible",
            Self::ContentTooLarge => "content_too_large",
            Self::TooManyRequests => "too_many_requests",
            Self::Unavailable => "unavailable",
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
            WebProvider::Staan,
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
        assert_eq!(WebProvider::parse(" Staan "), Some(WebProvider::Staan));
        assert_eq!(WebProvider::parse("nonsense"), None);
        // A code outside the enum is unknown.
        for unknown in ["", "staan2", "searxng-x"] {
            assert_eq!(WebProvider::parse(unknown), None, "{unknown}");
        }
    }

    #[test]
    fn a_staan_markets_code_is_its_wire_value() {
        use StaanMarket::*;
        for m in [FrFr, DeDe, EnUs, EnGb, EnFr, EnCa, EnAu, EnIn, EnIe, EnNz, EnSg, EnZa] {
            assert_eq!(serde_json::to_value(m).unwrap(), serde_json::json!(m.code()), "{m:?}");
        }
    }

    #[test]
    fn searxng_does_not_require_credential() {
        assert!(!WebProvider::Searxng.requires_credential());
    }

    #[test]
    fn staan_requires_credential() {
        assert!(WebProvider::Staan.requires_credential());
    }

    /// Every failure, on either call, lands on a code of the closed set, and
    /// the text the model reads starts with it. The audit category is not
    /// that code: dashboards keep reading `category()`.
    #[test]
    fn every_failure_tells_the_model_a_code_it_knows() {
        use crate::config::tool_rules::WebInterceptKind::{Fetch, Search};
        let all = [
            WebError::NoBackend,
            WebError::MissingCredential { backend: WebProvider::Staan },
            WebError::InvalidConfig("x".into()),
            WebError::InvalidUrl("x".into()),
            WebError::SsrfRefused("x".into()),
            WebError::SchemeRefused("file".into()),
            WebError::UrlFilterDenied { filter_id: "f".into(), reason: "r".into(), url: "u".into() },
            WebError::UpstreamError { status: Some(500), detail: "secret upstream body".into() },
            WebError::RateLimited { detail: "x".into() },
            WebError::Oversized { limit_bytes: 1 },
            WebError::Transport("connect 10.0.0.7 refused".into()),
            WebError::Internal("x".into()),
            WebError::Cancelled,
            WebError::PolicyBlocked("no fetches of example.org".into()),
            WebError::InvalidArguments("missing field `url`".into()),
        ];
        for e in &all {
            for op in [Search, Fetch] {
                let text = e.model_text(op, DeclaredArgs::ALL);
                assert!(text.starts_with(&format!("{}: ", e.model_code(op).as_str())), "{e:?} {op:?}: {text}");
                for leak in ["secret upstream body", "10.0.0.7", "tenant", "gateway"] {
                    assert!(!text.contains(leak), "{e:?} {op:?} leaks {leak:?}: {text}");
                }
            }
        }
        use ModelErrorCode::*;
        let code = |e: &WebError, op| e.model_code(op);
        assert_eq!(code(&all[4], Fetch), UrlNotAllowed);
        assert_eq!(code(&all[4], Search), Unavailable, "a search refusing its own backend is not the model's input");
        assert_eq!(code(&all[6], Fetch), UrlNotAllowed);
        assert_eq!(code(&all[7], Fetch), UrlNotAccessible);
        assert_eq!(code(&all[7], Search), Unavailable);
        assert_eq!(code(&all[8], Search), TooManyRequests);
        assert_eq!(code(&all[9], Fetch), ContentTooLarge);
        // No argument changes what a fetch reads (a slice is cut after the
        // capped read), so an oversized page sends the model elsewhere.
        assert_eq!(
            all[9].model_text(Fetch, DeclaredArgs::ALL),
            "content_too_large: the page is larger than the most that may be fetched from here, whatever the arguments; use another source."
        );
        assert_eq!(code(&all[14], Search), InvalidToolInput);
        assert_eq!(code(&all[13], Fetch), UrlNotAllowed);
        assert!(all[13].model_text(Fetch, DeclaredArgs::ALL).contains("no fetches of example.org"), "a block names its rule");
        assert!(all[14].model_text(Fetch, DeclaredArgs::ALL).contains("missing field `url`"), "bad arguments say which");
        // The audit category names the caller's arguments, not the
        // administrator's configuration (positive control beside it).
        assert_eq!(all[14].category(), "invalid_arguments");
        assert_eq!(WebError::InvalidConfig("x".into()).category(), "config_invalid");
        assert_eq!(all[4].category(), "ssrf_refused");
    }

    /// The parser's detail reaches the model bounded: one quoting a 200 KB
    /// offending value (multi-byte, so the cut must land on a char boundary)
    /// is cut, a short one is kept whole (positive control).
    #[test]
    fn an_invalid_arguments_detail_reaches_the_model_bounded() {
        use crate::config::tool_rules::WebInterceptKind::{Fetch, Search};
        let huge = format!("invalid type: string \"{}\", expected u64", "é".repeat(100_000));
        for op in [Fetch, Search] {
            let text = WebError::InvalidArguments(huge.clone()).model_text(op, DeclaredArgs::ALL);
            assert!(text.len() < MODEL_DETAIL_MAX_BYTES + 400, "{op:?}: {} bytes", text.len());
            assert!(text.contains("…); pass "), "{op:?}: {text}");
            let short = "missing field `url`";
            let text = WebError::InvalidArguments(short.into()).model_text(op, DeclaredArgs::ALL);
            assert!(text.contains(&format!("({short}); pass ")), "{op:?}: {text}");
        }
    }

    /// Bad arguments name only the optional arguments the called definition
    /// declares: all of them for one that declares them, none for one that
    /// declares none.
    #[test]
    fn bad_arguments_name_only_the_arguments_the_tool_declares() {
        use crate::config::tool_rules::WebInterceptKind::{Fetch, Search};
        let e = WebError::InvalidArguments("missing field `url`".into());
        let fetch_all = e.model_text(Fetch, DeclaredArgs::ALL);
        assert!(fetch_all.ends_with("`url`, and optionally `max_length` and `start_index` as whole numbers."), "{fetch_all}");
        let search_all = e.model_text(Search, DeclaredArgs::ALL);
        assert!(search_all.ends_with("`query`, and optionally `max_results` as a whole number."), "{search_all}");
        for op in [Fetch, Search] {
            let none = e.model_text(op, DeclaredArgs::default());
            for arg in ["max_length", "start_index", "max_results", "optionally"] {
                assert!(!none.contains(arg), "{op:?} names {arg} it does not declare: {none}");
            }
        }
        let schema = serde_json::json!({"type": "object", "properties": {"url": {"type": "string"}, "max_length": {"type": "integer"}}});
        let declared = DeclaredArgs::of_schema(&schema);
        assert_eq!(declared, DeclaredArgs { max_length: true, start_index: false, max_results: false });
        assert_eq!(declared.paging(), Paging::NotOffered);
        let one = e.model_text(Fetch, declared);
        assert!(one.ends_with("`url`, and optionally `max_length` as a whole number."), "{one}");
        assert_eq!(DeclaredArgs::ALL.paging(), Paging::Offered);
        // Declared only as the integer the executor reads; another type
        // (`Some(false)`) only for a plain `type` naming no integer, and an
        // empty `type` array makes no claim.
        for (prop, verdict) in [
            (serde_json::json!({"type": "integer"}), Some(true)),
            (serde_json::json!({"type": ["integer", "null"]}), Some(true)),
            (serde_json::json!({"anyOf": [{"type": "integer"}, {"type": "null"}]}), Some(true)),
            (serde_json::json!({"oneOf": [{"type": "integer", "minimum": 0}]}), Some(true)),
            (serde_json::json!({"type": "string"}), Some(false)),
            (serde_json::json!({"type": "number"}), Some(false)),
            (serde_json::json!({"type": ["string", "null"]}), Some(false)),
            (serde_json::json!({"type": "string", "anyOf": [{"type": "integer"}]}), Some(false)),
            (serde_json::json!({"type": ["integer", "string"]}), None),
            (serde_json::json!({"anyOf": [{"type": "integer"}, {"type": "string"}]}), None),
            (serde_json::json!({"anyOf": [{"type": "integer"}, {"minimum": 0}]}), None),
            (serde_json::json!({"anyOf": [{"type": "null"}]}), None),
            (serde_json::json!({"type": []}), None),
            (serde_json::json!({"description": "where to start"}), None),
            (serde_json::json!({}), None),
        ] {
            let schema = serde_json::json!({"properties": {"url": {"type": "string"}, "start_index": prop}});
            assert_eq!(DeclaredArgs::of_schema(&schema).start_index, verdict == Some(true), "{prop}");
            assert_eq!(declared_integer(&schema, "start_index"), verdict, "{prop}");
            assert_eq!(declared_integer(&schema, "max_length"), None);
        }
    }

    /// Every optional argument an executor reads is one `DeclaredArgs` holds:
    /// the built-in definitions declare each, a schema typing it `integer`
    /// declares it alone, and the empty default declares none.
    #[test]
    fn every_optional_argument_an_executor_reads_is_held() {
        for kind in [WebInterceptKind::Fetch, WebInterceptKind::Search] {
            for &name in kind.optional_integer_args() {
                assert!(DeclaredArgs::ALL.declares(name), "{kind:?} {name}");
                assert!(!DeclaredArgs::default().declares(name), "{kind:?} {name}");
                let schema = serde_json::json!({"properties": {name: {"type": "integer"}}});
                assert!(DeclaredArgs::of_schema(&schema).declares(name), "{kind:?} {name}");
            }
        }
        assert!(!DeclaredArgs::ALL.declares("url"), "a required argument is not an optional one");
    }

    fn page(text: &str) -> FetchResult {
        FetchResult {
            url: "https://a.test/".into(),
            final_url: "https://a.test/".into(),
            content_type: "text/plain".into(),
            status: 200,
            extracted_text: text.into(),
            redirect_chain: Vec::new(),
            extracted_size: text.len(),
            raw_size: text.len(),
            start_index: 0,
            total_length: 0,
            next_start_index: None,
            notice: None,
        }
    }

    fn ask(max_length: Option<u64>, start_index: Option<u64>) -> FetchRequest {
        FetchRequest { url: "https://a.test/".into(), max_length, start_index }
    }

    /// A slice is counted in characters, says where the rest starts only to
    /// a caller that can ask for it, and resumes exactly where it stopped.
    #[test]
    fn a_page_is_cut_in_characters_and_resumes_where_it_stopped() {
        let text = "héllo wörld";
        // Positive control: no paging argument returns the whole page.
        let mut whole = page(text);
        whole.take_slice(&ask(None, None), Paging::Offered);
        assert_eq!((whole.extracted_text.as_str(), whole.notice.as_deref(), whole.total_length), (text, None, 11));

        let mut first = page(text);
        first.take_slice(&ask(Some(4), None), Paging::Offered);
        assert_eq!(first.extracted_text, "héll");
        assert_eq!(first.extracted_size, "héll".len());
        assert_eq!(first.next_start_index, Some(4));
        assert!(first.notice.as_deref().is_some_and(|n| n.contains("start_index 4")), "{:?}", first.notice);

        let mut rest = page(text);
        rest.take_slice(&ask(Some(100), Some(4)), Paging::Offered);
        assert_eq!(format!("{}{}", first.extracted_text, rest.extracted_text), text);
        assert_eq!((rest.start_index, rest.next_start_index, rest.notice.as_deref()), (4, None, None));

        // A caller whose tool has no `start_index` is told the page was cut, not how to resume.
        let mut cut = page(text);
        cut.take_slice(&ask(Some(4), None), Paging::NotOffered);
        assert_eq!(cut.next_start_index, None);
        let notice = cut.notice.expect("a cut page says so");
        assert!(notice.contains("cut") && !notice.contains("start_index"), "{notice}");

        // Past the end: an empty slice saying nothing is left, not an error.
        let mut past = page(text);
        past.take_slice(&ask(None, Some(50)), Paging::Offered);
        assert_eq!((past.extracted_text.as_str(), past.start_index), ("", 11));
        assert!(past.notice.is_some_and(|n| n.contains("No more content")));
        let mut empty = page("");
        empty.take_slice(&ask(None, None), Paging::Offered);
        assert_eq!(empty.notice, None, "an empty page is whole");
    }

    #[test]
    fn error_categories_are_stable() {
        let e = WebError::SsrfRefused("loopback".into());
        assert_eq!(e.category(), "ssrf_refused");
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
            start_index: 0,
            total_length: 12,
            next_start_index: None,
            notice: None,
        };
        let c = r.classifiable();
        for marker in
            ["PAYLOAD_BODY", "PAYLOAD_URL", "PAYLOAD_FINAL", "PAYLOAD_CTYPE", "PAYLOAD_HOP"]
        {
            assert!(c.contains(marker), "{marker} reaches the model unscanned:\n{c}");
        }
    }
}
