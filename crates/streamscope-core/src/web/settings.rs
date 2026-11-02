//! Per-tenant Web settings — typed projection of the `system_settings.web`
//! key (one nested JSON object, same pattern as `tool_rules`).
//!
//! Lives on `TenantConfig.web`; populated by the proxy's config-sync
//! loop from the admin-pushed snapshot. Defaults: no search backend → MCP
//! `tools/list` serves `web_fetch` alone and a search short-circuits with
//! [`crate::web::WebError::NoBackend`].

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::types::WebProvider;

/// Where the `web_fetch` tool extracts content from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FetchProvider {
    /// Built-in fetch: tenant's own `reqwest` client → SSRF guard →
    /// HTML→markdown extraction. No external dependency. Default.
    #[default]
    Builtin,
    /// Tavily `extract` API. Requires the Tavily backend or its key.
    Tavily,
}

/// The destination lists attached to the Web tool, as the config body carries
/// them: every attached list's canonical entries, flattened by mode.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebDestinationLists {
    pub allow: Vec<String>,
    pub block: Vec<String>,
    /// A list is attached as allow — only what `allow` matches passes, so an
    /// attached allow list with no entries passes nothing.
    #[serde(default)]
    pub allow_attached: bool,
}

/// [`WebDestinationLists`] parsed: a URL passes when no allow list is attached
/// or one matches it, and no block list matches it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WebDestinations {
    pub allow: streamscope_client_templates::destination::DestinationSet,
    /// A list is attached as allow, whatever `allow` holds.
    pub allow_attached: bool,
    pub block: streamscope_client_templates::destination::DestinationSet,
    /// A blocked entry did not parse: every URL is refused, since passing one
    /// could pass what the administrator blocked.
    pub unreadable_block: bool,
}

impl WebDestinations {
    /// Parse the shipped entries (admin-api stores canonical entries only). An
    /// allowed entry that does not parse is left out with a warning — it
    /// allows less; a blocked one sets [`Self::unreadable_block`].
    pub fn from_lists(lists: &WebDestinationLists) -> Self {
        use streamscope_client_templates::destination::DestinationSet;
        let (allow, skipped) = DestinationSet::parse_allowed(&lists.allow);
        for (entry, err) in skipped {
            tracing::warn!(%entry, "allowed web destination left out: {err}");
        }
        let (block, unreadable_block) = match DestinationSet::parse_union(&lists.block) {
            Ok(set) => (set, false),
            Err(err) => {
                tracing::warn!("a blocked web destination does not parse, every URL is refused: {err}");
                (DestinationSet::default(), true)
            }
        };
        let allow_attached = lists.allow_attached || !lists.allow.is_empty();
        Self { allow, allow_attached, block, unreadable_block }
    }
}

/// Per-tenant configuration for the built-in web-search MCP.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct WebSettings {
    /// Configured search backend. `None` = no search: `web_search` is not
    /// listed and a call short-circuits; `web_fetch` is served regardless.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<WebProvider>,

    /// Custom upstream endpoint URL. Required for SearXNG (operator-supplied
    /// instance), optional for paid providers (override their well-known URL
    /// — useful for regional endpoints or pen-tests against a sandbox).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,

    /// Google CSE engine ID (`cx`). Required when backend is
    /// [`WebProvider::GoogleCse`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine_id: Option<String>,

    /// Which extractor `web_fetch` uses.
    #[serde(default)]
    pub fetch_provider: FetchProvider,

    /// Default maximum hits returned by `web_search` when the caller doesn't
    /// override. Hard upper bound: the service caps at 50 regardless.
    #[serde(default = "default_max_results")]
    pub max_results: u32,

    /// The destination lists attached to the Web tool, resolved. Not part of
    /// the stored settings: admin-api reads them from the lists and ships them
    /// beside the settings ([`WebDestinationLists`]).
    #[serde(skip)]
    pub destinations: WebDestinations,

    /// Maximum bytes the built-in fetcher will read from a single response.
    /// Larger responses abort with [`super::types::WebError::Oversized`].
    #[serde(default = "default_fetch_max_bytes")]
    pub fetch_max_bytes: u64,

    /// Cap on `web_audit.provider_response` size (KB). Oversized
    /// payloads are stored as a `Stripped` placeholder per the
    /// "Nothing is silently discarded" invariant.
    #[serde(default = "default_provider_response_max_kb")]
    pub audit_provider_response_max_kb: u64,

    /// Maximum number of *substitution iterations* the agent loop may run
    /// before forwarding the upstream's last response unmodified. An
    /// iteration = one round of (dispatch intercepted tool calls →
    /// re-issue upstream). With `substitution_max_iterations = N`, the
    /// loop runs up to `N+1` upstream calls total: `N` substitution rounds
    /// (each ending with `pending_intercepted` non-empty and
    /// `round < N`) plus a final pass-through round. When the cap is hit
    /// with pending intercepted calls, the loop emits
    /// [`crate::audit::badge::AuditBadge::WebSubstitutionMaxIter`]
    /// and forwards the upstream's last response (plus a synthetic text
    /// marker) so the client sees something rather than an empty stream.
    #[serde(default = "default_substitution_max_iterations")]
    pub substitution_max_iterations: u32,

    /// Maximum number of intercepted tool-calls the substitution agent loop
    /// dispatches in parallel within a single round. Caps the
    /// `futures::stream::buffer_unordered` concurrency. Without this bound,
    /// a model emitting 20+ tool_uses in one round would spawn 20+
    /// concurrent SearXNG / paid-backend HTTP calls. Default `8` — tuned
    /// for the SearXNG dev container's modest concurrency budget; raise
    /// for paid backends with higher rate limits.
    #[serde(default = "default_substitution_max_parallel")]
    pub substitution_max_parallel: u32,

    /// Maximum total bytes of buffered SSE events the substitution agent
    /// loop will accumulate within a single round before bailing out. Caps
    /// `round_events: Vec<BufferedEvent>` so a misbehaving upstream that
    /// emits megabytes of streaming text before a tool_use can't blow up
    /// memory. When the cap is hit mid-round the loop forwards what's
    /// already buffered to the client (no substitute) and emits an
    /// `injection_block` with `reason="round_byte_cap"`. Default 8 MB.
    #[serde(default = "default_substitution_round_max_bytes")]
    pub substitution_round_max_bytes: u64,

    /// Maximum total bytes of the cumulative `DomainRequest` body re-sent
    /// upstream across substitution rounds. Each round splices an
    /// `assistant tool_use` + `user tool_result` pair onto
    /// `agent_loop_domain`, then re-serialises to the upstream protocol.
    /// Without a cap, a long-running loop with large tool-result payloads
    /// (e.g. several hundred KB of fetched HTML) grows the upstream body
    /// linearly until the model's context window or the upstream's request
    /// size limit refuses it. When this cap is exceeded mid-loop, the
    /// agent loop drops the oldest splice (one assistant tool_use message
    /// and the contiguous tool-result messages following it) and
    /// re-translates, repeating up to a bounded number of passes; if still
    /// over cap, the loop emits a
    /// [`crate::audit::badge::AuditBadge::WebSubstitutionHistoryCap`]
    /// audit badge plus an `injection_block` with
    /// `reason="history_byte_cap"`, then breaks out via the existing
    /// serialize-failed path. Default 32 MB.
    #[serde(default = "default_substitution_history_max_bytes")]
    pub substitution_history_max_bytes: u64,

    /// TTL for the cross-request mixed-pending cache, in seconds.
    ///
    /// When an upstream turn emits both real and intercepted `tool_use`
    /// blocks in the same round ("mixed-pending"), the agent loop
    /// dispatches the intercepted call for audit and parks the result in
    /// [`crate::web::MixedPendingCache`] keyed on `(tenant_id,
    /// session_id, tool_use_id)`. The next request in the same session
    /// drains the cache and splices the parked result into the
    /// conversation history as a synthesised
    /// `assistant tool_use → user tool_result` pair so the model sees what
    /// it asked for.
    ///
    /// Entries older than this TTL are pruned on read and on a periodic
    /// background sweep. Set to `0` to disable cross-request splicing
    /// entirely (mixed-pending then behaves as in step-1: dispatch +
    /// audit + drop). Default 3600 (one hour) — long enough for a human
    /// reading a model response and replying, short enough that a parked
    /// search result doesn't surface days later when the conversation
    /// has pivoted.
    #[serde(default = "default_mixed_pending_cache_ttl_seconds")]
    pub mixed_pending_cache_ttl_seconds: u64,
}

fn default_max_results() -> u32 {
    5
}

fn default_fetch_max_bytes() -> u64 {
    10 * 1024 * 1024 // 10 MB
}

fn default_provider_response_max_kb() -> u64 {
    1024
}

fn default_substitution_max_iterations() -> u32 {
    5
}

fn default_substitution_max_parallel() -> u32 {
    8
}

fn default_substitution_round_max_bytes() -> u64 {
    8 * 1024 * 1024 // 8 MB
}

fn default_substitution_history_max_bytes() -> u64 {
    32 * 1024 * 1024 // 32 MB
}

fn default_mixed_pending_cache_ttl_seconds() -> u64 {
    3600
}

impl Default for WebSettings {
    fn default() -> Self {
        Self {
            backend: None,
            endpoint: None,
            engine_id: None,
            fetch_provider: FetchProvider::default(),
            max_results: default_max_results(),
            destinations: WebDestinations::default(),
            fetch_max_bytes: default_fetch_max_bytes(),
            audit_provider_response_max_kb: default_provider_response_max_kb(),
            substitution_max_iterations: default_substitution_max_iterations(),
            substitution_max_parallel: default_substitution_max_parallel(),
            substitution_round_max_bytes: default_substitution_round_max_bytes(),
            substitution_history_max_bytes: default_substitution_history_max_bytes(),
            mixed_pending_cache_ttl_seconds: default_mixed_pending_cache_ttl_seconds(),
        }
    }
}

impl WebSettings {
    /// Hard upper bound on `max_results` regardless of caller / setting.
    pub const MAX_RESULTS_HARD_CAP: u32 = 50;

    /// Effective max-results for a request: `min(caller_request, setting,
    /// HARD_CAP)`. Used by the service to clamp both layers in one place.
    pub fn effective_max_results(&self, requested: Option<u32>) -> u32 {
        let want = requested.unwrap_or(self.max_results).max(1);
        want.min(self.max_results.max(1))
            .min(Self::MAX_RESULTS_HARD_CAP)
    }

    /// `true` when a search backend is configured — what `web_search` needs
    /// (`served_web_tools` lists it only then); `web_fetch` does not. SearXNG
    /// is configured only with an endpoint: there is no platform default to
    /// fall back on, so an endpoint-less row advertises no search.
    pub fn is_configured(&self) -> bool {
        match self.backend {
            None => false,
            Some(WebProvider::Searxng) => {
                self.endpoint.as_deref().is_some_and(|e| !e.trim().is_empty())
            }
            Some(_) => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_unconfigured() {
        let s = WebSettings::default();
        assert!(!s.is_configured());
        assert_eq!(s.max_results, 5);
        assert_eq!(s.fetch_max_bytes, 10 * 1024 * 1024);
        assert_eq!(s.substitution_max_iterations, 5);
    }

    #[test]
    fn searxng_without_an_endpoint_is_not_configured() {
        let mut s = WebSettings {
            backend: Some(WebProvider::Searxng),
            ..Default::default()
        };
        assert!(!s.is_configured());
        s.endpoint = Some("   ".into());
        assert!(!s.is_configured());
        s.endpoint = Some("https://search.example.com".into());
        assert!(s.is_configured());
    }

    #[test]
    fn substitution_max_iterations_round_trips_through_json() {
        let s = WebSettings {
            substitution_max_iterations: 12,
            ..Default::default()
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: WebSettings = serde_json::from_str(&json).unwrap();
        assert_eq!(back.substitution_max_iterations, 12);
    }

    #[test]
    fn substitution_max_iterations_defaults_when_absent_from_json() {
        let s: WebSettings = serde_json::from_str("{}").unwrap();
        assert_eq!(s.substitution_max_iterations, 5);
    }

    #[test]
    fn substitution_max_parallel_default_is_eight() {
        let s = WebSettings::default();
        assert_eq!(s.substitution_max_parallel, 8);
        let s: WebSettings = serde_json::from_str("{}").unwrap();
        assert_eq!(s.substitution_max_parallel, 8);
    }

    #[test]
    fn substitution_history_max_bytes_default_is_thirty_two_megabytes() {
        let s = WebSettings::default();
        assert_eq!(s.substitution_history_max_bytes, 32 * 1024 * 1024);
        let s: WebSettings = serde_json::from_str("{}").unwrap();
        assert_eq!(s.substitution_history_max_bytes, 32 * 1024 * 1024);
    }

    #[test]
    fn substitution_history_max_bytes_round_trips_through_json() {
        let s = WebSettings {
            substitution_history_max_bytes: 16 * 1024 * 1024,
            ..Default::default()
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: WebSettings = serde_json::from_str(&json).unwrap();
        assert_eq!(back.substitution_history_max_bytes, 16 * 1024 * 1024);
    }

    #[test]
    fn mixed_pending_cache_ttl_seconds_default_is_one_hour() {
        let s = WebSettings::default();
        assert_eq!(s.mixed_pending_cache_ttl_seconds, 3600);
        let s: WebSettings = serde_json::from_str("{}").unwrap();
        assert_eq!(s.mixed_pending_cache_ttl_seconds, 3600);
    }

    #[test]
    fn mixed_pending_cache_ttl_seconds_round_trips_through_json() {
        let s = WebSettings {
            mixed_pending_cache_ttl_seconds: 1800,
            ..Default::default()
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: WebSettings = serde_json::from_str(&json).unwrap();
        assert_eq!(back.mixed_pending_cache_ttl_seconds, 1800);
    }

    #[test]
    fn effective_max_results_clamps_to_setting_then_hard_cap() {
        let s = WebSettings {
            max_results: 10,
            ..Default::default()
        };
        assert_eq!(s.effective_max_results(None), 10);
        assert_eq!(s.effective_max_results(Some(3)), 3);
        // Caller asks for more than the setting — clamped to setting.
        assert_eq!(s.effective_max_results(Some(20)), 10);
    }

    #[test]
    fn effective_max_results_honours_hard_cap() {
        let s = WebSettings {
            max_results: 200,
            ..Default::default()
        };
        assert_eq!(
            s.effective_max_results(Some(100)),
            WebSettings::MAX_RESULTS_HARD_CAP
        );
    }
}
