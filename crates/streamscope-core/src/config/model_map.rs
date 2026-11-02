//! Model alias resolution and load balancing.
//!
//! [`ModelMap`] maps client-sent model aliases (e.g. `"gpt-4"`) to one or more
//! [`UpstreamModel`] targets. Within the highest-priority group, selection is
//! **session-pinned** when a stable affinity key (the client session id) is
//! supplied — every turn of a conversation resolves to the same upstream so the
//! provider's prompt cache keeps hitting — and falls back to weighted
//! round-robin (atomic counter, no locks) when no key is present. Different
//! priorities provide failover ordering (highest priority group tried first).

use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};

use serde::{Deserialize, Serialize};

/// Maps client-sent model aliases to upstream provider models.
///
/// Each alias can map to multiple `UpstreamModel` targets for load balancing
/// and failover. Targets are sorted by priority (highest first).
/// Same priority → weighted round-robin. Different priority → failover.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModelMap {
    pub mappings: HashMap<String, Vec<UpstreamModel>>,
}

impl ModelMap {
    /// Look up a single upstream target for a given alias (first/highest priority).
    /// Convenience for code that only needs one target.
    pub fn resolve(&self, alias: &str) -> Option<&UpstreamModel> {
        self.mappings.get(alias).and_then(|v| v.first())
    }

    /// Select a target within the highest-priority group.
    ///
    /// When `affinity` is `Some` (the client session id), the target is chosen
    /// by a stable hash of that key so every turn of a session pins to the same
    /// upstream — preserving the provider's prompt cache across turns and across
    /// replicas. When `affinity` is `None`, falls back to weighted round-robin
    /// via `counter` (shared per-alias, incremented atomically).
    pub fn select_target(
        &self,
        alias: &str,
        affinity: Option<&str>,
        counter: &AtomicUsize,
    ) -> Option<&UpstreamModel> {
        let targets: Vec<&UpstreamModel> = self.mappings.get(alias)?.iter().collect();
        pick_primary(&targets, affinity, counter)
    }

    /// Get all targets for an alias ordered for retry: primary target first
    /// (selected with the same session-pinned/weighted logic as
    /// [`select_target`](Self::select_target)), then remaining targets by
    /// descending priority. `affinity` pins only the primary; the failover order
    /// of the remaining targets is unchanged.
    pub fn select_targets_for_retry(
        &self,
        alias: &str,
        affinity: Option<&str>,
        counter: &AtomicUsize,
    ) -> Vec<&UpstreamModel> {
        self.select_targets_for_retry_where(alias, affinity, counter, |_| true)
    }

    /// [`select_targets_for_retry`](Self::select_targets_for_retry) over only
    /// the targets `admit` accepts. The filter runs BEFORE the weighted pick, so
    /// a refused peer's share spreads over the admitted ones by weight instead of
    /// falling to whichever peer is listed next.
    pub fn select_targets_for_retry_where(
        &self,
        alias: &str,
        affinity: Option<&str>,
        counter: &AtomicUsize,
        admit: impl Fn(&UpstreamModel) -> bool,
    ) -> Vec<&UpstreamModel> {
        let targets: Vec<&UpstreamModel> = match self.mappings.get(alias) {
            Some(t) => t.iter().filter(|m| admit(m)).collect(),
            None => return Vec::new(),
        };
        if targets.len() <= 1 {
            return targets;
        }
        let primary = pick_primary(&targets, affinity, counter);
        let primary_id = primary.map(|p| p as *const UpstreamModel);
        // Primary first, then the rest, already sorted by priority DESC.
        primary
            .into_iter()
            .chain(targets.iter().copied().filter(|t| Some(*t as *const UpstreamModel) != primary_id))
            .collect()
    }
}

/// The primary among `targets` (sorted by priority DESC): the session-pinned
/// or weighted round-robin pick within the highest-priority group.
fn pick_primary<'a>(
    targets: &[&'a UpstreamModel],
    affinity: Option<&str>,
    counter: &AtomicUsize,
) -> Option<&'a UpstreamModel> {
    let first = *targets.first()?;
    if targets.len() == 1 {
        return Some(first);
    }
    let group: Vec<&UpstreamModel> =
        targets.iter().copied().take_while(|t| t.priority == first.priority).collect();
    if group.len() == 1 {
        return Some(first);
    }
    // Weighted selection within the group: session-pinned hash if an affinity
    // key is present, else weighted round-robin.
    let total_weight: i32 = group.iter().map(|t| t.weight.max(1)).sum();
    let idx = group_index(total_weight, affinity, counter);
    let mut cumulative = 0;
    for target in &group {
        cumulative += target.weight.max(1);
        if idx < cumulative {
            return Some(target);
        }
    }
    Some(first)
}

/// Pick an index into `[0, total_weight)` for the weighted group.
///
/// With an `affinity` key, the index is a stable hash of that key, so the same
/// session always lands on the same target — preserving the upstream prompt
/// cache across a conversation's turns. The stability is load-bearing across
/// replicas: `DefaultHasher::new()` uses fixed (non-`RandomState`) keys, so the
/// same key hashes identically in every proxy process running the same binary
/// (a coordinated single-version deploy) — no shared state needed. Without a
/// key, falls back to the atomic round-robin counter.
fn group_index(total_weight: i32, affinity: Option<&str>, counter: &AtomicUsize) -> i32 {
    match affinity {
        Some(key) => {
            let mut h = DefaultHasher::new();
            key.hash(&mut h);
            (h.finish() % total_weight as u64) as i32
        }
        // Reduced as usize BEFORE the narrowing cast: a counter past i32::MAX
        // would otherwise cast negative and pin every pick to the first target.
        None => (counter.fetch_add(1, Ordering::Relaxed) % total_weight.max(1) as usize) as i32,
    }
}

/// An upstream model target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamModel {
    /// Raw provider string as configured (`openai`, `google_gemini`, an added
    /// SaaS like `xai`, …). Kept verbatim for attribution (audit provider,
    /// analytics grouping, `/v1/models` owner, brand icon); the enum is derived
    /// only where the *protocol* is needed (`upstream_api_version_for_provider`).
    pub provider: String,
    /// Real model name on the upstream (e.g., "gpt-4o-2024-08-06").
    pub model: String,
    /// Whether this upstream has a zero-data-retention agreement.
    #[serde(default)]
    pub zdr: bool,
    /// Whether this upstream's server has a stored credential — presented from
    /// the tenant configuration's [`ServerCredentials`](crate::config::credentials::ServerCredentials)
    /// under [`Self::upstream_server_id`].
    #[serde(default)]
    pub has_credential: bool,
    /// Model's context window size (tokens). Used to drive compression decisions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_window: Option<i32>,
    /// Maximum output tokens the upstream model supports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<i32>,
    /// Client-perceived context window (from alias config).
    /// Used for token scaling so clients trigger compaction at the right time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_context_window: Option<i32>,
    /// The upstream provider's native API format. Tells the proxy which
    /// translator to use when calling out. Values: "chat_completions",
    /// "responses", "anthropic_messages", "google_gemini". This is NOT a
    /// constraint on which client protocol can reach this upstream — the
    /// proxy translates between any client protocol and any upstream
    /// protocol (see ApiVersion::from_path()).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_api_format: Option<String>,
    /// Override for the appended chat-completions endpoint path (e.g. `/chat`
    /// for Writer, `/chat/completions` with no `/v1` for DeepInfra). None = the
    /// default `/v1/chat/completions`. Applies only to the `chat_completions`
    /// protocol; other protocols' paths are fixed.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub chat_endpoint_path: Option<String>,
    /// How the server is addressed and authenticated — orthogonal to
    /// `upstream_api_format`, which says only which protocol it speaks.
    #[serde(default)]
    pub transport: crate::config::upstream_transport::UpstreamTransport,
    /// How this server expresses a request's QoS class, if it does. Default =
    /// `none`: the class stays the gateway's own dispatch decision.
    #[serde(default)]
    pub scheduling_dialect: crate::config::qos::SchedulingDialect,
    /// UUID of the upstream_servers row (for audit tracking).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub upstream_server_id: Option<String>,
    /// UUID of the `downstream_providers` row this target's route belongs to.
    /// Lets the catch-all `/v1/*` handler pick the upstream that backs the
    /// route-policy-matched provider instead of an arbitrary `model_map` entry.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub downstream_provider_id: Option<String>,
    /// UUID of the upstream_models row (for audit tracking).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub upstream_model_id: Option<String>,
    /// Priority for LB/failover. Higher = preferred. Same priority = round-robin.
    #[serde(default)]
    pub priority: i32,
    /// Weight for weighted round-robin within same priority group (default 1).
    #[serde(default = "default_weight")]
    pub weight: i32,
    // ── Capability flags (resolved from model → catalog) ──
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub supports_vision: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub supports_reasoning: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub supports_function_calling: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub supports_caching: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub supports_audio_input: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub supports_audio_output: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub supports_video_input: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub supports_pdf_input: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub supports_response_schema: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub supports_system_messages: Option<bool>,
    /// Per-model JSON healing override (None = inherit tenant `healing_enabled`).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub healing_enabled: Option<bool>,
    /// Resolved native invocation preset for this (alias → model) target —
    /// the model's selected (or default) preset `settings`, a partial request
    /// body in the model's own protocol vocabulary. Force-merged onto the
    /// already-translated upstream body by the proxy. `Null`/empty = passthrough.
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub preset_settings: serde_json::Value,
    /// UUID of the `downstream_routes` row (alias binding) this target came
    /// from. The response cache partitions and flushes by it.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub route_id: Option<String>,
    /// Resolved response-cache policy for the alias (the route's cache preset,
    /// flattened to values at snapshot build). `None` = the alias is uncached,
    /// which is also the zero-cost path: no key is built and nothing is stored.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cache: Option<crate::proxy::response_cache::CachePolicy>,
    /// Resolved pricing rates for this upstream model.
    #[serde(default = "crate::pricing::Rates::unknown")]
    pub pricing: crate::pricing::Rates,
}

fn default_weight() -> i32 {
    1
}

/// Pass-through binding for a BYOK forward-auth key.
///
/// Carried on [`UserContext`](crate::auth::UserContext) when a `vk-*` key is
/// bound to a granted BYOK downstream. On a `model_map` miss the proxy forwards
/// the request verbatim to `upstream_url` with the client's own credential (the
/// downstream's linked upstream is keyless). An override route inside the same
/// downstream is a `model_map` HIT and wins over this fallback.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ByokPassthrough {
    /// The bound downstream's raw provider string (kept verbatim for attribution;
    /// the enum is derived only for the protocol fallback in
    /// `upstream_api_version_for_provider`).
    pub provider: String,
    /// The bound downstream's official upstream endpoint URL.
    pub upstream_url: String,
    /// The bound upstream's native protocol (None = infer from provider).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub upstream_api_format: Option<String>,
    /// Override for the appended chat-completions endpoint path (None = the
    /// default `/v1/chat/completions`). Applies only to the `chat_completions`
    /// protocol.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub chat_endpoint_path: Option<String>,
    /// How the bound upstream is addressed and authenticated. A BYOK
    /// pass-through carries the client's own credential, but the URL shape and
    /// the header it rides in are still the server's property.
    #[serde(default)]
    pub transport: crate::config::upstream_transport::UpstreamTransport,
    /// UUID of the bound `downstream_providers` row this pass-through belongs to.
    pub downstream_provider_id: String,
}


/// Supported upstream providers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    OpenAi,
    Anthropic,
    Groq,
    Together,
    Fireworks,
    DeepSeek,
    Mistral,
    OpenRouter,
    Nvidia,
    Ollama,
    Vllm,
    AzureOpenAi,
    AwsBedrock,
    GoogleVertex,
    GoogleGemini,
    Custom,
}

impl Provider {
    /// Parse a provider string, handling both snake_case enum variants
    /// (e.g. "open_ai") and common shorthand forms (e.g. "openai").
    pub fn from_str_relaxed(s: &str) -> Provider {
        // Try exact serde deserialization first (handles snake_case like "open_ai")
        if let Ok(p) =
            serde_json::from_value::<Provider>(serde_json::Value::String(s.to_string()))
        {
            return p;
        }
        // Fallback: common shorthand mappings
        match s.to_lowercase().as_str() {
            "openai" => Provider::OpenAi,
            "anthropic" => Provider::Anthropic,
            "groq" => Provider::Groq,
            "together" => Provider::Together,
            "fireworks" => Provider::Fireworks,
            "deepseek" => Provider::DeepSeek,
            "mistral" => Provider::Mistral,
            "openrouter" => Provider::OpenRouter,
            "nvidia" | "nim" | "nvidia_nim" | "nvidianim" => Provider::Nvidia,
            "ollama" => Provider::Ollama,
            "vllm" => Provider::Vllm,
            "azure" | "azure_openai" | "azureopenai" => Provider::AzureOpenAi,
            "bedrock" | "aws_bedrock" | "awsbedrock" => Provider::AwsBedrock,
            "vertex" | "google_vertex" | "googlevertex" => Provider::GoogleVertex,
            "gemini" | "google_gemini" | "googlegemini" => Provider::GoogleGemini,
            _ => Provider::Custom,
        }
    }

}

impl std::fmt::Display for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_value(self)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| format!("{self:?}"));
        write!(f, "{s}")
    }
}

/// Helper to create an UpstreamModel with default test values.
#[cfg(test)]
pub fn test_upstream_model(provider: Provider, model: &str) -> UpstreamModel {
    UpstreamModel {
        provider: provider.to_string(),
        model: model.to_string(),
        zdr: false,
        has_credential: false,
        chat_endpoint_path: None,
        scheduling_dialect: Default::default(),
        transport: crate::config::upstream_transport::UpstreamTransport::Default,
        context_window: None,
        max_output_tokens: None,
        client_context_window: None,
        upstream_api_format: None,
        upstream_server_id: None,
        downstream_provider_id: None,
        upstream_model_id: None,
        priority: 0,
        weight: 1,
        supports_vision: None,
        supports_reasoning: None,
        supports_function_calling: None,
        supports_caching: None,
        supports_audio_input: None,
        supports_audio_output: None,
        supports_video_input: None,
        supports_pdf_input: None,
        supports_response_schema: None,
        supports_system_messages: None,
        healing_enabled: None,
        preset_settings: serde_json::Value::Null,
        route_id: None,
        cache: None,
        pricing: crate::pricing::Rates::unknown(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_existing_alias() {
        let mut map = ModelMap::default();
        map.mappings.insert(
            "gpt-4o".to_string(),
            vec![test_upstream_model(Provider::OpenAi, "gpt-4o-2024-08-06")],
        );
        let result = map.resolve("gpt-4o");
        assert!(result.is_some());
        let upstream = result.unwrap();
        assert_eq!(upstream.model, "gpt-4o-2024-08-06");
        assert_eq!(upstream.provider, "open_ai");
    }

    #[test]
    fn resolve_unknown_alias_returns_none() {
        let map = ModelMap::default();
        assert!(map.resolve("nonexistent").is_none());
    }

    #[test]
    fn resolve_keeps_the_target_as_mapped() {
        let mut map = ModelMap::default();
        let mut model = test_upstream_model(Provider::Ollama, "llama3");
        model.zdr = true;
        map.mappings.insert("local-model".to_string(), vec![model]);

        let result = map.resolve("local-model").unwrap();
        assert_eq!(result.model, "llama3");
        assert!(result.zdr);
    }

    #[test]
    fn multiple_aliases_resolve_independently() {
        let mut map = ModelMap::default();
        map.mappings.insert(
            "alias-a".to_string(),
            vec![test_upstream_model(Provider::OpenAi, "model-a")],
        );
        map.mappings.insert(
            "alias-b".to_string(),
            vec![test_upstream_model(Provider::Anthropic, "model-b")],
        );
        assert_eq!(map.resolve("alias-a").unwrap().model, "model-a");
        assert_eq!(map.resolve("alias-b").unwrap().model, "model-b");
    }

    #[test]
    fn select_target_single_target() {
        let mut map = ModelMap::default();
        map.mappings.insert(
            "test".to_string(),
            vec![test_upstream_model(Provider::OpenAi, "gpt-4o")],
        );
        let counter = AtomicUsize::new(0);
        let target = map.select_target("test", None, &counter).unwrap();
        assert_eq!(target.model, "gpt-4o");
    }

    #[test]
    fn select_target_round_robin_same_priority() {
        let mut map = ModelMap::default();
        let mut a = test_upstream_model(Provider::OpenAi, "model-a");
        a.priority = 0;
        a.weight = 1;
        let mut b = test_upstream_model(Provider::OpenAi, "model-b");
        b.priority = 0;
        b.weight = 1;
        map.mappings.insert("test".to_string(), vec![a, b]);

        let counter = AtomicUsize::new(0);
        let t1 = map.select_target("test", None, &counter).unwrap().model.clone();
        let t2 = map.select_target("test", None, &counter).unwrap().model.clone();
        // Should alternate between model-a and model-b
        assert_ne!(t1, t2);
    }

    #[test]
    fn select_target_weighted_rr() {
        let mut map = ModelMap::default();
        let mut a = test_upstream_model(Provider::OpenAi, "model-a");
        a.priority = 0;
        a.weight = 3;
        let mut b = test_upstream_model(Provider::OpenAi, "model-b");
        b.priority = 0;
        b.weight = 1;
        map.mappings.insert("test".to_string(), vec![a, b]);

        let counter = AtomicUsize::new(0);
        let mut counts = HashMap::new();
        for _ in 0..400 {
            let model = map.select_target("test", None, &counter).unwrap().model.clone();
            *counts.entry(model).or_insert(0) += 1;
        }
        // model-a should get ~75% (300), model-b ~25% (100)
        assert_eq!(counts["model-a"], 300);
        assert_eq!(counts["model-b"], 100);
    }

    #[test]
    fn select_target_failover_uses_highest_priority() {
        let mut map = ModelMap::default();
        let mut primary = test_upstream_model(Provider::OpenAi, "primary");
        primary.priority = 10;
        let mut fallback = test_upstream_model(Provider::OpenAi, "fallback");
        fallback.priority = 5;
        // Sorted by priority DESC
        map.mappings.insert("test".to_string(), vec![primary, fallback]);

        let counter = AtomicUsize::new(0);
        // Should always pick primary (highest priority group has only 1 member)
        for _ in 0..10 {
            let target = map.select_target("test", None, &counter).unwrap();
            assert_eq!(target.model, "primary");
        }
    }

    #[test]
    fn select_targets_for_retry_orders_correctly() {
        let mut map = ModelMap::default();
        let mut primary = test_upstream_model(Provider::OpenAi, "primary");
        primary.priority = 10;
        let mut fallback = test_upstream_model(Provider::OpenAi, "fallback");
        fallback.priority = 5;
        map.mappings.insert("test".to_string(), vec![primary, fallback]);

        let counter = AtomicUsize::new(0);
        let targets = map.select_targets_for_retry("test", None, &counter);
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].model, "primary");
        assert_eq!(targets[1].model, "fallback");
    }

    #[test]
    fn select_target_affinity_pins_same_target() {
        let mut map = ModelMap::default();
        let mut a = test_upstream_model(Provider::OpenAi, "model-a");
        a.priority = 0;
        let mut b = test_upstream_model(Provider::OpenAi, "model-b");
        b.priority = 0;
        map.mappings.insert("test".to_string(), vec![a, b]);

        // A given affinity key resolves to the same target every time, with no
        // counter advancement — independent of round-robin position.
        let counter = AtomicUsize::new(0);
        let first = map
            .select_target("test", Some("sess-1"), &counter)
            .unwrap()
            .model
            .clone();
        for _ in 0..50 {
            let m = map.select_target("test", Some("sess-1"), &counter).unwrap();
            assert_eq!(m.model, first);
        }
    }

    #[test]
    fn select_target_affinity_spreads_distinct_sessions_by_weight() {
        let mut map = ModelMap::default();
        let mut a = test_upstream_model(Provider::OpenAi, "model-a");
        a.priority = 0;
        a.weight = 3;
        let mut b = test_upstream_model(Provider::OpenAi, "model-b");
        b.priority = 0;
        b.weight = 1;
        map.mappings.insert("test".to_string(), vec![a, b]);

        let counter = AtomicUsize::new(0);
        let mut counts: HashMap<String, i32> = HashMap::new();
        for i in 0..2000 {
            let key = format!("sess-{i}");
            let m = map
                .select_target("test", Some(&key), &counter)
                .unwrap()
                .model
                .clone();
            *counts.entry(m).or_insert(0) += 1;
        }
        // Weighted hash distributes distinct sessions ~3:1; allow generous slack.
        let a_count = counts["model-a"];
        let b_count = counts["model-b"];
        assert!(a_count > b_count * 2, "a={a_count} b={b_count}");
        // No counter advancement on the affinity path.
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn round_robin_keeps_rotating_past_i32_max() {
        let mut map = ModelMap::default();
        map.mappings.insert(
            "m".to_string(),
            ["a", "b"].iter().map(|n| test_upstream_model(Provider::OpenAi, n)).collect(),
        );
        // Just below and past the point where an i32 cast turns negative.
        let counter = AtomicUsize::new(i32::MAX as usize - 1);
        let picks: Vec<String> =
            (0..4).map(|_| map.select_target("m", None, &counter).unwrap().model.clone()).collect();
        assert_eq!(picks.iter().filter(|m| *m == "a").count(), 2, "{picks:?}");
        assert_eq!(picks.iter().filter(|m| *m == "b").count(), 2, "{picks:?}");
    }

    #[test]
    fn a_refused_peer_spreads_its_share_over_the_admitted_ones() {
        // Filtering after the pick would hand every pick of A to B (the next in
        // the list); filtering before it keeps B and C even.
        let mut map = ModelMap::default();
        map.mappings.insert(
            "m".to_string(),
            ["a", "b", "c"].iter().map(|n| test_upstream_model(Provider::OpenAi, n)).collect(),
        );
        let counter = AtomicUsize::new(0);
        let mut primaries = std::collections::HashMap::<String, usize>::new();
        for _ in 0..60 {
            let picked = map.select_targets_for_retry_where("m", None, &counter, |t| t.model != "a");
            assert_eq!(picked.len(), 2, "the refused peer is not in the failover list either");
            *primaries.entry(picked[0].model.clone()).or_default() += 1;
        }
        assert_eq!(primaries.get("b"), Some(&30));
        assert_eq!(primaries.get("c"), Some(&30));
        // Positive control: with everything admitted, A takes its third.
        let all = (0..60).filter(|_| map.select_targets_for_retry("m", None, &counter)[0].model == "a").count();
        assert_eq!(all, 20);
    }

    #[test]
    fn select_targets_for_retry_affinity_pins_primary_keeps_failover() {
        let mut map = ModelMap::default();
        let mut a = test_upstream_model(Provider::OpenAi, "model-a");
        a.priority = 10;
        let mut b = test_upstream_model(Provider::OpenAi, "model-b");
        b.priority = 10;
        let mut fallback = test_upstream_model(Provider::OpenAi, "fallback");
        fallback.priority = 5; // lower-priority failover tier
        map.mappings
            .insert("test".to_string(), vec![a, b, fallback]); // sorted DESC by priority

        let counter = AtomicUsize::new(0);
        let targets = map.select_targets_for_retry("test", Some("sess-x"), &counter);
        // All three targets present; primary is one of the top-priority group,
        // and it is stable across calls for the same affinity key.
        assert_eq!(targets.len(), 3);
        let primary = targets[0].model.clone();
        assert!(primary == "model-a" || primary == "model-b");
        for _ in 0..20 {
            let again = map.select_targets_for_retry("test", Some("sess-x"), &counter);
            assert_eq!(again[0].model, primary);
        }
    }
}
