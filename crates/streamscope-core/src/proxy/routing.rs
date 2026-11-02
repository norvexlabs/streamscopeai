//! Upstream target resolution — maps a request to a concrete provider endpoint.
//!
//! Consults the user's per-key [`ModelMap`](crate::config::model_map::ModelMap)
//! (scoped to the key's downstream routes, no global fallback). A target presents
//! its server's stored credential, opened in the key's own tenant configuration
//! ([`ServerCredentials`]). For BYOK (`vk-*` keys), the client's own auth header
//! is forwarded instead.

use std::sync::atomic::AtomicUsize;

use crate::api::sse::ApiVersion;
use crate::api::ApiRequest;
use crate::auth::UserContext;
use crate::config::model_map::{Provider, UpstreamModel};
use crate::error::AppError;
use crate::config::credentials::ServerCredentials;

/// Resolved capability flags for an upstream model.
#[derive(Clone, Debug, Default)]
pub struct ModelCapabilities {
    pub vision: bool,
    pub reasoning: bool,
    pub function_calling: bool,
    pub caching: bool,
    pub audio_input: bool,
    pub audio_output: bool,
    pub video_input: bool,
    pub pdf_input: bool,
    pub response_schema: bool,
    pub system_messages: bool,
}

impl ModelCapabilities {
    // The single source of truth for what a capability resolves to when NO
    // level (route / upstream_model / catalog) declares a value — i.e. an
    // undiscovered, uncataloged model. A standard text-LLM baseline: chat with
    // tools, system prompts, and structured output are near-universal; every
    // modality (vision/audio/video/pdf), reasoning, and prompt caching are
    // opt-in and stay off until discovered or explicitly set. The admin
    // `resolved_*` materialization and the edge config snapshot derive their
    // defaults from these same constants — keep them the only definition.
    pub const DEFAULT_VISION: bool = false;
    pub const DEFAULT_REASONING: bool = false;
    pub const DEFAULT_FUNCTION_CALLING: bool = true;
    pub const DEFAULT_CACHING: bool = false;
    pub const DEFAULT_AUDIO_INPUT: bool = false;
    pub const DEFAULT_AUDIO_OUTPUT: bool = false;
    pub const DEFAULT_VIDEO_INPUT: bool = false;
    pub const DEFAULT_PDF_INPUT: bool = false;
    pub const DEFAULT_RESPONSE_SCHEMA: bool = true;
    pub const DEFAULT_SYSTEM_MESSAGES: bool = true;

    /// The standard capability set assumed when nothing declares a value.
    pub const fn default_when_unknown() -> ModelCapabilities {
        ModelCapabilities {
            vision: Self::DEFAULT_VISION,
            reasoning: Self::DEFAULT_REASONING,
            function_calling: Self::DEFAULT_FUNCTION_CALLING,
            caching: Self::DEFAULT_CACHING,
            audio_input: Self::DEFAULT_AUDIO_INPUT,
            audio_output: Self::DEFAULT_AUDIO_OUTPUT,
            video_input: Self::DEFAULT_VIDEO_INPUT,
            pdf_input: Self::DEFAULT_PDF_INPUT,
            response_schema: Self::DEFAULT_RESPONSE_SCHEMA,
            system_messages: Self::DEFAULT_SYSTEM_MESSAGES,
        }
    }

    /// Resolve an [`UpstreamModel`]'s already-COALESCE'd (route → model →
    /// catalog) `Option<bool>` flags into concrete capabilities: a NULL flag
    /// (no level declared a value) falls back to `default_when_unknown()`, an
    /// explicit value always wins. The single authoritative resolution point —
    /// shared by `build_target` (enforcement) and the `/v1/models` contract
    /// (advertisement) so the two never drift.
    pub fn resolve(model: &UpstreamModel) -> ModelCapabilities {
        ModelCapabilities {
            vision: model.supports_vision.unwrap_or(Self::DEFAULT_VISION),
            reasoning: model.supports_reasoning.unwrap_or(Self::DEFAULT_REASONING),
            function_calling: model.supports_function_calling.unwrap_or(Self::DEFAULT_FUNCTION_CALLING),
            caching: model.supports_caching.unwrap_or(Self::DEFAULT_CACHING),
            audio_input: model.supports_audio_input.unwrap_or(Self::DEFAULT_AUDIO_INPUT),
            audio_output: model.supports_audio_output.unwrap_or(Self::DEFAULT_AUDIO_OUTPUT),
            video_input: model.supports_video_input.unwrap_or(Self::DEFAULT_VIDEO_INPUT),
            pdf_input: model.supports_pdf_input.unwrap_or(Self::DEFAULT_PDF_INPUT),
            response_schema: model.supports_response_schema.unwrap_or(Self::DEFAULT_RESPONSE_SCHEMA),
            system_messages: model.supports_system_messages.unwrap_or(Self::DEFAULT_SYSTEM_MESSAGES),
        }
    }

    /// Whether a TRANSLATED request carries the client's reasoning to this
    /// model: unless the model is KNOWN not to reason. Distinct from the
    /// advertised `reasoning` flag, which defaults off: a model nobody has
    /// described (a self-hosted server that publishes no flag) gets the
    /// client's request, while one explicitly off — or carried by the catalog
    /// without the flag, which admin bakes as off — does not, since it refuses
    /// the parameter outright.
    pub fn accepts_reasoning(model: &UpstreamModel) -> bool {
        model.supports_reasoning.unwrap_or(true)
    }

    /// The reasoning flag admin bakes for an edge, from the COALESCE'd
    /// model → catalog value and whether a catalog row matched. The catalog's
    /// feed states `supports_reasoning` only when it is true, so its silence
    /// on a row it carries is a "no" (gpt-4o refuses `reasoning_effort`); a
    /// model no row matched stays undeclared.
    pub fn edge_reasoning_flag(declared: Option<bool>, catalog_matched: bool) -> Option<bool> {
        declared.or(catalog_matched.then_some(false))
    }

}

/// Resolved upstream target for a request.
#[derive(Clone)]
pub struct UpstreamTarget {
    pub url: String,
    pub api_key: String,
    pub model: String,
    pub provider: String,
    pub context_window: Option<i32>,
    /// Maximum output tokens the upstream model supports.
    pub max_output_tokens: Option<i32>,
    /// Client-perceived context window (from alias config). Used for token scaling.
    pub client_context_window: Option<i32>,
    /// The API version to use when talking to this upstream.
    pub upstream_api_version: ApiVersion,
    /// Override for the appended chat-completions endpoint path (None = the
    /// default `/v1/chat/completions`). Applies only when
    /// `upstream_api_version` is `ChatCompletions`.
    pub chat_endpoint_path: Option<String>,
    /// How this target is addressed and authenticated. Orthogonal to
    /// `upstream_api_version`: the transport decides the URL prefix and the
    /// credential header, the protocol decides the body.
    pub transport: crate::config::upstream_transport::UpstreamTransport,
    /// How this target's server expresses a request's QoS class. Applied after
    /// the preset merge, per ACTUAL target — so a vLLM replica is told the class
    /// and a hosted fallback in the same alias is told nothing.
    pub scheduling_dialect: crate::config::qos::SchedulingDialect,
    /// UUID of the upstream_servers row (for audit tracking).
    pub upstream_server_id: Option<String>,
    /// UUID of the upstream_models row (for audit tracking).
    pub upstream_model_id: Option<String>,
    /// Capability flags for the upstream model.
    pub capabilities: ModelCapabilities,
    /// Whether a translated request carries reasoning to this model — see
    /// [`ModelCapabilities::accepts_reasoning`].
    pub accepts_reasoning: bool,
    /// Pricing rates for this upstream model.
    pub pricing: crate::pricing::Rates,
    /// Per-model JSON healing override (None = inherit tenant `healing_enabled`).
    pub healing_enabled: Option<bool>,
    /// Resolved native invocation preset for this target — the selected (or
    /// default) preset's `settings`, a partial request body in the model's own
    /// protocol. Force-merged onto the translated upstream body. `Null`/empty =
    /// passthrough (default preset / BYOK).
    pub preset_settings: serde_json::Value,
    /// UUID of the alias binding (`downstream_routes` row) this target came from.
    /// The response-cache partition + flush grain; `None` for a BYOK
    /// pass-through target, which is never cached.
    pub route_id: Option<uuid::Uuid>,
    /// Resolved response-cache policy for the alias. `None` = uncached — the
    /// zero-cost path, where no cache key is ever built.
    pub cache: Option<crate::proxy::response_cache::CachePolicy>,
    /// Whether this target carries its own stored upstream credential (`api_key`
    /// resolved from an encrypted credential). When false, a BYOK (`vk-*`) request
    /// forwards the client's own credential instead; when true, the stored
    /// credential is used and the client's is NOT forwarded — so an override route
    /// to an on-prem upstream with a stored key never receives the client's key.
    pub has_stored_credential: bool,
    /// A BYOK pass-through target: the client's request goes to the client's
    /// own provider as it was sent — no route, no alias to translate.
    pub passthrough: bool,
    /// The replica endpoint `url` addresses; `None` only for a pass-through
    /// target, which is sent to its binding's URL.
    pub endpoint_id: Option<uuid::Uuid>,
    /// Which selected route target this is a replica of. Consecutive entries
    /// of one slot are the same model on different endpoints: moving between
    /// them is a spill, not a failover.
    pub route_slot: usize,
    /// How many requests this gateway may have in flight at this endpoint, and
    /// how long the engine's own queue may grow before it stops being sent
    /// more. Both `None` — every server without capacity knobs — means the
    /// dispatch gate does not apply to this target at all.
    pub gate_max_in_flight: Option<u32>,
    pub gate_waiting_threshold: Option<u32>,
    /// Whether the in-flight limit here is learned from the engine's readings,
    /// `gate_max_in_flight` being its ceiling.
    pub gate_adaptive: bool,
}

/// `api_key` holds the resolved upstream credential — on the Entra transport the
/// whole client-credentials document — so `Debug` is redacted by hand rather than
/// derived, matching `ForwardAuthContext` and `UpstreamEndpoint`.
impl std::fmt::Debug for UpstreamTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamTarget")
            .field("url", &self.url)
            .field("api_key", &"<redacted>")
            .field("model", &self.model)
            .field("provider", &self.provider)
            .field("upstream_api_version", &self.upstream_api_version)
            .field("transport", &self.transport)
            .field("upstream_server_id", &self.upstream_server_id)
            .field("upstream_model_id", &self.upstream_model_id)
            .field("endpoint_id", &self.endpoint_id)
            .finish_non_exhaustive()
    }
}

impl UpstreamTarget {
    /// The output-cap spelling this target reads, if it speaks Chat Completions.
    pub fn chat_cap_field(&self) -> crate::api::domain_request::ChatCapField {
        crate::api::domain_request::ChatCapField::for_upstream(&self.provider, self.transport, &self.url)
    }

    /// Where this target's Chat Completions wire differs from OpenAI's.
    pub fn chat_dialect(&self) -> crate::api::mistral::ChatDialect {
        crate::api::mistral::ChatDialect::for_upstream(&self.provider, &self.url)
    }

    /// The body forwarded to this target, conformed to its API — its Chat
    /// dialect, or what Anthropic verifies ([`conform_for`]) — and what that
    /// changed (`None` when nothing is conformed). `translated`: the
    /// client spoke another protocol than the target. Every forward to a
    /// target — each attempt, each substitution round — goes through here.
    pub fn conform_body(
        &self,
        body: bytes::Bytes,
        forward_version: crate::api::sse::ApiVersion,
        translated: bool,
    ) -> (bytes::Bytes, Option<crate::api::mistral::Conformed>) {
        conform_for(self.chat_dialect(), self.model_reasoning(), translated, body, forward_version)
    }

    /// What the model is known to do with reasoning, for a dialect pass.
    pub fn model_reasoning(&self) -> crate::api::mistral::ModelReasoning {
        crate::api::mistral::ModelReasoning {
            accepts: self.accepts_reasoning,
            declared: self.capabilities.reasoning,
        }
    }

    /// What a translation to this target needs to know about it — see
    /// [`crate::api::domain_request::UpstreamFacts`].
    pub fn translation_facts(&self) -> crate::api::domain_request::UpstreamFacts {
        use crate::api::domain_request::{is_openai_platform, openai_model_takes_effort_none};
        crate::api::domain_request::UpstreamFacts {
            output_limit: self.max_output_tokens.and_then(|limit| u32::try_from(limit).ok()).filter(|&l| l > 0),
            // Mistral takes `none` only on a model that reasons (live: a model
            // that does not refuses it), so only where reasoning is declared.
            takes_effort_none: (is_openai_platform(&self.provider, self.transport, &self.url)
                && openai_model_takes_effort_none(&self.model))
                || (self.chat_dialect() == crate::api::mistral::ChatDialect::Mistral && self.capabilities.reasoning),
            chat_dialect: self.chat_dialect(),
            rerenders_client_request: false,
        }
    }

    /// The domain a translated request is rendered from for this target, and
    /// what that translation has no channel for. The list is read BEFORE the
    /// reasoning gate drops anything, so the drop is on it — every translation
    /// site goes through here so that order cannot be got wrong at one of them.
    /// The domain carries this target's output limit, which the walks and the
    /// list both read.
    pub fn prepare_translation(
        &self,
        request: &crate::api::ApiRequest,
    ) -> (crate::api::domain_request::DomainRequest, Vec<String>) {
        let mut domain = crate::api::domain_request::DomainRequest::from_api_request(request);
        domain.upstream = self.translation_facts();
        let not_carried = domain.not_carried_to(self.upstream_api_version, &self.model, self.accepts_reasoning);
        domain.drop_reasoning_unless(self.accepts_reasoning);
        (domain, not_carried)
    }

    /// Where this target's requests go and how they are carried there.
    ///
    /// The only supported way to address a target: it binds the URL, the
    /// credential and the transport together, so no forward path can pair one
    /// server's URL with another's auth scheme.
    pub fn endpoint(&self) -> crate::proxy::client::UpstreamEndpoint<'_> {
        crate::proxy::client::UpstreamEndpoint {
            url: &self.url,
            api_key: &self.api_key,
            transport: self.transport,
        }
    }

    /// The model a raw-bytes forward names in the body: the routed target's
    /// upstream model, or `None` for a pass-through — whose body goes out with
    /// the client's own `model` (or none), never a name the gateway filled in.
    pub fn forward_model(&self) -> Option<&str> {
        (!self.passthrough).then_some(self.model.as_str())
    }

    /// The circuit-breaker key: the endpoint when known — each replica trips on
    /// its own — else the server (or, keyless, the URL host). Not the URL: an
    /// endpoint pointed at another host keeps its breaker, so an outage the
    /// operator fixed that way closes with a recovery (whose report names the
    /// new URL) rather than staying open for ever under the old key.
    pub fn breaker_key(&self) -> String {
        match self.endpoint_id {
            Some(id) => id.to_string(),
            None => crate::proxy::health::target_key(self.upstream_server_id.as_deref(), &self.url),
        }
    }

    /// Whether `other` is this target on another endpoint (same route, same
    /// model) — trying it is a spill between replicas, not a failover.
    pub fn same_route_as(&self, other: &UpstreamTarget) -> bool {
        self.route_slot == other.route_slot
    }
}

/// Resolve the upstream target for a given request and user context.
///
/// Uses weighted round-robin for same-priority targets and failover
/// ordering (highest priority first) when priorities differ.
///
/// Only the user's per-key model_map (scoped to the key's downstream provider)
/// is consulted. No global fallback — returns `ModelNotFound` if the model
/// is not in the key's downstream routes.
///
/// The single-target form of [`resolve_all_upstreams`], kept for the tests
/// that assert one pick at a time; production resolves the failover list.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub fn resolve_upstream(
    request: &ApiRequest,
    user: &UserContext,
    credentials: &ServerCredentials,
    lb_counters: &dashmap::DashMap<String, AtomicUsize>,
    affinity: Option<&str>,
    protocol: ApiVersion,
    origin_host: Option<&str>,
    endpoints: &crate::config::endpoints::EndpointTable,
) -> Result<UpstreamTarget, AppError> {
    resolve_all_upstreams(request, user, credentials, lb_counters, affinity, protocol, origin_host, endpoints)
        .map(|targets| targets.into_iter().next().expect("a resolved target list is never empty"))
}

/// The refusal for a pass-through request to a provider with no enabled route
/// target to forward to (and no pass-through entry) — a routing state, not a
/// server without a URL, so it names the provider.
pub(crate) fn no_route_target(downstream_provider_id: &str) -> AppError {
    if crate::log_throttle::due(&format!("no-route:{downstream_provider_id}"), std::time::Instant::now()) {
        tracing::warn!(
            downstream_provider_id,
            "pass-through request to a provider with no enabled route target — not forwarded (logged once per provider every {} s)",
            crate::log_throttle::EVERY.as_secs()
        );
    }
    AppError::Unroutable {
        reason: "this provider has no enabled model to forward the request to",
        model: None,
    }
}

/// The credential a route target presents: its server's stored one, else —
/// keyless — the caller's own. A stored credential this configuration cannot
/// produce is reported, and the target goes out with none.
pub(crate) fn route_credential(
    upstream_model: &UpstreamModel,
    user: &UserContext,
    credentials: &ServerCredentials,
) -> String {
    if !upstream_model.has_credential {
        return user.real_api_key.clone();
    }
    // A target is only built for a server with endpoints, so it has an id.
    let Some(server) = upstream_model.upstream_server_id.as_deref() else {
        return String::new();
    };
    match credentials.get(server) {
        Ok(credential) => credential.to_string(),
        Err(miss) => {
            if crate::log_throttle::due(&format!("credential:{server}"), std::time::Instant::now()) {
                tracing::warn!(
                    server,
                    "upstream credential {} — sent without one (logged once per server every {} s)",
                    miss.as_str(),
                    crate::log_throttle::EVERY.as_secs()
                );
            }
            String::new()
        }
    }
}

/// The target for a route target on one endpoint of its server.
fn build_target(
    upstream_model: &UpstreamModel,
    api_key: String,
    ep: &crate::config::endpoints::EndpointConfig,
    route_slot: usize,
) -> UpstreamTarget {
    let upstream_api_version = upstream_api_version_for_provider(
        &upstream_model.provider,
        upstream_model.upstream_api_format.as_deref(),
    );

    // Single authoritative capability resolution — NULL flags fall back to the
    // standard text-LLM baseline, explicit values win. Shared with `/v1/models`.
    let capabilities = ModelCapabilities::resolve(upstream_model);

    UpstreamTarget {
        url: ep.url.clone(),
        api_key,
        model: upstream_model.model.clone(),
        provider: upstream_model.provider.to_string(),
        context_window: upstream_model.context_window,
        max_output_tokens: upstream_model.max_output_tokens,
        client_context_window: upstream_model.client_context_window,
        upstream_api_version,
        chat_endpoint_path: upstream_model.chat_endpoint_path.clone(),
        transport: upstream_model.transport,
        scheduling_dialect: upstream_model.scheduling_dialect,
        gate_max_in_flight: ep.max_in_flight,
        gate_waiting_threshold: ep.waiting_threshold,
        gate_adaptive: ep.adaptive_concurrency,
        upstream_server_id: upstream_model.upstream_server_id.clone(),
        upstream_model_id: upstream_model.upstream_model_id.clone(),
        capabilities,
        accepts_reasoning: ModelCapabilities::accepts_reasoning(upstream_model),
        pricing: upstream_model.pricing.clone(),
        healing_enabled: upstream_model.healing_enabled,
        preset_settings: upstream_model.preset_settings.clone(),
        route_id: upstream_model
            .route_id
            .as_deref()
            .and_then(|s| uuid::Uuid::parse_str(s).ok()),
        cache: upstream_model.cache,
        has_stored_credential: upstream_model.has_credential,
        passthrough: false,
        endpoint_id: Some(ep.id),
        route_slot,
    }
}

/// A target on one replica of a server, for tests that need a real
/// [`UpstreamTarget`] without resolving one through a key.
#[cfg(test)]
pub(crate) fn test_replica_target(server_id: uuid::Uuid, endpoint_id: uuid::Uuid, url: &str) -> UpstreamTarget {
    let mut target = build_passthrough_target(
        &crate::config::model_map::ByokPassthrough {
            provider: "openai".to_string(),
            upstream_url: url.to_string(),
            upstream_api_format: None,
            chat_endpoint_path: None,
            transport: Default::default(),
            downstream_provider_id: String::new(),
        },
        "m",
    );
    target.upstream_server_id = Some(server_id.to_string());
    target.endpoint_id = Some(endpoint_id);
    target
}

/// Build a synthetic pass-through target for a BYOK forward-auth key on a
/// `model_map` miss. The request is forwarded verbatim (model name unchanged) to
/// the bound BYOK downstream's keyless upstream endpoint; the client's own
/// credential is forwarded (the synthesized model is keyless, so the credential
/// rule in `proxy_handler_inner` forwards it). Capabilities fall back to the
/// standard text-LLM baseline; pricing is zero (a BYOK request is funded by the
/// user's own provider account, so the gateway does not meter its cost).
fn build_passthrough_target(
    pt: &crate::config::model_map::ByokPassthrough,
    model: &str,
) -> UpstreamTarget {
    let upstream_api_version =
        upstream_api_version_for_provider(&pt.provider, pt.upstream_api_format.as_deref());
    UpstreamTarget {
        url: pt.upstream_url.clone(),
        api_key: String::new(),
        model: model.to_string(),
        provider: pt.provider.to_string(),
        context_window: None,
        max_output_tokens: None,
        client_context_window: None,
        upstream_api_version,
        chat_endpoint_path: pt.chat_endpoint_path.clone(),
        // A pass-through goes to the customer's own provider; the gateway
        // states no class on someone else's engine.
        scheduling_dialect: crate::config::qos::SchedulingDialect::None,
        gate_max_in_flight: None,
        gate_waiting_threshold: None,
        gate_adaptive: false,
        transport: pt.transport,
        upstream_server_id: None,
        upstream_model_id: None,
        // A pass-through has no alias binding of its own, so it can carry no
        // cache policy — BYOK traffic is never served from the response cache.
        route_id: None,
        cache: None,
        // Pass-through forwards the request verbatim to the customer's own
        // provider, which is the authority on what it supports — the gateway must
        // NOT gate modality here (the text-only baseline would 400 a Claude Code /
        // Gemini image request). Permit every capability; an unsupported modality
        // is rejected by the upstream itself.
        capabilities: ModelCapabilities {
            vision: true,
            reasoning: true,
            function_calling: true,
            caching: true,
            audio_input: true,
            audio_output: true,
            video_input: true,
            pdf_input: true,
            response_schema: true,
            system_messages: true,
        },
        accepts_reasoning: true,
        pricing: crate::pricing::Rates::free(),
        healing_enabled: None,
        // BYOK forwards verbatim — never preset-overridden.
        preset_settings: serde_json::Value::Null,
        // Keyless by construction → the client's forwarded credential is used.
        has_stored_credential: false,
        passthrough: true,
        endpoint_id: None,
        route_slot: 0,
    }
}

/// Select the BYOK pass-through entry for a request from the key's set.
///
/// The gateway-supplied intercepted origin host (X-Origin-Host) is the
/// authoritative answer when present: it names the provider the client was
/// talking to, so an entry for that host is chosen and, when the key holds none,
/// the request is REFUSED — whatever the set's size or protocols. Forwarding it
/// anywhere else would hand the client's credential for one provider to another
/// (an Inline AI key granted only OpenAI still receives every host the inline gateway
/// redirects). Without a host, a single-entry key resolves to its one target, and
/// a larger set only to the one entry speaking the request's protocol.
pub(crate) fn select_byok_passthrough<'a>(
    set: &'a [crate::config::model_map::ByokPassthrough],
    protocol: ApiVersion,
    origin_host: Option<&str>,
) -> Option<&'a crate::config::model_map::ByokPassthrough> {
    if let Some(host) = origin_host {
        return passthroughs_for_host(set, host).next();
    }
    match set.len() {
        0 => None,
        1 => set.first(),
        _ => {
            // Several same-protocol pass-throughs (the seeded fan-out is mostly
            // `chat_completions`): picking one would forward the client's
            // credential to an arbitrary provider. Refuse (→ ModelNotFound)
            // unless exactly one entry speaks the protocol.
            let mut matching = set.iter().filter(|pt| {
                upstream_api_version_for_provider(&pt.provider, pt.upstream_api_format.as_deref())
                    == protocol
            });
            match (matching.next(), matching.next()) {
                (Some(only), None) => Some(only),
                _ => None,
            }
        }
    }
}

/// Extract the host (authority, no scheme/port/path) from an upstream URL, for
/// matching the gateway-supplied origin host.
fn byok_host(url: &str) -> Option<&str> {
    let after_scheme = url.split("://").nth(1).unwrap_or(url);
    let authority = after_scheme.split('/').next()?;
    Some(authority.split(':').next().unwrap_or(authority))
}

/// A host in the one spelling both sides of the origin-host match use: DNS
/// names are case-insensitive, and a port or a trailing root dot names the same
/// host. Applied to the header AND the configured URL's host.
fn same_host(host: &str) -> String {
    let host = host.split(':').next().unwrap_or(host);
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// The pass-throughs whose endpoint is `origin_host`, in any spelling of it —
/// the one host match every credential decision reads.
fn passthroughs_for_host<'a>(
    set: &'a [crate::config::model_map::ByokPassthrough],
    origin_host: &str,
) -> impl Iterator<Item = &'a crate::config::model_map::ByokPassthrough> {
    let host = same_host(origin_host);
    set.iter().filter(move |pt| byok_host(&pt.upstream_url).is_some_and(|h| same_host(h) == host))
}

/// Which keyless destinations may receive the credential a request forwards.
///
/// A forward-auth key (`vk-`, Inline AI) sends the client's own credential to
/// any target holding no stored credential of its own. That credential was
/// issued by ONE provider, so a keyless target on a DIFFERENT pass-through
/// provider — that provider's override route — must not receive it. Who issued
/// it is read from the request: the origin host names the provider outright;
/// with no host, a key holding one pass-through leaves no doubt, and a key
/// holding several is singled out by the client's `protocol` the way the
/// pass-through fallback itself picks ([`select_byok_passthrough`]) — a request
/// naming no protocol (a forwarded path) singles out none.
///
/// Keyless targets on providers that are NOT pass-throughs of this key (the
/// operator's own servers on curated routes) are outside the question: they
/// receive the forwarded credential. A stored-credential target never sees the
/// client's, and an `sk-` key — or a call the gateway makes on its own account,
/// like a cache embedding — forwards none. Built once per request, before any lock is taken; every
/// resolution path judges targets through it — model routes, the media path
/// and forwarded paths alike.
pub(crate) struct CredentialScope<'a> {
    user: &'a UserContext,
    /// The pass-through downstreams the forwarded credential may belong to.
    /// `None`: no constraint (the key forwards no client credential).
    owners: Option<Vec<&'a str>>,
}

impl<'a> CredentialScope<'a> {
    /// A call that forwards no client credential at all: every target qualifies.
    pub(crate) fn unconstrained(user: &'a UserContext) -> Self {
        Self { user, owners: None }
    }

    pub(crate) fn of(user: &'a UserContext, protocol: Option<ApiVersion>, origin_host: Option<&str>) -> Self {
        let set = &user.byok_passthrough;
        let owners = user.forward_auth.then(|| match origin_host {
            Some(host) => passthroughs_for_host(set, host).map(|pt| pt.downstream_provider_id.as_str()).collect(),
            None if set.len() <= 1 => set.iter().map(|pt| pt.downstream_provider_id.as_str()).collect(),
            None => protocol
                .and_then(|p| select_byok_passthrough(set, p, None))
                .map(|pt| pt.downstream_provider_id.as_str())
                .into_iter()
                .collect(),
        });
        Self { user, owners }
    }

    /// May a keyless target on `downstream_provider_id` receive the credential?
    pub(crate) fn admits_keyless(&self, downstream_provider_id: Option<&str>) -> bool {
        let Some(owners) = &self.owners else { return true };
        let Some(d) = downstream_provider_id else { return true };
        let is_passthrough = self.user.byok_passthrough.iter().any(|pt| pt.downstream_provider_id == d);
        !is_passthrough || owners.contains(&d)
    }

    /// May `m` serve this request?
    pub(crate) fn admits(&self, m: &UpstreamModel) -> bool {
        m.has_credential || self.admits_keyless(m.downstream_provider_id.as_deref())
    }

    /// May a forwarded path addressed to the provider `downstream_provider_id`
    /// be served? Only a pass-through can be refused, and a pass-through's
    /// forwarded paths always reach its own keyless endpoint
    /// ([`forwarded_path_target`]), so this is the keyless question itself.
    pub(crate) fn admits_forwarded_path(&self, downstream_provider_id: &str) -> bool {
        self.admits_keyless(Some(downstream_provider_id))
    }
}

/// Whether `downstream_provider_id` is the pass-through for the request's
/// origin host — the provider the client addressed. A forwarded path carrying
/// an origin host is served by that provider or by none.
pub(crate) fn names_origin_host(user: &UserContext, origin_host: Option<&str>, downstream_provider_id: &str) -> bool {
    origin_host.is_some_and(|host| {
        passthroughs_for_host(&user.byok_passthrough, host).any(|pt| pt.downstream_provider_id == downstream_provider_id)
    })
}

/// Why no provider serves a forwarded path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ForwardedPathRefusal {
    /// No allowed provider's route policy matches the path.
    NoPolicy,
    /// The path carries an origin host, and the provider it names does not
    /// forward the path: another provider's would receive the client's data.
    NotTheAddressedProvider,
    /// No origin host, and every provider forwarding the path would hand the
    /// client's credential to a pass-through it may not belong to.
    CredentialUnattributed,
}

/// The provider a forwarded (catch-all) path is served by, among `matches` —
/// the allowed providers whose route policy matches it, in grant order.
///
/// For a forward-auth key with an origin host: the provider that host names,
/// or none — the client addressed that provider, and its data must not reach
/// another. (Stricter than a model route, deliberately: a model route is an
/// alias the operator mapped, so a stored-credential override still serves it;
/// a forwarded path names no model for anyone to have mapped.) Otherwise:
/// the first match whose target [`CredentialScope`] admits (a forwarded path
/// names no protocol).
pub(crate) fn forwarded_path_provider<'m, P>(
    user: &UserContext,
    origin_host: Option<&str>,
    matches: &'m [(uuid::Uuid, P)],
) -> Result<&'m (uuid::Uuid, P), ForwardedPathRefusal> {
    if matches.is_empty() {
        return Err(ForwardedPathRefusal::NoPolicy);
    }
    // The host binds only a key that forwards the client's own credential: an
    // `sk-` key holds no pass-through for a host to name, and sends the client
    // nowhere but where the operator routed it.
    match origin_host.filter(|_| user.forward_auth) {
        Some(_) => matches
            .iter()
            .find(|(pid, _)| names_origin_host(user, origin_host, &pid.to_string()))
            .ok_or(ForwardedPathRefusal::NotTheAddressedProvider),
        None => {
            let scope = CredentialScope::of(user, None, None);
            matches
                .iter()
                .find(|(pid, _)| scope.admits_forwarded_path(&pid.to_string()))
                .ok_or(ForwardedPathRefusal::CredentialUnattributed)
        }
    }
}

/// The route target a forwarded (catch-all) path is sent to for the provider
/// `downstream_provider_id`: its highest-priority `model_map` entry, ties
/// broken by server id so every replica and every snapshot picks the same one.
///
/// `None` means the path goes to the key's pass-through endpoint for that
/// provider. A pass-through ALWAYS answers that way, override routes or not: an
/// override replaces one model, and a forwarded path names none — sending it
/// to an override's server would divert the provider's whole file/batch
/// surface, and the member's own key with it, to wherever one model was
/// pointed.
pub(crate) fn forwarded_path_target<'a>(
    user: &'a UserContext,
    downstream_provider_id: &str,
) -> Option<&'a UpstreamModel> {
    if user.byok_passthrough.iter().any(|pt| pt.downstream_provider_id == downstream_provider_id) {
        return None;
    }
    user.model_map
        .mappings
        .values()
        .flatten()
        .filter(|t| t.downstream_provider_id.as_deref() == Some(downstream_provider_id))
        .max_by(|a, b| {
            a.priority
                .cmp(&b.priority)
                .then_with(|| b.upstream_server_id.cmp(&a.upstream_server_id))
                .then_with(|| b.model.cmp(&a.model))
        })
}

/// Resolve ALL upstream targets for failover retry.
///
/// Returns the primary target (session-pinned when `affinity` is present, else
/// weighted RR) followed by remaining targets in descending priority order. If
/// only one target exists, returns a single-element vec.
///
/// Only the user's per-key model_map (scoped to the key's downstream provider)
/// is consulted. Returns `ModelNotFound` if the model is not in the key's
/// downstream routes.
#[allow(clippy::too_many_arguments)]
pub fn resolve_all_upstreams(
    request: &ApiRequest,
    user: &UserContext,
    credentials: &ServerCredentials,
    lb_counters: &dashmap::DashMap<String, AtomicUsize>,
    affinity: Option<&str>,
    protocol: ApiVersion,
    origin_host: Option<&str>,
    endpoints: &crate::config::endpoints::EndpointTable,
) -> Result<Vec<UpstreamTarget>, AppError> {
    let model = request.model();

    let models = admitted_route_targets(user, model, affinity, lb_counters, &CredentialScope::of(user, Some(protocol), origin_host));

    if models.is_empty() {
        // BYOK pass-through fallback (curated routes above always win).
        if let Some(pt) = select_byok_passthrough(&user.byok_passthrough, protocol, origin_host) {
            return Ok(vec![build_passthrough_target(pt, model)]);
        }
        return Err(AppError::ModelNotFound(model.to_string()));
    }

    collect_targets(models, user, credentials, endpoints, lb_counters, affinity)
}

/// The alias's route targets `scope` admits, in retry order. When none is left
/// the caller falls back to the pass-through, never to a target on another
/// pass-through provider.
fn admitted_route_targets<'a>(
    user: &'a UserContext,
    alias: &str,
    affinity: Option<&str>,
    lb_counters: &dashmap::DashMap<String, AtomicUsize>,
    scope: &CredentialScope<'_>,
) -> Vec<&'a UpstreamModel> {
    // Judged before the counter's entry is taken: the entry holds its shard's
    // write lock until it drops. A scope that withholds some of the alias's
    // targets rotates its own counter: sharing the alias's with requests that
    // see a different set would let the two interleave into a fixed pick.
    let targets = user.model_map.mappings.get(alias).map_or(&[][..], Vec::as_slice);
    let admitted: Vec<usize> =
        targets.iter().enumerate().filter(|(_, m)| scope.admits(m)).map(|(i, _)| i).collect();
    if admitted.is_empty() {
        return Vec::new();
    }
    let counter_key = if admitted.len() == targets.len() {
        alias.to_string()
    } else {
        let set: Vec<String> = admitted.iter().map(usize::to_string).collect();
        format!("{alias}\u{0}{}", set.join(","))
    };
    // The entry guard MUST drop before this returns — the caller builds targets
    // with another `lb_counters.entry()`, which on the same shard would block
    // forever. Keep nothing but the pick inside it.
    let counter = lb_counters.entry(counter_key).or_insert_with(|| AtomicUsize::new(0));
    user.model_map.select_targets_for_retry_where(alias, affinity, counter.value(), |m| scope.admits(m))
}

/// Build every selected target, skipping one that cannot be forwarded to, and
/// expand each into one target per replica endpoint of its model.
///
/// A route target's replicas come out consecutively, in the order
/// [`order_endpoints`](crate::config::endpoints::order_endpoints) gives this
/// request (`affinity` pins a session to one replica), sharing a
/// [`UpstreamTarget::route_slot`]. The endpoint table is the only place a
/// target's URLs come from: a target no enabled endpoint of its server serves
/// is dropped so the alias's remaining failover targets still serve; only when
/// none is left does the request fail.
fn collect_targets(
    models: Vec<&UpstreamModel>,
    user: &UserContext,
    credentials: &ServerCredentials,
    endpoints: &crate::config::endpoints::EndpointTable,
    lb_counters: &dashmap::DashMap<String, AtomicUsize>,
    affinity: Option<&str>,
) -> Result<Vec<UpstreamTarget>, AppError> {
    let mut targets = Vec::with_capacity(models.len());
    let mut refused = None;
    for (slot, m) in models.into_iter().enumerate() {
        let server = m.upstream_server_id.as_deref().and_then(|s| uuid::Uuid::parse_str(s).ok());
        let model_id = m.upstream_model_id.as_deref().and_then(|s| uuid::Uuid::parse_str(s).ok());
        let members = server.and_then(|server| endpoints.members(server, model_id)).unwrap_or_default();
        if members.is_empty() {
            refused = Some(no_serving_endpoint(m.upstream_model_id.as_deref()));
            continue;
        }
        let api_key = route_credential(m, user, credentials);
        let salt = m.upstream_model_id.as_deref().unwrap_or(&m.model);
        // The guard is dropped at the end of this statement: no other counter
        // of the map is taken while it is held.
        let ordered = crate::config::endpoints::order_endpoints(
            members,
            affinity,
            salt,
            lb_counters.entry(format!("endpoint:{salt}")).or_insert_with(|| AtomicUsize::new(0)).value(),
        );
        for ep in ordered {
            targets.push(build_target(m, api_key.clone(), ep, slot));
        }
    }
    match refused {
        Some(e) if targets.is_empty() => Err(e),
        _ => Ok(targets),
    }
}

/// Whether an upstream refusal says the endpoint does not serve the model it
/// was sent: vLLM answers an unknown model with HTTP 404 and
/// `{"error":{"type":"NotFoundError","param":"model",…}}` (vLLM main,
/// 2026-09). Anything else — another status, another type or parameter, a
/// body that is not that JSON — is not this claim.
pub fn is_model_not_served(e: &AppError) -> bool {
    let AppError::Upstream { status: 404, body, .. } = e else {
        return false;
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else {
        return false;
    };
    let err = &v["error"];
    err["type"] == "NotFoundError" && err["param"] == "model"
}

/// Whether another replica of the same model could answer a request this one
/// failed: no HTTP answer at all (connection, TLS, timeout), an overload or
/// server fault (408, 429, 5xx), or a 404 — a replica may lack a model its
/// siblings serve, and engines word that refusal differently (only vLLM's is
/// recognised as a mismatch to report, [`is_model_not_served`]). Any other
/// client error — a malformed body, a rejected credential, a prompt over the
/// context window — is the same on every replica, so it is not sent to the
/// others.
pub fn another_replica_may_answer(e: &AppError) -> bool {
    match e {
        AppError::Upstream { status, .. } => matches!(*status, 404 | 408 | 429) || *status >= 500,
        // A request that could not be built fails the same way on every
        // replica of the server: they share its credential and its protocol.
        // A fallback to ANOTHER server may still answer.
        AppError::UpstreamUnbuildable(_) => false,
        _ => true,
    }
}

/// Whether a "model not found" from this endpoint for this model is due to be
/// reported, recording it if so (the same once-per-interval gate as the
/// configuration-error log).
pub(crate) fn model_missing_due(endpoint_id: uuid::Uuid, model: &str) -> bool {
    crate::log_throttle::due(&format!("model-missing:{endpoint_id}:{model}"), std::time::Instant::now())
}

/// The refusal for a route target whose model no enabled endpoint serves.
pub(crate) fn no_serving_endpoint(model_id: Option<&str>) -> AppError {
    let model_id = model_id.unwrap_or("-");
    if crate::log_throttle::due(&format!("no-endpoint:{model_id}"), std::time::Instant::now()) {
        tracing::warn!(
            upstream_model_id = model_id,
            "no enabled endpoint serves this model — not forwarded (logged once per model every {} s)",
            crate::log_throttle::EVERY.as_secs()
        );
    }
    AppError::Unroutable {
        reason: "no enabled endpoint of the gateway's upstream server serves this model",
        model: None,
    }
}

/// Resolve upstream target(s) by model name (for media endpoints that don't use `ApiRequest`).
///
/// Same logic as [`resolve_all_upstreams`] but accepts a raw model string instead of `ApiRequest`.
#[allow(clippy::too_many_arguments)]
pub fn resolve_all_upstreams_by_model(
    model: &str,
    user: &UserContext,
    credentials: &ServerCredentials,
    lb_counters: &dashmap::DashMap<String, AtomicUsize>,
    affinity: Option<&str>,
    protocol: ApiVersion,
    origin_host: Option<&str>,
    endpoints: &crate::config::endpoints::EndpointTable,
    forwards_client_credential: bool,
) -> Result<Vec<UpstreamTarget>, AppError> {
    let scope = if forwards_client_credential {
        CredentialScope::of(user, Some(protocol), origin_host)
    } else {
        CredentialScope::unconstrained(user)
    };
    let models = admitted_route_targets(user, model, affinity, lb_counters, &scope);

    if models.is_empty() {
        // BYOK pass-through fallback (media path); curated routes above win.
        if let Some(pt) = select_byok_passthrough(&user.byok_passthrough, protocol, origin_host) {
            return Ok(vec![build_passthrough_target(pt, model)]);
        }
        return Err(AppError::ModelNotFound(model.to_string()));
    }

    collect_targets(models, user, credentials, endpoints, lb_counters, affinity)
}

/// Pick the API version the proxy will speak to the upstream, given the
/// provider and an optional explicit `upstream_api_format` override
/// (`COALESCE(route → model → server)`). This is the sole legitimate
/// downstream-side consumer of `upstream_api_format`.
/// The protocol an upstream speaks: its pinned `upstream_api_format`, else
/// derived from the provider brand.
///
/// **The single derivation, and it must stay single.** `upstream_servers.provider`
/// is free text — no vocabulary check on write, which is why this file also
/// carries `canonical_provider_key` — so a brand arrives spelled any number of
/// ways and `Provider::from_str_relaxed` is what absorbs that. A second
/// derivation matching literals by hand agrees only for the spellings whoever
/// wrote it thought of: `"Anthropic"` or `"google_gemini"` then resolve to one
/// protocol on the path that forwards the request and another on the path that
/// describes it to a client, and the two surfaces disagree about a live route
/// with nothing to report it. `pub` for exactly that reason — the admin crate
/// derives the same answer through here rather than re-deriving it.
pub fn upstream_api_version_for_provider(
    provider: &str,
    upstream_api_format: Option<&str>,
) -> ApiVersion {
    if let Some(fmt) = upstream_api_format {
        return match fmt {
            "responses" => ApiVersion::Responses,
            "anthropic_messages" => ApiVersion::AnthropicMessages,
            "google_gemini" => ApiVersion::GoogleGemini,
            _ => ApiVersion::ChatCompletions,
        };
    }
    // No explicit format — derive the protocol from the provider brand.
    match Provider::from_str_relaxed(provider) {
        Provider::Anthropic => ApiVersion::AnthropicMessages,
        Provider::GoogleGemini => ApiVersion::GoogleGemini,
        _ => ApiVersion::ChatCompletions,
    }
}

/// [`UpstreamTarget::conform_body`] for a target known by its dialect and
/// reasoning gate (a substitution round holds those, not the target).
pub fn conform_for(
    dialect: crate::api::mistral::ChatDialect,
    model: crate::api::mistral::ModelReasoning,
    translated: bool,
    body: bytes::Bytes,
    forward_version: crate::api::sse::ApiVersion,
) -> (bytes::Bytes, Option<crate::api::mistral::Conformed>) {
    let (body, conformed) = match (dialect, forward_version) {
        (crate::api::mistral::ChatDialect::Mistral, crate::api::sse::ApiVersion::ChatCompletions) => {
            let (body, conformed) = crate::api::mistral::conform_chat_body(body, model, translated);
            (body, Some(conformed))
        }
        (crate::api::mistral::ChatDialect::Compatible, crate::api::sse::ApiVersion::ChatCompletions) => {
            crate::api::mistral::conform_compatible_body(body)
        }
        // A translated request is rendered by the Anthropic walk, which
        // already sends only thinking Anthropic verifies.
        (_, crate::api::sse::ApiVersion::AnthropicMessages) if !translated => {
            return crate::api::messages::conform_anthropic_body(body);
        }
        _ => return (body, None),
    };
    (body, conformed.map(|c| crate::api::mistral::Conformed { dialect: dialect.label(), ..c }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    /// Thinking and the answer share Anthropic's `max_tokens`. With no cap from
    /// the client, a request that thinks gets the model's own output limit —
    /// the 4096 default leaves a hard prompt no room to answer — while one that
    /// does not think keeps the default, held under that limit.
    #[test]
    fn a_thinking_request_with_no_cap_gets_the_models_output_limit() {
        use crate::api::sse::ApiVersion;
        let target = |model: &str, limit: Option<i32>, reasons: bool| {
            let mut t = test_replica_target(uuid::Uuid::nil(), uuid::Uuid::nil(), "http://upstream");
            t.passthrough = false;
            t.upstream_api_version = ApiVersion::AnthropicMessages;
            t.model = model.to_string();
            t.max_output_tokens = limit;
            t.accepts_reasoning = reasons;
            t
        };
        let sent = |t: &UpstreamTarget, extra: serde_json::Value| -> serde_json::Value {
            let mut body = serde_json::json!({"model": "alias", "messages": [{"role": "user", "content": "hi"}]});
            body.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
            let request = ApiRequest::parse(ApiVersion::ChatCompletions, &bytes::Bytes::from(body.to_string())).unwrap();
            let (domain, _) = t.prepare_translation(&request);
            let (bytes, _) = domain.translate_to(ApiVersion::AnthropicMessages, &t.model, t.chat_cap_field()).unwrap();
            serde_json::from_slice(&bytes).unwrap()
        };
        // Streamed: the model's own output limit.
        let asks = serde_json::json!({"reasoning_effort": "high", "stream": true});
        let silent = serde_json::json!({"stream": true});
        let off = serde_json::json!({"reasoning_effort": "none", "stream": true});

        assert_eq!(sent(&target("claude-opus-4-7", Some(128_000), true), asks.clone())["max_tokens"], 128_000);
        // A manual budget keeps to half the cap it shares with the answer.
        let manual = sent(&target("claude-sonnet-4-5", Some(64_000), true), asks.clone());
        assert_eq!((manual["max_tokens"].clone(), manual["thinking"]["budget_tokens"].clone()), (64_000.into(), 32_000.into()));
        // A model that thinks unasked, and one that cannot be told to stop.
        assert_eq!(sent(&target("claude-opus-5-5", Some(128_000), true), silent.clone())["max_tokens"], 128_000);
        assert_eq!(sent(&target("claude-opus-5-5", Some(128_000), true), off.clone())["max_tokens"], 128_000);
        // Nothing thinks: the default stays, and never exceeds the model's limit.
        assert_eq!(sent(&target("claude-opus-4-7", Some(128_000), true), silent.clone())["max_tokens"], 4096);
        assert_eq!(sent(&target("claude-sonnet-5", Some(128_000), true), off)["max_tokens"], 4096);
        assert_eq!(sent(&target("claude-opus-4-7", Some(2_000), true), silent.clone())["max_tokens"], 2_000);
        assert_eq!(sent(&target("claude-opus-4-7", Some(4_097), true), silent)["max_tokens"], 4096);
        // A model known not to reason is sent no reasoning, and so no room for it.
        assert_eq!(sent(&target("claude-opus-4-7", Some(128_000), false), asks.clone())["max_tokens"], 4096);
        // An unknown limit keeps the default; the client's own cap always wins.
        assert_eq!(sent(&target("claude-opus-4-7", None, true), asks.clone())["max_tokens"], 4096);
        let capped = serde_json::json!({"reasoning_effort": "high", "max_tokens": 9_000});
        assert_eq!(sent(&target("claude-opus-4-7", Some(128_000), true), capped)["max_tokens"], 9_000);

        // Not streamed: at most what Anthropic's SDKs let a non-streaming
        // request ask for — expected to finish inside ten minutes, reckoned at
        // an hour per 128 000 tokens (21 333), and 8 192 on Opus 4 and 4.1 —
        // on both sides of each bound, never below the 4096 default.
        let asks = serde_json::json!({"reasoning_effort": "high"});
        for (model, limit, max_tokens) in [
            ("claude-opus-4-7", 128_000, 21_333),
            ("claude-opus-4-7", 21_334, 21_333),
            ("claude-opus-4-7", 21_333, 21_333),
            ("claude-opus-4-7", 21_332, 21_332),
            ("claude-opus-4-1-20250805", 32_000, 8_192),
            ("claude-opus-4-20250514", 32_000, 8_192),
            ("anthropic.claude-opus-4-1-20250805-v1:0", 32_000, 8_192),
            ("claude-opus-4-1-20250805", 8_000, 8_000),
            ("claude-sonnet-4-20250514", 64_000, 21_333),
        ] {
            let sent = sent(&target(model, Some(limit), true), asks.clone());
            assert_eq!(sent["max_tokens"], max_tokens, "{model} limit {limit}");
        }
        let manual = sent(&target("claude-sonnet-4-5", Some(64_000), true), asks.clone());
        assert_eq!((manual["max_tokens"].clone(), manual["thinking"]["budget_tokens"].clone()), (21_333.into(), 10_666.into()));
        assert_eq!(sent(&target("claude-opus-5-5", Some(128_000), true), serde_json::json!({}))["max_tokens"], 21_333);
        assert_eq!(sent(&target("claude-opus-4-7", Some(128_000), true), serde_json::json!({}))["max_tokens"], 4096);
    }

    /// A request from each other protocol, translated for a Mistral target and
    /// conformed as the forward does: the emitted body is in Mistral's shape
    /// (checked live against api.mistral.ai, whose schema is closed): the cap
    /// in `max_tokens`, "do not reason" as `reasoning_effort: "none"`, a prefill
    /// as `prefix`, a tool's missing parameters schema filled in.
    #[test]
    fn a_translated_request_reaches_mistral_in_its_shape() {
        use crate::api::sse::ApiVersion;
        let mut t = test_replica_target(uuid::Uuid::nil(), uuid::Uuid::nil(), "https://api.mistral.ai/v1");
        t.passthrough = false;
        t.provider = "mistral".into();
        t.upstream_api_version = ApiVersion::ChatCompletions;
        t.model = "mistral-medium-latest".into();
        t.accepts_reasoning = true;
        let sent = |t: &UpstreamTarget, client: ApiVersion, body: serde_json::Value| {
            let request = ApiRequest::parse(client, &bytes::Bytes::from(body.to_string())).unwrap();
            let (domain, _) = t.prepare_translation(&request);
            let (bytes, _) = domain.translate_to(t.upstream_api_version, &t.model, t.chat_cap_field()).unwrap();
            let (bytes, conformed) = t.conform_body(bytes, t.upstream_api_version, true);
            (serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(), conformed.unwrap())
        };

        // Anthropic: a prefill and thinking switched off.
        let (body, c) = sent(
            &t,
            ApiVersion::AnthropicMessages,
            serde_json::json!({"model": "a", "max_tokens": 300, "thinking": {"type": "disabled"},
                "messages": [{"role": "user", "content": "hi"}, {"role": "assistant", "content": "Hel"}]}),
        );
        assert_eq!(body["max_tokens"], 300);
        assert_eq!(body["reasoning_effort"], "none");
        assert_eq!(body["messages"].as_array().unwrap().last().unwrap()["prefix"], true);
        assert!(c.adapted.contains(&"trailing assistant message sent as a prefix".to_string()));

        // Responses: a custom tool (declared as a function off Responses, by
        // design) whose missing schema Mistral requires, and a cap.
        let (body, c) = sent(
            &t,
            ApiVersion::Responses,
            serde_json::json!({"model": "a", "input": "hi", "max_output_tokens": 200,
                "tools": [{"type": "function", "name": "f", "parameters": {"type": "object", "properties": {}}},
                          {"type": "custom", "name": "patch"}]}),
        );
        assert_eq!(body["max_tokens"], 200, "{body}");
        let tools = body["tools"].as_array().unwrap();
        assert_eq!(tools[1]["type"], "function", "{body}");
        assert_eq!(tools[1]["function"]["name"], "patch");
        assert_eq!(tools[1]["function"]["parameters"], serde_json::json!({"type": "object", "properties": {}}));
        assert!(c.not_carried.is_empty(), "{c:?}");
        for key in body.as_object().unwrap().keys() {
            assert!(!["max_completion_tokens", "store", "user", "seed"].contains(&key.as_str()), "{key}");
        }

        // A document by URL: Mistral's own chunk, not OpenAI's text marker.
        let (body, _) = sent(
            &t,
            ApiVersion::AnthropicMessages,
            serde_json::json!({"model": "a", "max_tokens": 10, "messages": [{"role": "user", "content": [
                {"type": "document", "source": {"type": "url", "url": "https://x/a.pdf"}, "title": "A"},
                {"type": "text", "text": "summarise"}]}]}),
        );
        assert_eq!(
            body["messages"][0]["content"][0],
            serde_json::json!({"type": "document_url", "document_url": "https://x/a.pdf", "document_name": "A"}),
            "{body}"
        );

        // A model known not to reason gets no effort at all, `none` included.
        t.accepts_reasoning = false;
        let (body, _) = sent(
            &t,
            ApiVersion::AnthropicMessages,
            serde_json::json!({"model": "a", "max_tokens": 10, "thinking": {"type": "disabled"},
                "messages": [{"role": "user", "content": "hi"}]}),
        );
        assert!(body.get("reasoning_effort").is_none());

        // An OpenAI-compatible server is not conformed.
        t.provider = "custom".into();
        t.url = "http://vllm:8000/v1".into();
        assert!(t.conform_body(bytes::Bytes::from_static(b"{\"seed\":1}"), ApiVersion::ChatCompletions, false).1.is_none());
    }

    /// An Anthropic target's same-protocol forward is fitted to what
    /// Anthropic verifies, and the badge names Anthropic; a translated one is
    /// already rendered by the walk and passes through the pass unchanged.
    #[test]
    fn an_anthropic_forward_is_conformed_only_in_its_own_protocol() {
        use crate::api::mistral::ChatDialect;
        let body = bytes::Bytes::from(
            serde_json::to_vec(&serde_json::json!({"model": "m", "max_tokens": 10, "messages": [
                {"role": "user", "content": "q"},
                {"role": "assistant", "content": [
                    {"type": "thinking", "thinking": "t", "signature": "synth_1"}, {"type": "text", "text": "a"}]},
                {"role": "user", "content": "next"}]}))
            .unwrap(),
        );
        let reasoning = crate::api::mistral::ModelReasoning { accepts: true, declared: true };
        let (_, own) = conform_for(ChatDialect::Compatible, reasoning, false, body.clone(), ApiVersion::AnthropicMessages);
        assert_eq!(own.as_ref().unwrap().not_carried, ["thinking the gateway built from another provider"]);
        let (sent, translated) = conform_for(ChatDialect::Compatible, reasoning, true, body.clone(), ApiVersion::AnthropicMessages);
        assert_eq!((sent, translated), (body, None));
        assert_eq!(own.as_ref().map(|c| c.dialect), Some("anthropic"));
        let mistral = conform_for(ChatDialect::Mistral, reasoning, false, bytes::Bytes::from_static(b"{\"seed\":1}"), ApiVersion::ChatCompletions);
        assert_eq!(mistral.1.map(|c| c.dialect), Some("mistral"));
        let compatible = conform_for(ChatDialect::Compatible, reasoning, false, bytes::Bytes::from_static(b"{\"tool_choice\":\"any\"}"), ApiVersion::ChatCompletions);
        assert_eq!(compatible.1.map(|c| c.dialect), Some("openai_compatible"));
    }

    /// "Do not reason" is a value OpenAI documents per model: `none` on
    /// GPT-5.1 and later (and GPT-6 Sol and Luna), refused with a 400 by o3,
    /// o4-mini, GPT-5 and GPT-6 Astra. So `none` is sent only to OpenAI's own
    /// API serving a model documented to take it; anywhere else — another
    /// model, a compatible server — nothing is sent and the row says so.
    #[test]
    fn do_not_reason_is_sent_as_none_only_where_the_model_takes_it() {
        use crate::api::sse::ApiVersion;
        let target = |provider: &str, url: &str, model: &str, protocol: ApiVersion| {
            let mut t = test_replica_target(uuid::Uuid::nil(), uuid::Uuid::nil(), url);
            t.passthrough = false;
            t.provider = provider.to_string();
            t.upstream_api_version = protocol;
            t.model = model.to_string();
            t.accepts_reasoning = true;
            t
        };
        // An Anthropic client asking for no thinking, translated.
        let request = ApiRequest::parse(
            ApiVersion::AnthropicMessages,
            &bytes::Bytes::from(
                r#"{"model":"alias","max_tokens":64,"thinking":{"type":"disabled"},"messages":[{"role":"user","content":"hi"}]}"#,
            ),
        )
        .unwrap();
        let sent = |t: &UpstreamTarget| -> (serde_json::Value, Vec<String>) {
            let (domain, not_carried) = t.prepare_translation(&request);
            let (bytes, _) = domain.translate_to(t.upstream_api_version, &t.model, t.chat_cap_field()).unwrap();
            (serde_json::from_slice(&bytes).unwrap(), not_carried)
        };
        let off = |body: &serde_json::Value, protocol: ApiVersion| match protocol {
            ApiVersion::ChatCompletions => body.get("reasoning_effort").cloned(),
            _ => body.get("reasoning").cloned(),
        };
        for protocol in [ApiVersion::ChatCompletions, ApiVersion::Responses] {
            let none = match protocol {
                ApiVersion::ChatCompletions => serde_json::json!("none"),
                _ => serde_json::json!({"effort": "none"}),
            };
            for model in ["gpt-5.1", "gpt-5.5", "gpt-5.6", "gpt-5.2-2025-12-11", "gpt-6-sol", "gpt-6-luna"] {
                let (body, not_carried) = sent(&target("openai", "https://api.openai.com", model, protocol));
                assert_eq!(off(&body, protocol), Some(none.clone()), "{model} {protocol:?}");
                assert!(not_carried.is_empty(), "{model} {protocol:?}: {not_carried:?}");
            }
            for (provider, url, model) in [
                ("openai", "https://api.openai.com", "o3"),
                ("openai", "https://api.openai.com", "o4-mini"),
                ("openai", "https://api.openai.com", "gpt-5"),
                ("openai", "https://api.openai.com", "gpt-5-mini"),
                ("openai", "https://api.openai.com", "gpt-6-astra"),
                ("openai", "https://api.openai.com", "gpt-5.1-codex"),
                // The same model name on a server that is not OpenAI's.
                ("openai", "http://vllm.internal:8000", "gpt-5.5"),
                ("ollama", "http://ollama:11434", "qwen3"),
            ] {
                let (body, not_carried) = sent(&target(provider, url, model, protocol));
                assert_eq!(off(&body, protocol), None, "{model} at {url} {protocol:?}");
                assert_eq!(not_carried, ["reasoning off (not confirmed for this model)"], "{model} at {url} {protocol:?}");
            }
        }
    }

    /// A pass-through's body goes out with the client's own `model`: the
    /// gateway names a model only for a routed target (positive control).
    #[test]
    fn only_a_routed_target_names_its_model_in_the_body() {
        let pt = byok_pt("openai", "https://api.openai.com", "chat_completions");
        let target = build_passthrough_target(&pt, "dall-e-2");
        assert!(target.passthrough);
        assert_eq!(target.forward_model(), None);
        let mut routed = target.clone();
        routed.passthrough = false;
        assert_eq!(routed.forward_model(), Some("dall-e-2"));
    }

    /// Once per subject per interval, on both sides of the boundary; another
    /// subject is logged on its own clock.
    #[test]
    fn a_configuration_error_is_logged_once_per_subject_per_interval() {
        let t0 = std::time::Instant::now();
        let key = "no-endpoint:11111111-2222-4333-8444-555555555555";
        assert!(crate::log_throttle::due(key, t0));
        assert!(!crate::log_throttle::due(key, t0 + std::time::Duration::from_secs(1)));
        assert!(!crate::log_throttle::due(key, t0 + crate::log_throttle::EVERY - std::time::Duration::from_millis(1)));
        assert!(crate::log_throttle::due(key, t0 + crate::log_throttle::EVERY));
        assert!(crate::log_throttle::due("no-route:11111111-2222-4333-8444-555555555555", t0 + std::time::Duration::from_secs(1)));
    }
    use crate::auth::{RateLimitConfig, UserContext};
    use crate::config::model_map::{ByokPassthrough, ModelMap, Provider, test_upstream_model};
    use bytes::Bytes;

    fn byok_pt(provider: &str, url: &str, fmt: &str) -> ByokPassthrough {
        ByokPassthrough {
            provider: provider.to_string(),
            upstream_url: url.to_string(),
            upstream_api_format: Some(fmt.to_string()),
            chat_endpoint_path: None,
            transport: crate::config::upstream_transport::UpstreamTransport::Default,
            downstream_provider_id: "dp".to_string(),
        }
    }

    #[test]
    fn byok_passthrough_selection() {
        // The inline key's fan-out: distinct protocols (anthropic/openai) + several
        // that share chat_completions (the seeded majority).
        let set = vec![
            byok_pt("openai", "https://api.openai.com", "responses"),
            byok_pt("anthropic", "https://api.anthropic.com", "anthropic_messages"),
            byok_pt("groq", "https://api.groq.com/openai", "chat_completions"),
            byok_pt("cerebras", "https://api.cerebras.ai", "chat_completions"),
        ];
        let who = |o: Option<&ByokPassthrough>| o.map(|p| p.provider.clone());

        // A unique protocol resolves without an origin host.
        assert_eq!(
            who(select_byok_passthrough(&set, ApiVersion::AnthropicMessages, None)),
            Some("anthropic".to_string())
        );
        assert_eq!(
            who(select_byok_passthrough(&set, ApiVersion::Responses, None)),
            Some("openai".to_string())
        );
        // Ambiguous protocol (two chat_completions) with no host → refuse, never
        // silently forward the client's credential to an arbitrary provider.
        assert!(select_byok_passthrough(&set, ApiVersion::ChatCompletions, None).is_none());
        // The origin host disambiguates the ambiguous protocol.
        assert_eq!(
            who(select_byok_passthrough(&set, ApiVersion::ChatCompletions, Some("api.cerebras.ai"))),
            Some("cerebras".to_string())
        );
        // A single-target key with no host resolves to its one target (protocol-agnostic).
        let one = vec![byok_pt("groq", "https://api.groq.com/openai", "chat_completions")];
        assert_eq!(
            who(select_byok_passthrough(&one, ApiVersion::AnthropicMessages, None)),
            Some("groq".to_string())
        );
        assert!(select_byok_passthrough(&[], ApiVersion::ChatCompletions, None).is_none());
    }

    #[test]
    fn a_host_the_key_holds_no_pass_through_for_is_refused_never_rerouted() {
        let who = |o: Option<&ByokPassthrough>| o.map(|p| p.provider.clone());
        // An Inline AI key granted one provider still receives every host the
        // Inline gateway redirects: a DeepSeek call must not reach OpenAI with the
        // DeepSeek credential.
        let one = vec![byok_pt("openai", "https://api.openai.com", "chat_completions")];
        assert!(select_byok_passthrough(&one, ApiVersion::ChatCompletions, Some("api.deepseek.com")).is_none());
        // Positive control: the host it does hold, in any spelling of it.
        for spelling in ["api.openai.com", "API.OpenAI.com", "api.openai.com:443", "api.openai.com."] {
            assert_eq!(
                who(select_byok_passthrough(&one, ApiVersion::ChatCompletions, Some(spelling))),
                Some("openai".to_string()),
                "{spelling}"
            );
        }
        // Several entries: a unique protocol match is no licence either.
        let set = vec![
            byok_pt("openai", "https://api.openai.com", "responses"),
            byok_pt("anthropic", "https://api.anthropic.com", "anthropic_messages"),
        ];
        assert!(select_byok_passthrough(&set, ApiVersion::Responses, Some("api.deepseek.com")).is_none());
        assert_eq!(
            who(select_byok_passthrough(&set, ApiVersion::Responses, None)),
            Some("openai".to_string())
        );
    }

    #[test]
    fn passthrough_target_carries_the_endpoint_path_override() {
        // A BYOK pass-through with a chat_endpoint_path override propagates it onto
        // the resolved target, so `forward` substitutes it for the canonical path.
        let mut pt = byok_pt("deepinfra", "https://api.deepinfra.com/v1/openai", "chat_completions");
        pt.chat_endpoint_path = Some("/chat/completions".to_string());
        let target = build_passthrough_target(&pt, "some-model");
        assert_eq!(target.chat_endpoint_path.as_deref(), Some("/chat/completions"));
        assert_eq!(target.upstream_api_version, ApiVersion::ChatCompletions);

        // No override → None (canonical path used by `forward`).
        let plain = byok_pt("groq", "https://api.groq.com/openai", "chat_completions");
        assert_eq!(build_passthrough_target(&plain, "m").chat_endpoint_path, None);
    }

    fn make_user_context(model_map: ModelMap) -> UserContext {
        UserContext {
            inline_ai: false,
            qos_class_id: None,
            qos_class_elevated: false,
            user_id: uuid::Uuid::nil(),
            tenant_id: uuid::Uuid::nil(),
            email: None,
            display_name: None,
            real_api_key: "sk-real-key".to_string(),
            model_map: model_map.into(),
            rate_limit: RateLimitConfig::default(),
            user_rate_override: None,
            key_budget: None,
            tenant_budget: None,
            expires_at: None,
            key_id: None,
            app_id: None,
            session_id: None,
            workspace_id: uuid::Uuid::nil(),
            allowed_provider_ids: Vec::new(),
            allowed_virtual_server_ids: Vec::new(),
            allowed_a2a_agent_ids: Vec::new(),
            mcp_scope: None,
            forward_auth: false,
            byok_passthrough: Vec::new(),
        }
    }

    fn make_request(model: &str) -> ApiRequest {
        let json = format!(
            r#"{{"model":"{model}","messages":[{{"role":"user","content":"hi"}}]}}"#
        );
        ApiRequest::parse(
            crate::api::sse::ApiVersion::ChatCompletions,
            &Bytes::from(json),
        )
        .unwrap()
    }

    fn make_cache() -> ServerCredentials {
        ServerCredentials::default()
    }

    fn make_lb_counters() -> dashmap::DashMap<String, AtomicUsize> {
        dashmap::DashMap::new()
    }

    /// The server reached at `url`: one server per URL in these tests.
    fn server_at(url: &str) -> uuid::Uuid {
        uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, url.as_bytes())
    }

    /// `m` on the server reached at `url`.
    fn at(mut m: crate::config::model_map::UpstreamModel, url: &str) -> crate::config::model_map::UpstreamModel {
        m.upstream_server_id = Some(server_at(url).to_string());
        m
    }

    /// An endpoint table holding, for each of `urls`, its server's one enabled
    /// endpoint.
    fn served(urls: &[&str]) -> crate::config::endpoints::EndpointTable {
        let mut table = crate::config::endpoints::EndpointTable::default();
        for url in urls {
            table.servers.insert(
                server_at(url),
                vec![crate::config::endpoints::EndpointConfig {
                    id: uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, url.as_bytes()),
                    url: (*url).to_string(),
                    weight: 1,
                    max_in_flight: None,
                    waiting_threshold: None,
                    engine_metrics: false,
                    adaptive_concurrency: false,
                    adaptive_itl_target: Default::default(),
                }],
            );
        }
        table
    }

    const UPSTREAM: &str = "https://upstream.test";

    #[test]
    fn capability_resolve_null_falls_back_to_defaults() {
        // All flags NULL → the standard text-LLM baseline.
        let model = test_upstream_model(Provider::OpenAi, "m");
        let caps = ModelCapabilities::resolve(&model);
        assert!(caps.function_calling); // DEFAULT_FUNCTION_CALLING
        assert!(caps.system_messages); // DEFAULT_SYSTEM_MESSAGES
        assert!(caps.response_schema); // DEFAULT_RESPONSE_SCHEMA
        assert!(!caps.vision); // DEFAULT_VISION
        assert!(!caps.reasoning);
        assert!(!caps.pdf_input);
    }

    /// Admin's bake and the edge's gate compose to one verdict per case: sent
    /// unless declared off or carried by the catalog without the flag — and the
    /// advertised flag never claims more than was declared.
    #[test]
    fn the_baked_reasoning_flag_gates_translation_as_intended() {
        for (declared, catalog_matched, sent) in [
            (None, false, true),
            (None, true, false),
            (Some(true), false, true),
            (Some(true), true, true),
            (Some(false), false, false),
            (Some(false), true, false),
        ] {
            let mut model = test_upstream_model(Provider::OpenAi, "m");
            model.supports_reasoning = ModelCapabilities::edge_reasoning_flag(declared, catalog_matched);
            assert_eq!(ModelCapabilities::accepts_reasoning(&model), sent, "{declared:?} {catalog_matched}");
            assert_eq!(ModelCapabilities::resolve(&model).reasoning, declared == Some(true));
        }
    }

    #[test]
    fn capability_resolve_explicit_value_wins() {
        // An explicit flag (already COALESCE'd route→model→catalog on the wire)
        // overrides the default in either direction.
        let mut model = test_upstream_model(Provider::OpenAi, "m");
        model.supports_vision = Some(true);
        model.supports_function_calling = Some(false);
        let caps = ModelCapabilities::resolve(&model);
        assert!(caps.vision);
        assert!(!caps.function_calling);
    }

    #[tokio::test]
    async fn model_in_map_returns_mapped_target() {
        let mut map = ModelMap::default();
        map.mappings.insert(
            "gpt-4o".to_string(),
            vec![at(test_upstream_model(Provider::OpenAi, "gpt-4o-2024-08-06"), UPSTREAM)],
        );
        let user = make_user_context(map);
        let request = make_request("gpt-4o");
        let cache = make_cache();
        let lb = make_lb_counters();

        let target = resolve_upstream(&request, &user, &cache, &lb, None, crate::api::sse::ApiVersion::ChatCompletions, None, &served(&[UPSTREAM])).unwrap();
        assert_eq!(target.model, "gpt-4o-2024-08-06");
        assert_eq!(target.provider, "open_ai");
        assert_eq!(target.url, UPSTREAM);
        assert_eq!(target.endpoint_id, Some(uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, UPSTREAM.as_bytes())));
    }

    /// A target no endpoint of the table serves is refused — never forwarded
    /// to a host nobody configured with that server's credential: not when its
    /// server is unknown to the table, and not when it names no server.
    #[tokio::test]
    async fn a_target_without_an_endpoint_is_refused_not_sent_anywhere() {
        let (cache, lb) = (make_cache(), make_lb_counters());
        let mut model = at(test_upstream_model(Provider::Custom, "llama3"), "http://vllm:8000");
        model.has_credential = true;
        let mut map = ModelMap::default();
        map.mappings.insert("local".to_string(), vec![model.clone()]);
        let user = make_user_context(map);

        for table in [served(&[]), served(&["http://other:8000"])] {
            let err = resolve_upstream(&make_request("local"), &user, &cache, &lb, None, crate::api::sse::ApiVersion::ChatCompletions, None, &table)
                .unwrap_err();
            assert_matches!(err, AppError::Unroutable { .. });
        }
        // Positive control: the same target, its server's endpoint shipped.
        let t = resolve_upstream(&make_request("local"), &user, &cache, &lb, None, crate::api::sse::ApiVersion::ChatCompletions, None, &served(&["http://vllm:8000"]))
            .unwrap();
        assert_eq!(t.url, "http://vllm:8000");

        // A target naming no server is the same absence.
        model.upstream_server_id = None;
        let mut map = ModelMap::default();
        map.mappings.insert("local".to_string(), vec![model]);
        let user = make_user_context(map);
        let err = resolve_upstream(&make_request("local"), &user, &cache, &lb, None, crate::api::sse::ApiVersion::ChatCompletions, None, &served(&["http://vllm:8000"]))
            .unwrap_err();
        assert_matches!(err, AppError::Unroutable { .. });
    }

    /// Dropping a target without an endpoint leaves the alias's other targets
    /// serving: one broken server does not take the whole failover chain down.
    #[tokio::test]
    async fn a_target_without_an_endpoint_is_skipped_and_the_others_still_serve() {
        let mut map = ModelMap::default();
        let mut broken = at(test_upstream_model(Provider::Custom, "broken"), "http://gone:8000");
        broken.priority = 10;
        let good = at(test_upstream_model(Provider::Custom, "good"), "http://vllm:8000");
        map.mappings.insert("m".to_string(), vec![broken, good]);
        let user = make_user_context(map);
        let (cache, lb) = (make_cache(), make_lb_counters());

        let targets = resolve_all_upstreams(&make_request("m"), &user, &cache, &lb, None, crate::api::sse::ApiVersion::ChatCompletions, None, &served(&["http://vllm:8000"]))
            .unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].model, "good");
        assert_eq!(targets[0].url, "http://vllm:8000");
    }

    /// An Inline AI key holding two pass-throughs, with an override route on the
    /// OpenAI one sending `shared-model` to a keyless on-prem server.
    fn two_passthroughs_and_a_keyless_override() -> UserContext {
        let mut over = at(test_upstream_model(Provider::Custom, "on-prem"), "http://on-prem:8000");
        over.downstream_provider_id = Some("dp-openai".to_string());
        let mut map = ModelMap::default();
        map.mappings.insert("shared-model".to_string(), vec![over]);
        let mut user = make_user_context(map);
        let mut openai = byok_pt("openai", "https://api.openai.com", "chat_completions");
        openai.downstream_provider_id = "dp-openai".to_string();
        let mut deepseek = byok_pt("deepseek", "https://api.deepseek.com", "chat_completions");
        deepseek.downstream_provider_id = "dp-deepseek".to_string();
        user.byok_passthrough = vec![openai, deepseek];
        // An Inline AI key forwards the client's own credential.
        user.forward_auth = true;
        user
    }

    /// The model list judges each alias's targets as a call would: an override
    /// whose keyless target the caller's credential may not reach is not
    /// listed, and lends no window — the list is what the client plans against.
    #[test]
    fn the_model_list_lists_only_what_the_caller_may_reach() {
        let user = two_passthroughs_and_a_keyless_override();
        let listed = |host: Option<&'static str>| -> Vec<String> {
            let mut headers = axum::http::HeaderMap::new();
            if let Some(h) = host {
                headers.insert("x-origin-host", axum::http::HeaderValue::from_static(h));
            }
            crate::proxy::resolved_entries(&user, &[crate::api::sse::ApiVersion::ChatCompletions], &headers)
                .into_iter()
                .map(|e| e.alias)
                .collect()
        };
        assert!(listed(Some("api.deepseek.com")).is_empty(), "the DeepSeek credential never reaches the OpenAI override");
        assert!(listed(None).is_empty(), "an unattributed credential reaches neither pass-through's override");
        // Positive control: the override's own provider lists it.
        assert_eq!(listed(Some("api.openai.com")), vec!["shared-model".to_string()]);
        // A key forwarding no client credential lists every alias.
        let mut stored = user.clone();
        stored.forward_auth = false;
        let headers = axum::http::HeaderMap::new();
        assert_eq!(
            crate::proxy::resolved_entries(&stored, &[crate::api::sse::ApiVersion::ChatCompletions], &headers).len(),
            1
        );
    }

    /// The OpenAI-shaped list is read by Chat and Responses clients alike, so
    /// it lists an alias a call in EITHER grammar could reach: with no origin
    /// host, which pass-through a credential belongs to follows the grammar.
    #[test]
    fn the_openai_list_lists_what_either_of_its_grammars_reaches() {
        use crate::api::sse::ApiVersion::{ChatCompletions, Responses};
        let mut user = two_passthroughs_and_a_keyless_override();
        // The override's provider speaks Responses; the other speaks Chat.
        for pt in &mut user.byok_passthrough {
            if pt.downstream_provider_id == "dp-openai" {
                *pt = byok_pt("openai", "https://api.openai.com", "responses");
                pt.downstream_provider_id = "dp-openai".to_string();
            }
        }
        let headers = axum::http::HeaderMap::new();
        let listed = |callers: &[crate::api::sse::ApiVersion]| crate::proxy::resolved_entries(&user, callers, &headers).len();
        assert_eq!(listed(&[ChatCompletions]), 0, "a Chat call's credential is the Chat pass-through's");
        assert_eq!(listed(&[Responses]), 1, "a Responses call's credential is the override provider's");
        assert_eq!(listed(&[ChatCompletions, Responses]), 1);
    }

    #[tokio::test]
    async fn an_override_route_never_receives_a_credential_minted_for_another_host() {
        let user = two_passthroughs_and_a_keyless_override();
        let (cache, lb) = (make_cache(), make_lb_counters());
        let table = served(&["http://on-prem:8000"]);
        let request = make_request("shared-model");
        let resolve = |host: Option<&'static str>| {
            resolve_all_upstreams(&request, &user, &cache, &lb, None, crate::api::sse::ApiVersion::ChatCompletions, host, &table)
        };

        // A DeepSeek call for the same model name goes to DeepSeek, never to
        // the OpenAI pass-through's keyless override with the DeepSeek key.
        let t = resolve(Some("api.deepseek.com")).unwrap();
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].url, "https://api.deepseek.com");
        assert!(!t[0].has_stored_credential);

        // Positive control: the override's own provider's host reaches it, in
        // any spelling of that host.
        for host in ["api.openai.com", "API.OpenAI.com:443"] {
            let t = resolve(Some(host)).unwrap();
            assert_eq!(t[0].url, "http://on-prem:8000", "{host}");
        }
        // No origin host, and both pass-throughs speak this protocol: whose
        // credential the client sent is unknown, so neither the override nor a
        // pass-through receives it.
        let err = resolve(None).unwrap_err();
        assert_matches!(err, AppError::ModelNotFound(_));
        // The shape the snapshot builds: a `vk-` key bound to ONE pass-through,
        // carrying its override. No doubt without a host, so the override
        // serves; a host naming another provider is refused outright — the
        // credential is that provider's, and this key holds no route to it.
        let mut single = two_passthroughs_and_a_keyless_override();
        single.byok_passthrough.retain(|pt| pt.downstream_provider_id == "dp-openai");
        let t = resolve_all_upstreams(&request, &single, &cache, &lb, None, crate::api::sse::ApiVersion::ChatCompletions, None, &table)
            .unwrap();
        assert_eq!(t[0].url, "http://on-prem:8000");
        let err = resolve_all_upstreams(&request, &single, &cache, &lb, None, crate::api::sse::ApiVersion::ChatCompletions, Some("api.deepseek.com"), &table)
            .unwrap_err();
        assert_matches!(err, AppError::ModelNotFound(_));

        // A host the key holds no pass-through for reaches nothing.
        let err = resolve(Some("api.example.com")).unwrap_err();
        assert_matches!(err, AppError::ModelNotFound(_));

        // A key that forwards no client credential (`sk-`) has nothing at risk:
        // the origin host does not take its keyless route away.
        let mut managed = two_passthroughs_and_a_keyless_override();
        managed.forward_auth = false;
        let t = resolve_all_upstreams(&request, &managed, &cache, &lb, None, crate::api::sse::ApiVersion::ChatCompletions, Some("api.deepseek.com"), &table)
            .unwrap();
        assert_eq!(t[0].url, "http://on-prem:8000");

        // The media path resolves through the same rule.
        let t = resolve_all_upstreams_by_model("shared-model", &user, &cache, &lb, None, crate::api::sse::ApiVersion::ChatCompletions, Some("api.deepseek.com"), &table, true)
            .unwrap();
        assert_eq!(t[0].url, "https://api.deepseek.com");
        // A call made on the gateway's own account (a cache embedding) forwards
        // no client credential, so nothing is withheld from it.
        let t = resolve_all_upstreams_by_model("shared-model", &user, &cache, &lb, None, crate::api::sse::ApiVersion::ChatCompletions, None, &table, false)
            .unwrap();
        assert_eq!(t[0].url, "http://on-prem:8000");
    }

    #[tokio::test]
    async fn a_scope_that_withholds_part_of_an_alias_rotates_its_own_counter() {
        // Two equal peers: the keyless override (dp-openai) and a stored one.
        let mut user = two_passthroughs_and_a_keyless_override();
        let mut stored = at(test_upstream_model(Provider::Custom, "stored"), "http://stored:8000");
        stored.has_credential = true;
        std::sync::Arc::make_mut(&mut user.model_map).mappings.get_mut("shared-model").unwrap().push(stored);
        let (cache, lb) = (make_cache(), make_lb_counters());
        let table = served(&["http://on-prem:8000", "http://stored:8000"]);
        let request = make_request("shared-model");
        // The alias-level counters; each target's endpoint order keeps its own
        // (`endpoint:<model>`), which this does not count.
        let alias_counters = || lb.iter().filter(|e| !e.key().starts_with("endpoint:")).count();

        // Everything admitted: the alias's own counter turns.
        resolve_all_upstreams(&request, &user, &cache, &lb, None, crate::api::sse::ApiVersion::ChatCompletions, Some("api.openai.com"), &table)
            .unwrap();
        assert!(lb.contains_key("shared-model"));
        assert_eq!(alias_counters(), 1);
        // Part withheld: a counter of its own, and the alias's is left alone.
        let before = lb.get("shared-model").unwrap().load(std::sync::atomic::Ordering::Relaxed);
        resolve_all_upstreams(&request, &user, &cache, &lb, None, crate::api::sse::ApiVersion::ChatCompletions, Some("api.deepseek.com"), &table)
            .unwrap();
        assert_eq!(alias_counters(), 2, "the withholding scope keys its own counter");
        assert_eq!(lb.get("shared-model").unwrap().load(std::sync::atomic::Ordering::Relaxed), before);
    }

    #[tokio::test]
    async fn a_target_holding_its_own_credential_serves_any_origin_host() {
        // A stored-credential target never sees the client's credential, so the
        // origin host does not decide whether it serves.
        let mut user = two_passthroughs_and_a_keyless_override();
        for t in std::sync::Arc::make_mut(&mut user.model_map).mappings.values_mut().flatten() {
            t.has_credential = true;
        }
        let (cache, lb) = (make_cache(), make_lb_counters());
        let t = resolve_all_upstreams(&make_request("shared-model"), &user, &cache, &lb, None, crate::api::sse::ApiVersion::ChatCompletions, Some("api.deepseek.com"), &served(&["http://on-prem:8000"]))
            .unwrap();
        assert_eq!(t[0].url, "http://on-prem:8000");
        assert!(t[0].has_stored_credential);
    }

    #[test]
    fn a_forwarded_path_is_admitted_only_where_the_origin_host_holds() {
        use ForwardedPathRefusal as R;
        let user = two_passthroughs_and_a_keyless_override();
        let id = |s: &str| uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, s.as_bytes());
        // Provider ids are UUIDs on the wire; the fixture's downstream names are
        // mapped onto them for this test.
        let mut user = user;
        for pt in &mut user.byok_passthrough {
            pt.downstream_provider_id = id(&pt.downstream_provider_id).to_string();
        }
        for m in std::sync::Arc::make_mut(&mut user.model_map).mappings.values_mut().flatten() {
            m.downstream_provider_id = m.downstream_provider_id.as_deref().map(|d| id(d).to_string());
        }
        let (openai, deepseek, local) = (id("dp-openai"), id("dp-deepseek"), id("dp-local"));
        let pick = |u: &UserContext, host, matches: &[(uuid::Uuid, ())]| {
            forwarded_path_provider(u, host, matches).map(|(pid, _)| *pid)
        };

        // With a host: the provider it names, whatever the grant order.
        let both = [(openai, ()), (deepseek, ())];
        assert_eq!(pick(&user, Some("api.deepseek.com"), &both), Ok(deepseek));
        assert_eq!(pick(&user, Some("API.OpenAI.com"), &both), Ok(openai));
        // ... and never another provider, not even the operator's own.
        assert_eq!(
            pick(&user, Some("api.deepseek.com"), &[(openai, ()), (local, ())]),
            Err(R::NotTheAddressedProvider)
        );
        // No host, two pass-throughs: a forwarded path names no protocol, so
        // neither is singled out — but the operator's own provider still serves.
        assert_eq!(pick(&user, None, &both), Err(R::CredentialUnattributed));
        assert_eq!(pick(&user, None, &[(openai, ()), (local, ())]), Ok(local));
        // Positive control: a key holding one pass-through leaves no doubt.
        let mut single = user.clone();
        single.byok_passthrough.retain(|pt| pt.downstream_provider_id == openai.to_string());
        assert_eq!(pick(&single, None, &both), Ok(openai));
        assert_eq!(pick(&user, None, &[]), Err(R::NoPolicy));

        // A pass-through's forwarded paths go to its own endpoint, never to the
        // server one of its models is overridden to ...
        assert!(forwarded_path_target(&user, &openai.to_string()).is_none());
        // ... while any other provider's go to ITS highest-priority target, and
        // never to another provider's.
        let mut with_local = user.clone();
        for (name, priority) in [("local-low", 1), ("local-high", 5)] {
            let mut m = test_upstream_model(Provider::Custom, name);
            m.downstream_provider_id = Some(local.to_string());
            m.priority = priority;
            std::sync::Arc::make_mut(&mut with_local.model_map).mappings.insert(name.to_string(), vec![m]);
        }
        assert_eq!(
            forwarded_path_target(&with_local, &local.to_string()).map(|m| m.model.as_str()),
            Some("local-high")
        );
        assert!(forwarded_path_target(&with_local, &id("dp-nobody").to_string()).is_none());

        // An `sk-` key: a host names nothing it holds, and binds nothing.
        let mut managed = user.clone();
        managed.forward_auth = false;
        managed.byok_passthrough.clear();
        assert_eq!(pick(&managed, Some("api.openai.com"), &[(local, ())]), Ok(local));
    }

    #[tokio::test]
    async fn the_operators_own_keyless_route_serves_any_origin_host() {
        // Narrow on purpose: only another PASS-THROUGH provider's keyless target
        // is withheld. A keyless route on a provider of the operator's own keeps
        // receiving the forwarded credential, as the credential rule has it.
        let mut user = two_passthroughs_and_a_keyless_override();
        let mut local = at(test_upstream_model(Provider::Custom, "llama"), "http://local-vllm:8000");
        local.downstream_provider_id = Some("dp-local".to_string());
        std::sync::Arc::make_mut(&mut user.model_map).mappings.insert("llama".to_string(), vec![local]);
        let (cache, lb) = (make_cache(), make_lb_counters());
        for host in [Some("api.deepseek.com"), Some("api.example.com"), None] {
            let t = resolve_all_upstreams(&make_request("llama"), &user, &cache, &lb, None, crate::api::sse::ApiVersion::ChatCompletions, host, &served(&["http://local-vllm:8000"]))
                .unwrap();
            assert_eq!(t[0].url, "http://local-vllm:8000", "{host:?}");
        }
    }

    /// A replicated server: `n` endpoints for one server, and a model on it.
    fn replicated(n: u128) -> (ModelMap, crate::config::endpoints::EndpointTable, uuid::Uuid) {
        use crate::config::endpoints::{EndpointConfig, EndpointTable};
        let server = uuid::Uuid::from_u128(0xabc);
        let model_id = uuid::Uuid::from_u128(0xdef);
        let mut m = test_upstream_model(Provider::Custom, "llama");
        m.upstream_server_id = Some(server.to_string());
        m.upstream_model_id = Some(model_id.to_string());
        let mut map = ModelMap::default();
        map.mappings.insert("llama".to_string(), vec![m]);
        let mut table = EndpointTable::default();
        table.servers.insert(
            server,
            (1..=n)
                .map(|i| EndpointConfig {
                    id: uuid::Uuid::from_u128(i),
                    url: format!("http://replica-{i}:8000"),
                    weight: 1,
                    max_in_flight: None,
                    waiting_threshold: None,
                    engine_metrics: false,
                    adaptive_concurrency: false,
                    adaptive_itl_target: Default::default(),
                })
                .collect(),
        );
        (map, table, model_id)
    }

    /// Every replica of the model is a target, consecutively, sharing the
    /// route slot: moving between them is a spill, and the breaker keys each.
    #[tokio::test]
    async fn a_replicated_model_expands_to_one_target_per_endpoint() {
        let (map, table, _) = replicated(3);
        let user = make_user_context(map);
        let (cache, lb) = (make_cache(), make_lb_counters());
        let targets = resolve_all_upstreams(&make_request("llama"), &user, &cache, &lb, Some("sess-1"), crate::api::sse::ApiVersion::ChatCompletions, None, &table)
            .unwrap();
        assert_eq!(targets.len(), 3);
        let mut urls: Vec<&str> = targets.iter().map(|t| t.url.as_str()).collect();
        urls.sort_unstable();
        assert_eq!(urls, vec!["http://replica-1:8000", "http://replica-2:8000", "http://replica-3:8000"]);
        assert!(targets.iter().all(|t| t.same_route_as(&targets[0]) && t.model == "llama"));
        for t in &targets {
            assert_eq!(t.breaker_key(), t.endpoint_id.unwrap().to_string());
        }
    }

    /// Every turn of a session goes to the same replica first.
    #[tokio::test]
    async fn a_session_is_pinned_to_one_replica() {
        let (map, table, _) = replicated(4);
        let user = make_user_context(map);
        let (cache, lb) = (make_cache(), make_lb_counters());
        let first = |key: &'static str| {
            resolve_all_upstreams(&make_request("llama"), &user, &cache, &lb, Some(key), crate::api::sse::ApiVersion::ChatCompletions, None, &table)
                .unwrap()[0]
                .endpoint_id
        };
        let pinned = first("sess-a");
        for _ in 0..5 {
            assert_eq!(first("sess-a"), pinned);
        }
        // Without a session the first replica rotates.
        let rr: std::collections::HashSet<_> = (0..4)
            .map(|_| {
                resolve_all_upstreams(&make_request("llama"), &user, &cache, &lb, None, crate::api::sse::ApiVersion::ChatCompletions, None, &table)
                    .unwrap()[0]
                    .endpoint_id
            })
            .collect();
        assert_eq!(rr.len(), 4, "round-robin did not visit every replica");
    }

    /// Resolving never holds one load-balancing counter while taking another:
    /// the counters share a `DashMap`, whose entry guard is a shard write lock
    /// that is not re-entrant, so two keys on one shard would block the thread
    /// for ever. A two-shard map puts the alias's and the model's counters on
    /// one shard for about half of the models tried here; the resolution runs
    /// on its own thread so a hang fails the test instead of stalling it.
    #[test]
    fn resolving_never_holds_one_counter_while_taking_another() {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            rt.block_on(async {
                for n in 0..16u128 {
                    let (mut map, table, _) = replicated(2);
                    let model_id = uuid::Uuid::from_u128(0x1000 + n);
                    for targets in map.mappings.values_mut() {
                        targets[0].upstream_model_id = Some(model_id.to_string());
                    }
                    let user = make_user_context(map);
                    let lb = dashmap::DashMap::with_shard_amount(2);
                    let cache = make_cache();
                    resolve_all_upstreams(&make_request("llama"), &user, &cache, &lb, None, crate::api::sse::ApiVersion::ChatCompletions, None, &table)
                        .unwrap();
                    resolve_all_upstreams_by_model("llama", &user, &cache, &lb, None, crate::api::sse::ApiVersion::ChatCompletions, None, &table, true)
                        .unwrap();
                }
            });
            let _ = tx.send(());
        });
        assert!(
            rx.recv_timeout(std::time::Duration::from_secs(10)).is_ok(),
            "resolution deadlocked on the load-balancing counters"
        );
    }

    /// A model only some endpoints serve is sent only to those; a model no
    /// enabled endpoint serves is refused, not sent to the server's URL.
    #[tokio::test]
    async fn a_model_goes_only_to_the_endpoints_that_serve_it() {
        let (map, mut table, model_id) = replicated(3);
        table.model_members.insert(model_id, vec![uuid::Uuid::from_u128(2)]);
        let user = make_user_context(map);
        let (cache, lb) = (make_cache(), make_lb_counters());
        let targets = resolve_all_upstreams(&make_request("llama"), &user, &cache, &lb, Some("s"), crate::api::sse::ApiVersion::ChatCompletions, None, &table)
            .unwrap();
        assert_eq!(targets.iter().map(|t| t.url.as_str()).collect::<Vec<_>>(), vec!["http://replica-2:8000"]);

        table.model_members.insert(model_id, Vec::new());
        let err = resolve_all_upstreams(&make_request("llama"), &user, &cache, &lb, Some("s"), crate::api::sse::ApiVersion::ChatCompletions, None, &table)
            .unwrap_err();
        assert_matches!(err, AppError::Unroutable { .. });
    }

    #[test]
    fn only_vllms_model_not_found_counts_as_a_model_the_endpoint_does_not_serve() {
        let vllm = r#"{"error":{"message":"The model `x` does not exist.","type":"NotFoundError","param":"model","code":404}}"#;
        assert!(is_model_not_served(&AppError::upstream(404, vllm.to_string())));
        // Same body on another status, another parameter, or another type: no.
        assert!(!is_model_not_served(&AppError::upstream(400, vllm.to_string())));
        let other_param = vllm.replace(r#""param":"model""#, r#""param":"lora""#);
        assert!(!is_model_not_served(&AppError::upstream(404, other_param)));
        let other_type = vllm.replace("NotFoundError", "BadRequestError");
        assert!(!is_model_not_served(&AppError::upstream(404, other_type)));
        assert!(!is_model_not_served(&AppError::upstream(404, "not found".to_string())));
    }

    #[test]
    fn only_a_failure_another_replica_could_fix_moves_to_one() {
        let upstream = |status: u16, body: &str| AppError::upstream(status, body);
        for status in [408, 429, 500, 502, 503, 504] {
            assert!(another_replica_may_answer(&upstream(status, "{}")), "{status}");
        }
        for status in [400, 401, 403, 413, 422] {
            assert!(!another_replica_may_answer(&upstream(status, "{}")), "{status}");
        }
        // A 404 in any wording: another replica may serve the model.
        let vllm = r#"{"error":{"message":"The model `x` does not exist.","type":"NotFoundError","param":"model","code":404}}"#;
        assert!(another_replica_may_answer(&upstream(404, vllm)));
        let ollama = r#"{"error":{"message":"model \"x\" not found, try pulling it first","type":"api_error","param":null,"code":null}}"#;
        assert!(another_replica_may_answer(&upstream(404, ollama)));
        // No answer at all: another replica may be reachable.
        let unreachable =
            AppError::UpstreamUnreachable { kind: "connection", detail: "refused".into(), model: None };
        assert!(another_replica_may_answer(&unreachable));
        // A credential that could not be minted this time may mint for the
        // next replica; a request that could not be built fails on every one.
        assert!(another_replica_may_answer(&AppError::Internal("credential could not be minted".into())));
        assert!(!another_replica_may_answer(&AppError::UpstreamUnbuildable("bad header".into())));
    }

    /// The table is the only place a target's URLs come from: a server it
    /// does not know is refused, never reached at some URL of its own.
    #[tokio::test]
    async fn a_server_the_table_does_not_know_is_refused() {
        let (map, table, _) = replicated(3);
        let user = make_user_context(map);
        let (cache, lb) = (make_cache(), make_lb_counters());
        let err = resolve_all_upstreams(&make_request("llama"), &user, &cache, &lb, Some("s"), crate::api::sse::ApiVersion::ChatCompletions, None, &crate::config::endpoints::EndpointTable::default())
            .unwrap_err();
        assert_matches!(err, AppError::Unroutable { .. });
        // Positive control: the same mapping, its server's endpoints shipped.
        let targets = resolve_all_upstreams(&make_request("llama"), &user, &cache, &lb, Some("s"), crate::api::sse::ApiVersion::ChatCompletions, None, &table)
            .unwrap();
        assert_eq!(targets.len(), 3);
        assert!(targets.iter().all(|t| t.endpoint_id.is_some()));
    }

    #[tokio::test]
    async fn model_not_in_map_returns_model_not_found() {
        let user = make_user_context(ModelMap::default());
        let request = make_request("unknown-model");
        let cache = make_cache();
        let lb = make_lb_counters();

        let err = resolve_upstream(&request, &user, &cache, &lb, None, crate::api::sse::ApiVersion::ChatCompletions, None, &served(&[UPSTREAM])).unwrap_err();
        assert_matches!(err, AppError::ModelNotFound(_));
    }

    #[tokio::test]
    async fn a_target_goes_to_its_own_servers_endpoint() {
        let mut map = ModelMap::default();
        let model = at(test_upstream_model(Provider::Ollama, "llama3"), "http://ollama:11434");
        map.mappings.insert("local-llama".to_string(), vec![model]);

        let user = make_user_context(map);
        let request = make_request("local-llama");
        let cache = make_cache();
        let lb = make_lb_counters();

        let target = resolve_upstream(&request, &user, &cache, &lb, None, crate::api::sse::ApiVersion::ChatCompletions, None, &served(&[UPSTREAM, "http://ollama:11434"])).unwrap();
        assert_eq!(target.url, "http://ollama:11434");
        assert_eq!(target.model, "llama3");
    }

    #[tokio::test]
    async fn api_key_is_from_user_context_when_no_credential() {
        let mut map = ModelMap::default();
        map.mappings.insert(
            "gpt-4o".to_string(),
            vec![at(test_upstream_model(Provider::OpenAi, "gpt-4o"), UPSTREAM)],
        );
        let user = make_user_context(map);
        let request = make_request("gpt-4o");
        let cache = make_cache();
        let lb = make_lb_counters();

        let target = resolve_upstream(&request, &user, &cache, &lb, None, crate::api::sse::ApiVersion::ChatCompletions, None, &served(&[UPSTREAM])).unwrap();
        assert_eq!(target.api_key, "sk-real-key");
    }

    /// A target presents its own server's stored credential, opened in the
    /// configuration it routes on; a server whose credential that
    /// configuration does not carry presents none.
    #[test]
    fn a_target_presents_its_servers_credential() {
        let mut map = ModelMap::default();
        let mut model = at(test_upstream_model(Provider::OpenAi, "gpt-4o"), UPSTREAM);
        model.has_credential = true;
        map.mappings.insert("test-model".to_string(), vec![model]);
        let user = make_user_context(map);
        let request = make_request("test-model");
        let lb = make_lb_counters();

        let key = [3u8; 32];
        let sealed = crate::crypto::encrypt("sk-upstream-key", &key).unwrap();
        let credentials = ServerCredentials::open([(server_at(UPSTREAM).to_string(), sealed.as_str())], Some(&key));
        let target = resolve_upstream(&request, &user, &credentials, &lb, None, crate::api::sse::ApiVersion::ChatCompletions, None, &served(&[UPSTREAM])).unwrap();
        assert_eq!(target.api_key, "sk-upstream-key");

        let other = ServerCredentials::open([("another-server".to_string(), sealed.as_str())], Some(&key));
        let target = resolve_upstream(&request, &user, &other, &lb, None, crate::api::sse::ApiVersion::ChatCompletions, None, &served(&[UPSTREAM])).unwrap();
        assert_eq!(target.api_key, "", "another server's credential is never presented");
    }

    #[tokio::test]
    async fn lb_round_robin_distributes_across_targets() {
        let mut map = ModelMap::default();
        let mut a = at(test_upstream_model(Provider::OpenAi, "model-a"), UPSTREAM);
        a.priority = 0;
        let mut b = at(test_upstream_model(Provider::OpenAi, "model-b"), UPSTREAM);
        b.priority = 0;
        map.mappings.insert("test".to_string(), vec![a, b]);

        let user = make_user_context(map);
        let cache = make_cache();
        let lb = make_lb_counters();

        let req1 = make_request("test");
        let t1 = resolve_upstream(&req1, &user, &cache, &lb, None, crate::api::sse::ApiVersion::ChatCompletions, None, &served(&[UPSTREAM])).unwrap();
        let req2 = make_request("test");
        let t2 = resolve_upstream(&req2, &user, &cache, &lb, None, crate::api::sse::ApiVersion::ChatCompletions, None, &served(&[UPSTREAM])).unwrap();

        // Should alternate
        assert_ne!(t1.model, t2.model);
    }

    #[tokio::test]
    async fn session_affinity_pins_same_target_across_turns() {
        let mut map = ModelMap::default();
        let mut a = at(test_upstream_model(Provider::OpenAi, "model-a"), UPSTREAM);
        a.priority = 0;
        let mut b = at(test_upstream_model(Provider::OpenAi, "model-b"), UPSTREAM);
        b.priority = 0;
        map.mappings.insert("test".to_string(), vec![a, b]);

        let user = make_user_context(map);
        let cache = make_cache();
        let lb = make_lb_counters();

        // Same session id → same upstream on every turn (preserves prompt cache).
        let mut chosen: Option<String> = None;
        for _ in 0..10 {
            let req = make_request("test");
            let t = resolve_upstream(&req, &user, &cache, &lb, Some("sess-abc"), crate::api::sse::ApiVersion::ChatCompletions, None, &served(&[UPSTREAM]))
                .unwrap();
            match &chosen {
                None => chosen = Some(t.model),
                Some(prev) => assert_eq!(prev, &t.model),
            }
        }
    }

    #[tokio::test]
    async fn resolve_all_returns_model_not_found_for_missing_model() {
        let user = make_user_context(ModelMap::default());
        let request = make_request("nonexistent");
        let cache = make_cache();
        let lb = make_lb_counters();

        let err = resolve_all_upstreams(&request, &user, &cache, &lb, None, crate::api::sse::ApiVersion::ChatCompletions, None, &crate::config::endpoints::EndpointTable::default()).unwrap_err();
        assert_matches!(err, AppError::ModelNotFound(_));
    }

    #[tokio::test]
    async fn resolve_all_returns_targets_for_known_model() {
        let mut map = ModelMap::default();
        let a = at(test_upstream_model(Provider::OpenAi, "model-a"), UPSTREAM);
        map.mappings.insert("test".to_string(), vec![a]);

        let user = make_user_context(map);
        let request = make_request("test");
        let cache = make_cache();
        let lb = make_lb_counters();

        let targets = resolve_all_upstreams(&request, &user, &cache, &lb, None, crate::api::sse::ApiVersion::ChatCompletions, None, &served(&[UPSTREAM])).unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].model, "model-a");
        assert_eq!(targets[0].url, UPSTREAM);
    }
}
