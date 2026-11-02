//! How a request is *carried* to an upstream server.
//!
//! The transport is orthogonal to the protocol. `upstream_api_format` says which
//! wire language the gateway speaks to a server ([`ApiVersion`]); the transport
//! says how that request is addressed and authenticated. It owns exactly two
//! decisions — the URL, and the header the credential rides in — so every other
//! stage (translation, presets, guardrail, transforms, audit, session detection,
//! response cache, pricing) is reached by a cloud-hosted model on precisely the
//! same path as any other upstream.
//!
//! Invariant to preserve: a transport must never look at the request *body*. The
//! moment it does, it stops being orthogonal to the protocol and the translation
//! matrix has to grow a per-transport dimension. It may consult the *addressing*
//! facts routing has already resolved — the canonical path, the upstream model
//! name, whether the caller asked to stream — because those are what an address
//! is made of; Gemini and Vertex both put the model in the URL.
//!
//! [`ApiVersion`]: crate::api::sse::ApiVersion

use std::borrow::Cow;

use serde::{Deserialize, Serialize};

/// The Azure Foundry v1 surface lives under this prefix on the resource host.
/// Every canonical upstream path already begins `/v1/`, so the Azure transports
/// are a pure prefix and cover chat, responses and every media endpoint alike.
const AZURE_PREFIX: &str = "/openai";

/// The path suffix Microsoft's own samples use as `base_url`, which an operator
/// is therefore likely to paste into the server URL. Stripped before the prefix
/// is applied so all three documented spellings resolve to one endpoint.
const AZURE_BASE_SUFFIXES: [&str; 2] = ["/openai/v1", "/openai"];

/// Amazon Bedrock serves the OpenAI-compatible APIs under this prefix on the
/// `bedrock-runtime` host. It coincides with Azure's prefix but is an
/// independent fact about a different vendor, so the two are named separately.
const BEDROCK_PREFIX: &str = "/openai";

/// Base spellings AWS's own documentation gives for the same endpoint — the
/// Responses reference uses `.../openai/v1`, the Chat Completions reference
/// `.../v1`, and the endpoint table the bare host. All must resolve to one URL.
const BEDROCK_BASE_SUFFIXES: [&str; 3] = ["/openai/v1", "/openai", "/v1"];

/// Vertex AI mounts the OpenAI-compatible surface under this segment of a
/// project/location base, and the native Gemini surface under `publishers`.
const VERTEX_OPENAI_SEGMENT: &str = "/endpoints/openapi";

/// The publisher whose models the native Gemini surface serves. Vertex also
/// hosts other publishers, but they are addressed with `:rawPredict` and a body
/// dialect of their own — a protocol concern, not a carrier one.
const VERTEX_GEMINI_PUBLISHER: &str = "google";

/// How the gateway carries a request to one upstream server.
///
/// The serde spellings are pinned explicitly rather than derived: the same
/// strings are the DB `CHECK` values and the config-sync wire values, and
/// `rename_all = "snake_case"` would render `AzureOpenAi` as `azure_open_ai` —
/// a spelling nothing else in the system uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum UpstreamTransport {
    /// Canonical `/v1/...` paths, protocol-decided auth header. Every ordinary
    /// OpenAI-, Anthropic- and Gemini-compatible endpoint.
    #[default]
    #[serde(rename = "default")]
    Default,
    /// Azure OpenAI in Microsoft Foundry, v1 API: `{endpoint}/openai/v1/...`
    /// with the key in an `api-key` header. The deployment name travels in the
    /// body's `model` field exactly as OpenAI's does, so routing is unchanged.
    #[serde(rename = "azure_openai")]
    AzureOpenAi,
    /// The same surface authenticated with a Microsoft Entra ID access token
    /// minted from a stored client-credentials document.
    #[serde(rename = "azure_openai_entra")]
    AzureOpenAiEntra,
    /// Amazon Bedrock's OpenAI-compatible surface on the `bedrock-runtime`
    /// host: `{endpoint}/openai/v1/...`, authenticated with a Bedrock API key
    /// in the ordinary `Authorization: Bearer` header. The model id — usually a
    /// cross-Region inference profile such as `us.openai.gpt-5.6-sol` — travels
    /// in the body's `model` field, so routing is unchanged.
    #[serde(rename = "aws_bedrock")]
    AwsBedrock,
    /// Google Vertex AI, addressed from a project/location base. The native
    /// Gemini surface names the model in the path; the OpenAI-compatible
    /// surface hangs off `endpoints/openapi`. Authenticated with an OAuth
    /// access token minted from a stored service-account key.
    #[serde(rename = "google_vertex")]
    GoogleVertex,
}

impl UpstreamTransport {
    /// Parse a stored/wire transport string. An unrecognised value falls back to
    /// [`Self::Default`] with a warning: the alternative — guessing at a
    /// transport we don't implement — would address the wrong URL with the wrong
    /// credential header, and a `default` attempt fails loudly at the upstream
    /// instead of silently reaching something unintended.
    pub fn from_str_relaxed(s: &str) -> Self {
        match s.trim() {
            "" | "default" => Self::Default,
            "azure_openai" => Self::AzureOpenAi,
            "azure_openai_entra" => Self::AzureOpenAiEntra,
            "aws_bedrock" => Self::AwsBedrock,
            "google_vertex" => Self::GoogleVertex,
            other => {
                tracing::warn!(
                    transport = other,
                    "unrecognised upstream transport — falling back to `default`"
                );
                Self::Default
            }
        }
    }

    /// The stored/wire spelling.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::AzureOpenAi => "azure_openai",
            Self::AzureOpenAiEntra => "azure_openai_entra",
            Self::AwsBedrock => "aws_bedrock",
            Self::GoogleVertex => "google_vertex",
        }
    }

    /// Every transport an operator may choose, in menu order.
    pub const ALL: [Self; 5] = [
        Self::Default,
        Self::AzureOpenAi,
        Self::AzureOpenAiEntra,
        Self::AwsBedrock,
        Self::GoogleVertex,
    ];

    /// Whether this transport addresses the Azure Foundry v1 surface.
    pub fn is_azure(&self) -> bool {
        matches!(self, Self::AzureOpenAi | Self::AzureOpenAiEntra)
    }

    /// Whether this transport dictates the whole upstream URL rather than
    /// leaving it to the operator's base URL plus the canonical path.
    ///
    /// Every caller that builds a URL outside the request path — the liveness
    /// probe, model discovery, the cache-embedding probe — asks this rather than
    /// naming individual transports, so a transport added later is covered by
    /// construction instead of by remembering to update each site.
    pub fn owns_url(&self) -> bool {
        !matches!(self, Self::Default)
    }

    /// Whether this transport's endpoint publishes an OpenAI-shaped model list
    /// the gateway can discover models from.
    ///
    /// Vertex AI does not: its catalogue is a Model Garden resource addressed
    /// outside the project/location base a server is configured with. A server
    /// that cannot be discovered is also one the model-list liveness probe
    /// cannot check and one auto-sync must not run against, so this single
    /// answer gates all three rather than each site guessing.
    pub fn publishes_model_list(&self) -> bool {
        !matches!(self, Self::GoogleVertex)
    }

    /// Whether the stored credential is a JSON document the gateway mints
    /// tokens from, rather than a key sent verbatim in a header.
    pub fn credential_is_document(&self) -> bool {
        matches!(self, Self::AzureOpenAiEntra | Self::GoogleVertex)
    }

    /// Whether the gateway mints a short-lived bearer token for this transport
    /// instead of presenting the stored credential.
    pub fn mints_token(&self) -> bool {
        self.credential_is_document()
    }

    /// Whether a request in this protocol can be carried by this transport.
    ///
    /// The rule lives here because a protocol reaches a server by TWO doors: the
    /// server's own `upstream_api_format`, and the per-model override that wins
    /// over it. Both must ask, and a third door — switching an existing server
    /// onto a transport — must ask on behalf of every model already attached.
    ///
    /// The values are [`ApiVersion::as_str`] spellings.
    ///
    /// [`ApiVersion::as_str`]: crate::api::sse::ApiVersion::as_str
    pub fn allows_format(&self, upstream_api_format: &str) -> bool {
        match self {
            Self::Default => true,
            // Azure Foundry serves every model it hosts — DeepSeek and Grok
            // included — through the OpenAI v1 syntax.
            Self::AzureOpenAi | Self::AzureOpenAiEntra => {
                matches!(upstream_api_format, "chat_completions" | "responses")
            }
            // Bedrock's `bedrock-runtime` host serves Chat Completions and
            // Responses on `/openai/v1`. Its Anthropic Messages surface lives on
            // a *different* host (`bedrock-mantle`) whose paths need no rewrite
            // at all, so it is reached with the default transport rather than
            // this one; and Converse/InvokeModel are body dialects of their own,
            // which a carrier may not translate.
            Self::AwsBedrock => matches!(upstream_api_format, "chat_completions" | "responses"),
            // Vertex serves Gemini natively and an OpenAI-compatible Chat
            // Completions surface. Claude on Vertex needs `anthropic_version` in
            // the body and `model` taken out of it — a protocol concern, not a
            // carrier one — so it is not offered here.
            Self::GoogleVertex => matches!(upstream_api_format, "chat_completions" | "google_gemini"),
        }
    }

    /// Rewrite a canonical upstream path (`/v1/chat/completions`,
    /// `/v1/embeddings`, …) for this transport, for the transports whose rule is
    /// expressible as a path rewrite alone.
    pub fn upstream_path<'a>(&self, canonical: &'a str) -> Cow<'a, str> {
        match self {
            Self::Default => Cow::Borrowed(canonical),
            Self::AzureOpenAi | Self::AzureOpenAiEntra => {
                Cow::Owned(format!("{AZURE_PREFIX}{canonical}"))
            }
            Self::AwsBedrock => Cow::Owned(format!("{BEDROCK_PREFIX}{canonical}")),
            // Vertex's base already carries the API version, so the canonical
            // `/v1` is replaced rather than prefixed.
            Self::GoogleVertex => match canonical.strip_prefix("/v1/") {
                Some(rest) => Cow::Owned(format!("{VERTEX_OPENAI_SEGMENT}/{rest}")),
                None => Cow::Owned(format!("{VERTEX_OPENAI_SEGMENT}{canonical}")),
            },
        }
    }

    /// Build the full upstream URL for a canonical path.
    ///
    /// The `default` transport concatenates verbatim — that is long-standing
    /// behaviour operators have configured around, and trimming it now would
    /// change where existing servers are called. Every other transport
    /// normalises the base first, because each vendor documents its own endpoint
    /// under more than one spelling and all of them must land on one URL rather
    /// than on a doubled prefix that 404s with nothing to point at.
    pub fn upstream_url(&self, base: &str, canonical_path: &str) -> String {
        match self {
            Self::Default => format!("{base}{canonical_path}"),
            Self::AzureOpenAi | Self::AzureOpenAiEntra => {
                let base = trim_base(base, &AZURE_BASE_SUFFIXES);
                format!("{base}{AZURE_PREFIX}{canonical_path}")
            }
            Self::AwsBedrock => {
                let base = trim_base(base, &BEDROCK_BASE_SUFFIXES);
                format!("{base}{BEDROCK_PREFIX}{canonical_path}")
            }
            Self::GoogleVertex => {
                let base = base.trim_end_matches('/');
                format!("{base}{}", self.upstream_path(canonical_path))
            }
        }
    }

    /// Build the model-addressed Gemini URL.
    ///
    /// `model` must already be percent-encoded as a single path segment — in
    /// BYOK pass-through it is client-controlled, and `proxy::client` owns that
    /// encoding so there is exactly one place it can be forgotten.
    ///
    /// Gemini is the one protocol whose address names the model, which is why
    /// this is a method of its own rather than a canonical path: there is no
    /// `/v1/...` spelling to rewrite.
    pub fn gemini_url(&self, base: &str, encoded_model: &str, is_streaming: bool) -> String {
        let action = if is_streaming { "streamGenerateContent" } else { "generateContent" };
        let query = if is_streaming { "?alt=sse" } else { "" };
        match self {
            Self::GoogleVertex => {
                let base = base.trim_end_matches('/');
                format!(
                    "{base}/publishers/{VERTEX_GEMINI_PUBLISHER}/models/{encoded_model}:{action}{query}"
                )
            }
            // The Gemini Developer API's own shape. The Azure and Bedrock
            // transports refuse this protocol where it is set, so they never
            // reach here; concatenating verbatim keeps the default path's
            // long-standing behaviour byte-identical.
            Self::Default | Self::AzureOpenAi | Self::AzureOpenAiEntra | Self::AwsBedrock => {
                format!("{base}/v1beta/models/{encoded_model}:{action}{query}")
            }
        }
    }

    /// The header name this transport carries a raw credential in, for the
    /// transports that decide it themselves. `None` means the header is
    /// protocol-decided (see `UpstreamClient::forward`).
    ///
    /// Both Azure variants answer `api-key`: it is the credential header the
    /// Foundry v1 reference documents, and it is also the right destination for
    /// a BYOK client's own Azure key. Bedrock answers `None` — its API key is an
    /// ordinary bearer token on an OpenAI-shaped surface, which is exactly what
    /// the protocol default already sends. A minted *token* is a bearer
    /// credential and is applied separately, since minting is fallible and async.
    pub fn raw_credential_header(&self) -> Option<&'static str> {
        match self {
            Self::Default | Self::AwsBedrock => None,
            Self::AzureOpenAi | Self::AzureOpenAiEntra => Some("api-key"),
            // Vertex accepts only OAuth bearer tokens. Naming the header keeps
            // the credential on the transport's own branch rather than the
            // protocol-decided one, which would otherwise send the whole
            // service-account document in an `x-goog-api-key` header.
            Self::GoogleVertex => Some("authorization"),
        }
    }
}

/// Strip a trailing slash and any one of `suffixes` an operator pasted in.
fn trim_base<'a>(base: &'a str, suffixes: &[&str]) -> &'a str {
    let mut base = base.trim_end_matches('/');
    for suffix in suffixes {
        if let Some(stripped) = base.strip_suffix(suffix) {
            base = stripped.trim_end_matches('/');
            break;
        }
    }
    base
}

/// Decoding from the DB's `TEXT` column. Infallible by design — an unrecognised
/// value degrades to `default` with a warning rather than failing a config build
/// and stalling the whole tenant's sync (`From` also gives us the `TryFrom`
/// sqlx's `try_from` attribute needs).
impl From<String> for UpstreamTransport {
    fn from(s: String) -> Self {
        Self::from_str_relaxed(&s)
    }
}

impl std::fmt::Display for UpstreamTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_transport_leaves_every_canonical_path_alone() {
        let t = UpstreamTransport::Default;
        for path in [
            "/v1/chat/completions",
            "/v1/responses",
            "/v1/messages",
            "/v1/embeddings",
            "/v1/audio/speech",
            "/v1/images/generations",
        ] {
            assert_eq!(t.upstream_path(path), path);
            assert_eq!(t.upstream_url("https://api.openai.com", path), format!("https://api.openai.com{path}"));
        }
    }

    #[test]
    fn azure_prefixes_every_canonical_path_including_media() {
        for t in [UpstreamTransport::AzureOpenAi, UpstreamTransport::AzureOpenAiEntra] {
            assert_eq!(t.upstream_path("/v1/chat/completions"), "/openai/v1/chat/completions");
            assert_eq!(t.upstream_path("/v1/responses"), "/openai/v1/responses");
            assert_eq!(t.upstream_path("/v1/embeddings"), "/openai/v1/embeddings");
            assert_eq!(t.upstream_path("/v1/audio/transcriptions"), "/openai/v1/audio/transcriptions");
            assert_eq!(t.upstream_path("/v1/images/generations"), "/openai/v1/images/generations");
            assert_eq!(t.upstream_path("/v1/models"), "/openai/v1/models");
        }
    }

    /// Microsoft documents the endpoint both as the bare resource host and as
    /// `.../openai/v1/` (the `base_url` their OpenAI-client samples use), so an
    /// operator can legitimately paste either. All spellings must land on one
    /// URL — a doubled prefix would 404 with nothing to point at.
    #[test]
    fn azure_normalises_every_documented_base_spelling() {
        let t = UpstreamTransport::AzureOpenAi;
        let expected = "https://res.openai.azure.com/openai/v1/chat/completions";
        for base in [
            "https://res.openai.azure.com",
            "https://res.openai.azure.com/",
            "https://res.openai.azure.com/openai",
            "https://res.openai.azure.com/openai/",
            "https://res.openai.azure.com/openai/v1",
            "https://res.openai.azure.com/openai/v1/",
        ] {
            assert_eq!(t.upstream_url(base, "/v1/chat/completions"), expected, "base: {base}");
        }
        // A Foundry-flavoured host is the same shape.
        assert_eq!(
            t.upstream_url("https://res.services.ai.azure.com/openai/v1/", "/v1/responses"),
            "https://res.services.ai.azure.com/openai/v1/responses"
        );
    }

    /// A host that merely *contains* the suffix text elsewhere must not be
    /// trimmed — only a genuine trailing path segment is stripped.
    #[test]
    fn base_normalisation_only_strips_a_trailing_segment() {
        let t = UpstreamTransport::AzureOpenAi;
        assert_eq!(
            t.upstream_url("https://openai.internal.example/gw", "/v1/chat/completions"),
            "https://openai.internal.example/gw/openai/v1/chat/completions"
        );
    }

    #[test]
    fn bedrock_prefixes_every_canonical_path() {
        let t = UpstreamTransport::AwsBedrock;
        assert_eq!(t.upstream_path("/v1/chat/completions"), "/openai/v1/chat/completions");
        assert_eq!(t.upstream_path("/v1/responses"), "/openai/v1/responses");
        assert_eq!(t.upstream_path("/v1/models"), "/openai/v1/models");
        assert_eq!(
            t.upstream_url("https://bedrock-runtime.us-east-1.amazonaws.com", "/v1/chat/completions"),
            "https://bedrock-runtime.us-east-1.amazonaws.com/openai/v1/chat/completions"
        );
    }

    /// AWS documents the same endpoint three ways — the Responses reference as
    /// `.../openai/v1`, the Chat Completions reference as `.../v1`, and the
    /// endpoint table as the bare host. An operator may paste any of them.
    #[test]
    fn bedrock_normalises_every_documented_base_spelling() {
        let t = UpstreamTransport::AwsBedrock;
        let expected = "https://bedrock-runtime.us-east-1.amazonaws.com/openai/v1/chat/completions";
        for base in [
            "https://bedrock-runtime.us-east-1.amazonaws.com",
            "https://bedrock-runtime.us-east-1.amazonaws.com/",
            "https://bedrock-runtime.us-east-1.amazonaws.com/v1",
            "https://bedrock-runtime.us-east-1.amazonaws.com/v1/",
            "https://bedrock-runtime.us-east-1.amazonaws.com/openai",
            "https://bedrock-runtime.us-east-1.amazonaws.com/openai/",
            "https://bedrock-runtime.us-east-1.amazonaws.com/openai/v1",
            "https://bedrock-runtime.us-east-1.amazonaws.com/openai/v1/",
        ] {
            assert_eq!(t.upstream_url(base, "/v1/chat/completions"), expected, "base: {base}");
        }
    }

    /// Vertex's base already names the API version, the project and the
    /// location, so the canonical `/v1` is replaced by the openapi mount rather
    /// than prefixed — `/v1/v1/chat/completions` would 404.
    #[test]
    fn vertex_mounts_openai_paths_under_the_openapi_endpoint() {
        let t = UpstreamTransport::GoogleVertex;
        let base = "https://us-central1-aiplatform.googleapis.com/v1/projects/p/locations/us-central1";
        assert_eq!(
            t.upstream_url(base, "/v1/chat/completions"),
            format!("{base}/endpoints/openapi/chat/completions")
        );
        assert_eq!(
            t.upstream_url(&format!("{base}/"), "/v1/chat/completions"),
            format!("{base}/endpoints/openapi/chat/completions")
        );
        assert_eq!(
            t.upstream_url(base, "/v1/embeddings"),
            format!("{base}/endpoints/openapi/embeddings")
        );
    }

    #[test]
    fn vertex_addresses_gemini_by_publisher_and_model() {
        let t = UpstreamTransport::GoogleVertex;
        let base = "https://us-central1-aiplatform.googleapis.com/v1/projects/p/locations/us-central1";
        assert_eq!(
            t.gemini_url(base, "gemini-2.5-flash", false),
            format!("{base}/publishers/google/models/gemini-2.5-flash:generateContent")
        );
        assert_eq!(
            t.gemini_url(&format!("{base}/"), "gemini-2.5-flash", true),
            format!("{base}/publishers/google/models/gemini-2.5-flash:streamGenerateContent?alt=sse")
        );
    }

    /// The Gemini Developer API's own URL must not move when a Vertex arm is
    /// added beside it — this is the shape every existing Gemini server uses.
    #[test]
    fn default_gemini_url_is_the_developer_api_shape() {
        let t = UpstreamTransport::Default;
        assert_eq!(
            t.gemini_url("https://x.test", "gemini-2.5-flash", false),
            "https://x.test/v1beta/models/gemini-2.5-flash:generateContent"
        );
        assert_eq!(
            t.gemini_url("https://x.test", "gemini-2.5-flash", true),
            "https://x.test/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse"
        );
    }

    #[test]
    fn wire_spellings_round_trip() {
        for t in UpstreamTransport::ALL {
            assert_eq!(UpstreamTransport::from_str_relaxed(t.as_str()), t);
            assert_eq!(
                serde_json::to_value(t).unwrap(),
                serde_json::Value::String(t.as_str().to_string())
            );
        }
    }

    #[test]
    fn unknown_and_empty_transports_fall_back_to_default() {
        assert_eq!(UpstreamTransport::from_str_relaxed(""), UpstreamTransport::Default);
        assert_eq!(UpstreamTransport::from_str_relaxed("  "), UpstreamTransport::Default);
        assert_eq!(UpstreamTransport::from_str_relaxed("nonsense"), UpstreamTransport::Default);
    }

    #[test]
    fn each_transport_names_its_own_credential_carrier() {
        assert_eq!(UpstreamTransport::Default.raw_credential_header(), None);
        assert_eq!(UpstreamTransport::AzureOpenAi.raw_credential_header(), Some("api-key"));
        assert_eq!(UpstreamTransport::AzureOpenAiEntra.raw_credential_header(), Some("api-key"));
        // A Bedrock API key is an ordinary bearer token on an OpenAI-shaped
        // surface, which is precisely what the protocol default already sends.
        assert_eq!(UpstreamTransport::AwsBedrock.raw_credential_header(), None);
        assert_eq!(UpstreamTransport::GoogleVertex.raw_credential_header(), Some("authorization"));

        assert!(!UpstreamTransport::Default.owns_url());
        for t in UpstreamTransport::ALL.into_iter().filter(|t| *t != UpstreamTransport::Default) {
            assert!(t.owns_url(), "{t} must own its URL");
        }

        for t in UpstreamTransport::ALL {
            assert_eq!(
                t.publishes_model_list(),
                t != UpstreamTransport::GoogleVertex,
                "{t}"
            );
            assert_eq!(
                t.credential_is_document(),
                matches!(t, UpstreamTransport::AzureOpenAiEntra | UpstreamTransport::GoogleVertex),
                "{t}"
            );
            assert_eq!(t.mints_token(), t.credential_is_document(), "{t}");
        }
    }

    /// The protocol each transport can carry, stated as the whole matrix so a
    /// widened rule has to be written down rather than fall out of a `_` arm.
    #[test]
    fn protocol_matrix_is_exhaustive() {
        const PROTOCOLS: [&str; 4] =
            ["chat_completions", "responses", "anthropic_messages", "google_gemini"];
        let allowed = |t: UpstreamTransport| {
            PROTOCOLS.into_iter().filter(|p| t.allows_format(p)).collect::<Vec<_>>()
        };
        assert_eq!(allowed(UpstreamTransport::Default), PROTOCOLS);
        assert_eq!(
            allowed(UpstreamTransport::AzureOpenAi),
            ["chat_completions", "responses"]
        );
        assert_eq!(
            allowed(UpstreamTransport::AzureOpenAiEntra),
            ["chat_completions", "responses"]
        );
        assert_eq!(allowed(UpstreamTransport::AwsBedrock), ["chat_completions", "responses"]);
        assert_eq!(
            allowed(UpstreamTransport::GoogleVertex),
            ["chat_completions", "google_gemini"]
        );
        // An unknown protocol is never carried by a transport that names its set.
        for t in UpstreamTransport::ALL.into_iter().filter(|t| *t != UpstreamTransport::Default) {
            assert!(!t.allows_format("converse"), "{t}");
        }
    }
}
