//! Unified seed loader — reads all seed data from disk at runtime.
//!
//! Directory layout:
//! ```text
//! seeds/
//! ├── apps/        *.json  — one file per app
//! ├── destination_lists/ *.json — one file per destination list
//! ├── experts/     *.txt   — YAML frontmatter + prompt
//! ├── scripts/     *.rhai  — // key = "value" header metadata
//! ├── models/      models.json   (model catalog seed data)
//! ├── snippets/    *.md    — YAML frontmatter + content
//! └── tool-policy/ rules.json
//! ```
//!
//! All seed data is loaded at runtime (not `include_str!()`).
//! Missing directories/files are silently skipped — the system degrades gracefully.

use std::path::{Path, PathBuf};

use crate::routes::analytics::AppInfo;
use streamscope_client_templates::ClientProfile;
use streamscope_core::pricing::Rates;

/// A seeded destination list, loaded from `seeds/destination_lists/*.json`.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationListSeed {
    /// The seed's stable handle (`destination_lists.seed_key`).
    pub key: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Canonical entries once loaded.
    pub entries: Vec<String>,
    /// How "Use the developer defaults" attaches the list to the sandbox;
    /// absent = not part of the developer defaults. Metadata of the seed, not
    /// of the list.
    #[serde(default)]
    pub sandbox_default: Option<crate::routes::destination_lists::DestinationMode>,
}

/// A script definition loaded from a `.rhai` file.
#[derive(Debug, Clone)]
pub struct ScriptDef {
    pub name: String,
    pub description: String,
    pub source: String,
    pub phase: String,
    pub scope: String,
    pub priority: i32,
    pub enabled: bool,
    pub model_filter: Option<String>,
    pub app_filter: Option<String>,
    pub trigger_regex: Option<String>,
    pub match_mode: Option<String>,
}

/// An expert definition loaded from a `.txt` file with YAML frontmatter.
#[derive(Debug, Clone)]
pub struct ExpertSeed {
    pub axis: String,
    pub description: String,
    pub raw_prompt: String,
    pub input_types: Vec<String>,
    pub output_types: Vec<String>,
    /// Whether this expert pools into merged analysis calls (frontmatter
    /// `merge:`, default true). Applied on INSERT only — the DB flag is admin
    /// state that seed-sync never overwrites.
    pub merge_enabled: bool,
}

/// A catalog entry loaded from `models.json`.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct CatalogEntry {
    pub provider: String,
    pub model: String,
    /// Published prices for this model, each at its unit's natural scale (per 1M
    /// for token units, per unit otherwise).
    ///
    /// A unit absent from the map is a price the feed does not publish, which
    /// resolves as *unknown*: it bills at a floor of zero and badges the request.
    /// A rate of `0.0` is genuinely free. Collapsing the two would report an
    /// unpriced request as costing nothing, and — because budget accrual skips a
    /// zero cost — turn an enforcing budget into a no-op cap. An entry with no
    /// `rates` key at all supplies capabilities only.
    #[serde(default = "Rates::unknown")]
    pub rates: Rates,
    #[serde(default)]
    pub context_window: Option<i32>,
    #[serde(default)]
    pub max_output_tokens: Option<i32>,
    #[serde(default)]
    pub supports_caching: Option<bool>,
    #[serde(default)]
    pub supports_reasoning: Option<bool>,
    #[serde(default)]
    pub supports_vision: Option<bool>,
    #[serde(default)]
    pub supports_function_calling: Option<bool>,
    #[serde(default)]
    pub supports_audio_input: Option<bool>,
    #[serde(default)]
    pub supports_audio_output: Option<bool>,
    #[serde(default)]
    pub supports_video_input: Option<bool>,
    #[serde(default)]
    pub supports_pdf_input: Option<bool>,
    #[serde(default)]
    pub supports_response_schema: Option<bool>,
    #[serde(default)]
    pub supports_system_messages: Option<bool>,
    #[serde(default)]
    pub deprecation_date: Option<String>,
    #[serde(default)]
    pub model_type: Option<String>,
    #[serde(default)]
    pub output_vector_size: Option<i32>,
}

/// One tool advertised by a catalog MCP server (probed via tools/list at import).
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct McpCatalogTool {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
}

/// An MCP catalog entry loaded from `mcp_servers/catalog.json`.
///
/// The shape mirrors the offline import script's output. `source_name` is the
/// stable per-tenant seed key.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct McpCatalogSeed {
    #[serde(default)]
    pub source: Option<String>,
    pub source_name: String,
    pub name: String,
    #[serde(default)]
    pub display_title: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub featured: bool,
    #[serde(default)]
    pub website_url: Option<String>,
    #[serde(default)]
    pub repository_url: Option<String>,
    #[serde(default)]
    pub icon_url: Option<String>,
    pub upstream_url: String,
    #[serde(default = "default_transport")]
    pub transport: String,
    #[serde(default = "default_auth_mode")]
    pub auth_mode: String,
    #[serde(default)]
    pub oauth_issuer_url: Option<String>,
    #[serde(default)]
    pub oauth_authorization_url: Option<String>,
    #[serde(default)]
    pub oauth_token_url: Option<String>,
    #[serde(default)]
    pub oauth_revocation_url: Option<String>,
    #[serde(default)]
    pub oauth_default_scopes: Vec<String>,
    #[serde(default)]
    pub tools: Vec<McpCatalogTool>,
    #[serde(default)]
    pub tool_count: Option<i32>,
    #[serde(default)]
    pub liveness: Option<String>,
}

fn default_transport() -> String {
    "streamable_http".to_string()
}

fn default_auth_mode() -> String {
    "no_auth".to_string()
}

/// A QoS class loaded from `seeds/qos_classes/classes.json`.
///
/// `is_default` and `mint_default_for` are read ONLY when a tenant is created:
/// they place the tenant's three stars once, and the restart reconcile never
/// writes them, because an admin may have moved one.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct QosClassSeed {
    pub key: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub rank: i32,
    #[serde(default)]
    pub sheddable: bool,
    #[serde(default)]
    pub queue_ttl_ms: Option<i32>,
    #[serde(default)]
    pub is_default: bool,
    #[serde(default)]
    pub mint_default_for: Option<String>,
}

/// A prompt snippet loaded from a `.md` file with YAML frontmatter.
#[derive(Debug, Clone)]
pub struct SnippetEntry {
    pub key: String,
    pub label: String,
    pub content: String,
}

/// Loads seed data from disk.
/// A provider definition loaded from `seeds/providers/providers.json` — the
/// single canonical source of provider identity: display label, brand icon,
/// default upstream URL + native protocol, and built-in BYOK pass-through config.
///
/// This file is the root: the frontend catalog
/// (`admin-ui/src/lib/generated/providers.ts`) is generated from it, and the
/// `Provider` enum stays a pure protocol/translation discriminant carrying no
/// URL/format data. Added OpenAI-compatible SaaS legitimately map to
/// `Provider::Custom` and route by their explicit `default_api_format` (the proxy
/// dispatches on the format string, not the brand).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ProviderSeed {
    /// Provider key. For the concrete `Provider` variants this is the
    /// ecosystem string (`openai`, `google_gemini`, `azure_openai`, …, matching
    /// the DB/frontend convention — NOT the enum's serde Display); an added
    /// OpenAI-compatible SaaS uses its own name (mapped to `Provider::Custom`).
    pub provider: String,
    pub label: String,
    /// 24x24 fill SVG path, rendered by the frontend `<ProviderIcon>`.
    pub icon: String,
    /// Official upstream base URL, or `None` for self-hosted providers requiring
    /// an explicit URL. The proxy appends the canonical protocol path
    /// (`/v1/chat/completions`, …), so this base must yield the real endpoint.
    #[serde(default)]
    pub default_url: Option<String>,
    /// Native protocol a freshly-added manual upstream defaults to.
    pub default_api_format: String,
    /// Override for the appended chat-completions endpoint path when this
    /// provider's OpenAI-compatible chat endpoint is not `{default_url}/v1/chat/completions`
    /// (e.g. Writer `/chat`, DeepInfra `/chat/completions` with no `/v1`). None =
    /// the canonical `/v1/chat/completions`. Seeded onto the keyless BYOK upstream.
    #[serde(default)]
    pub chat_endpoint_path: Option<String>,
    /// How a freshly-added upstream for this provider is carried — the URL shape
    /// and credential header (`upstream_servers.transport`). None = `default`, a
    /// plain bearer-auth endpoint on canonical `/v1/...` paths. Set for providers
    /// whose endpoint is not shaped that way (Azure OpenAI, AWS Bedrock, Google
    /// Vertex). Such a provider's endpoint belongs to the deployment, so it carries
    /// no `default_url` and cannot be `byok_builtin`.
    #[serde(default)]
    pub default_transport: Option<String>,
    /// Seed a keyless built-in BYOK pass-through downstream for this provider and
    /// auto-grant it to the Inline AI workspace.
    #[serde(default)]
    pub byok_builtin: bool,
    /// BYOK downstream display name. **Immutable once shipped** — it is the
    /// `(tenant_id, name)` upsert key, so changing it on a deployed DB does not
    /// rename anything: the seed sync inserts a *second* downstream under the new
    /// name beside the old one. A rename is therefore a reset-db change (or needs
    /// a data migration over `is_builtin AND byok` rows). Present iff `byok_builtin`.
    #[serde(default)]
    pub byok_display_name: Option<String>,
    /// BYOK pass-through protocol; defaults to `default_api_format` when unset
    /// (only OpenAI differs — `responses` for Codex vs `chat_completions`).
    #[serde(default)]
    pub byok_api_format: Option<String>,
    /// Icon-registry-only entry (e.g. `google`, `meta`) — surfaced to the icon
    /// picker but excluded from the provider dropdown / provider-defaults / BYOK.
    #[serde(default)]
    pub icon_only: bool,
}

impl ProviderSeed {
    /// The BYOK pass-through protocol, falling back to `default_api_format`.
    pub fn effective_byok_api_format(&self) -> &str {
        self.byok_api_format.as_deref().unwrap_or(&self.default_api_format)
    }
}

pub struct SeedLoader {
    base_dir: PathBuf,
}

impl SeedLoader {
    /// Create a new SeedLoader. Uses centralized settings for seed directory.
    pub fn new() -> Self {
        let base_dir = PathBuf::from(crate::settings::admin_settings().seeds_dir.clone());
        Self { base_dir }
    }

    /// A fingerprint of **everything the startup seed reconcile's writes depend
    /// on**: the seed tree and the build applying it. The reconcile reads no
    /// operator setting; one it starts reading must be hashed here too, or a
    /// change to it with no release and no seed edit is silently skipped.
    ///
    /// Both are load-bearing. The seed bytes are the content being merged.
    /// The **build version** covers the sync code itself — a release that adds a
    /// backfill must re-run against byte-identical seeds.
    ///
    /// Each component is length-prefixed, so two different input sets cannot
    /// produce the same byte stream by concatenation (`{a:"xy",b:"z"}` must not
    /// collide with `{a:"x",b:"yz"}`).
    ///
    /// `None` when the tree cannot be read. The caller must then reconcile
    /// unconditionally: an unreadable stamp may never be taken as "unchanged".
    pub fn content_stamp(&self) -> Option<String> {
        use sha2::{Digest, Sha256};

        let mut files = Vec::new();
        collect_files_recursive(&self.base_dir, &mut files).ok()?;
        files.sort();

        let mut hasher = Sha256::new();
        let feed = |bytes: &[u8], h: &mut Sha256| {
            h.update((bytes.len() as u64).to_le_bytes());
            h.update(bytes);
        };
        feed(streamscope_core::VERSION.as_bytes(), &mut hasher);
        for path in &files {
            let rel = path.strip_prefix(&self.base_dir).unwrap_or(path);
            feed(rel.to_string_lossy().as_bytes(), &mut hasher);
            feed(&std::fs::read(path).ok()?, &mut hasher);
        }
        Some(hex::encode(hasher.finalize()))
    }

    /// Load all app definitions from `seeds/apps/*.json`.
    pub fn load_apps(&self) -> Vec<AppInfo> {
        let dir = self.base_dir.join("apps");
        let mut apps = Vec::new();
        for path in read_dir_sorted(&dir, "json") {
            match std::fs::read_to_string(&path) {
                Ok(content) => match serde_json::from_str::<AppInfo>(&content) {
                    Ok(mut app) => {
                        app.builtin = true; // seed files are always builtin
                        apps.push(app);
                    }
                    Err(e) => tracing::warn!(path = %path.display(), error = %e, "invalid app seed"),
                },
                Err(e) => tracing::warn!(path = %path.display(), error = %e, "failed to read app seed"),
            }
        }
        tracing::info!(count = apps.len(), "loaded app seeds");
        apps
    }

    /// Load the canonical provider catalog from `seeds/providers/providers.json`.
    /// Gracefully returns an empty vec if the file is missing/malformed (logged).
    pub fn load_providers(&self) -> Vec<ProviderSeed> {
        let path = self.base_dir.join("providers/providers.json");
        match std::fs::read_to_string(&path) {
            Ok(content) => match serde_json::from_str::<Vec<ProviderSeed>>(&content) {
                Ok(entries) => {
                    tracing::info!(count = entries.len(), "loaded provider seeds");
                    entries
                }
                Err(e) => {
                    tracing::warn!(error = %e, "invalid provider seed");
                    Vec::new()
                }
            },
            Err(e) => {
                tracing::warn!(error = %e, "failed to read provider seed");
                Vec::new()
            }
        }
    }

    /// Load all expert definitions from `seeds/experts/*.txt`.
    /// Files prefixed with `_` are reference files and are skipped.
    pub fn load_experts(&self) -> Vec<ExpertSeed> {
        let dir = self.base_dir.join("experts");
        let mut experts = Vec::new();
        for path in read_dir_sorted(&dir, "txt") {
            // Skip reference files (prefixed with _)
            if path.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with('_')) {
                continue;
            }
            match std::fs::read_to_string(&path) {
                Ok(content) => match parse_expert_frontmatter(&content) {
                    Some(expert) => experts.push(expert),
                    None => tracing::warn!(path = %path.display(), "invalid expert seed (missing frontmatter)"),
                },
                Err(e) => tracing::warn!(path = %path.display(), error = %e, "failed to read expert seed"),
            }
        }
        tracing::info!(count = experts.len(), "loaded expert seeds");
        experts
    }

    /// Load all Rhai scripts from `seeds/scripts/*.rhai`.
    pub fn load_scripts(&self) -> Vec<ScriptDef> {
        let dir = self.base_dir.join("scripts");
        let mut scripts = Vec::new();
        for path in read_dir_sorted(&dir, "rhai") {
            match std::fs::read_to_string(&path) {
                Ok(content) => match parse_script(&content) {
                    Some(script) => scripts.push(script),
                    None => tracing::warn!(path = %path.display(), "invalid script seed (missing name)"),
                },
                Err(e) => tracing::warn!(path = %path.display(), error = %e, "failed to read script seed"),
            }
        }
        tracing::info!(count = scripts.len(), "loaded script seeds");
        scripts
    }

    /// Load catalog entries from `seeds/models/models.json`.
    pub fn load_catalog(&self) -> Vec<CatalogEntry> {
        let path = self.base_dir.join("models/models.json");
        match std::fs::read_to_string(&path) {
            Ok(content) => match serde_json::from_str::<Vec<CatalogEntry>>(&content) {
                Ok(entries) => {
                    tracing::info!(count = entries.len(), "loaded catalog seeds");
                    entries
                }
                Err(e) => {
                    tracing::warn!(error = %e, "invalid catalog seed");
                    Vec::new()
                }
            },
            Err(e) => {
                tracing::warn!(error = %e, "failed to read catalog seed");
                Vec::new()
            }
        }
    }

    /// Load MCP catalog entries from `seeds/mcp_servers/catalog.json`.
    pub fn load_mcp_catalog(&self) -> Vec<McpCatalogSeed> {
        let path = self.base_dir.join("mcp_servers/catalog.json");
        match std::fs::read_to_string(&path) {
            Ok(content) => match serde_json::from_str::<Vec<McpCatalogSeed>>(&content) {
                Ok(entries) => {
                    tracing::info!(count = entries.len(), "loaded MCP catalog seeds");
                    entries
                }
                Err(e) => {
                    tracing::warn!(error = %e, "invalid MCP catalog seed");
                    Vec::new()
                }
            },
            Err(e) => {
                tracing::warn!(error = %e, "failed to read MCP catalog seed");
                Vec::new()
            }
        }
    }

    /// Load prompt snippets from `seeds/snippets/*.md`.
    pub fn load_snippets(&self) -> Vec<SnippetEntry> {
        let dir = self.base_dir.join("snippets");
        let mut snippets = Vec::new();
        for path in read_dir_sorted(&dir, "md") {
            match std::fs::read_to_string(&path) {
                Ok(content) => match parse_snippet_frontmatter(&content) {
                    Some(snippet) => snippets.push(snippet),
                    None => tracing::warn!(path = %path.display(), "invalid snippet seed (missing frontmatter)"),
                },
                Err(e) => tracing::warn!(path = %path.display(), error = %e, "failed to read snippet seed"),
            }
        }
        tracing::info!(count = snippets.len(), "loaded snippet seeds");
        snippets
    }

    /// Load the QoS classes from `seeds/qos_classes/classes.json`.
    pub fn load_qos_classes(&self) -> Vec<QosClassSeed> {
        let path = self.base_dir.join("qos_classes/classes.json");
        match std::fs::read_to_string(&path) {
            Ok(content) => match serde_json::from_str::<Vec<QosClassSeed>>(&content) {
                Ok(classes) => {
                    tracing::info!(count = classes.len(), "loaded QoS class seeds");
                    classes
                }
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "invalid QoS class seed");
                    Vec::new()
                }
            },
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "failed to read QoS class seed");
                Vec::new()
            }
        }
    }

    /// Load all client-config profiles from `seeds/client_profiles/*.json`.
    /// Builtin flag is forced to `true` on every loaded profile — admins can
    /// flip it to `false` per-tenant by overriding via the admin API.
    pub fn load_client_profiles(&self) -> Vec<ClientProfile> {
        let dir = self.base_dir.join("client_profiles");
        let mut profiles = Vec::new();
        for path in read_dir_sorted(&dir, "json") {
            match std::fs::read_to_string(&path) {
                Ok(content) => match serde_json::from_str::<ClientProfile>(&content) {
                    Ok(mut profile) => {
                        profile.builtin = true;
                        profiles.push(profile);
                    }
                    Err(e) => tracing::warn!(path = %path.display(), error = %e, "invalid client profile seed"),
                },
                Err(e) => tracing::warn!(path = %path.display(), error = %e, "failed to read client profile seed"),
            }
        }
        tracing::info!(count = profiles.len(), "loaded client profile seeds");
        profiles
    }

    /// Load the seeded destination lists from `seeds/destination_lists/*.json`,
    /// each entry canonicalised. A file that does not parse, or names an entry
    /// the destination syntax refuses, is skipped with a warning.
    pub fn load_destination_lists(&self) -> Vec<DestinationListSeed> {
        self.load_destination_lists_checked().0
    }

    /// [`Self::load_destination_lists`], and whether every seed file loaded —
    /// a prune of the lists the seed no longer ships may only read a complete
    /// load, or one broken file would delete its list in every tenant.
    pub fn load_destination_lists_checked(&self) -> (Vec<DestinationListSeed>, bool) {
        let dir = self.base_dir.join("destination_lists");
        let mut lists = Vec::new();
        let mut complete = true;
        for path in read_dir_sorted(&dir, "json") {
            let parsed = std::fs::read_to_string(&path)
                .map_err(|e| e.to_string())
                .and_then(|c| serde_json::from_str::<DestinationListSeed>(&c).map_err(|e| e.to_string()))
                .and_then(|mut seed| {
                    let set = streamscope_client_templates::destination::DestinationSet::parse(&seed.entries)
                        .map_err(|e| e.to_string())?;
                    seed.entries = set.canonical();
                    Ok(seed)
                });
            match parsed {
                Ok(seed) => lists.push(seed),
                Err(e) => {
                    complete = false;
                    tracing::warn!(path = %path.display(), error = %e, "invalid destination list seed");
                }
            }
        }
        tracing::info!(count = lists.len(), "loaded destination list seeds");
        (lists, complete)
    }

    /// Load tool risk rules from `seeds/tool-policy/rules.json`.
    pub fn load_tool_rules(&self) -> Vec<serde_json::Value> {
        let path = self.base_dir.join("tool-policy/rules.json");
        match std::fs::read_to_string(&path) {
            Ok(content) => match serde_json::from_str::<Vec<serde_json::Value>>(&content) {
                Ok(rules) => {
                    tracing::info!(count = rules.len(), "loaded tool risk seeds");
                    rules
                }
                Err(e) => {
                    tracing::warn!(error = %e, "invalid tool risk seed");
                    Vec::new()
                }
            },
            Err(e) => {
                tracing::warn!(error = %e, "failed to read tool risk seed");
                Vec::new()
            }
        }
    }

    /// Load tool field profiles from the curated + machine-imported seed
    /// files (sorted alphabetically so load order is deterministic). Returns
    /// the merged array as raw `serde_json::Value` entries — the proxy-side
    /// `config_sync` deserialises each into a typed `FieldProfile` and skips
    /// malformed entries individually.
    pub fn load_tool_field_profiles(&self) -> Vec<serde_json::Value> {
        let dir = self.base_dir.join("tool-policy");
        let candidates = [
            "tool_field_profiles.json",
            "tool_field_profiles_mcp.json",
        ];
        let mut merged: Vec<serde_json::Value> = Vec::new();
        for name in candidates {
            let path = dir.join(name);
            if !path.exists() {
                continue;
            }
            match std::fs::read_to_string(&path) {
                Ok(content) => match serde_json::from_str::<Vec<serde_json::Value>>(&content) {
                    Ok(entries) => {
                        tracing::info!(
                            file = name,
                            count = entries.len(),
                            "loaded tool field profile seeds"
                        );
                        merged.extend(entries);
                    }
                    Err(e) => tracing::warn!(file = name, error = %e, "invalid tool field profile seed"),
                },
                Err(e) => tracing::warn!(file = name, error = %e, "failed to read tool field profile seed"),
            }
        }
        merged
    }
}

/// The set of stable rule ids in the builtin seed file. Cached once at
/// process start — the seed is source-shipped and static. Used by the
/// `/tool-rules` handlers to compute `is_builtin` per rule at response
/// time, and by `actions/reset` / seed-sync to know what "restore builtins"
/// means.
pub fn builtin_tool_rule_ids() -> &'static std::collections::HashSet<String> {
    static CACHE: std::sync::OnceLock<std::collections::HashSet<String>> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| {
        let loader = SeedLoader::new();
        loader
            .load_tool_rules()
            .iter()
            .filter_map(|r| r.get("id").and_then(|v| v.as_str()).map(String::from))
            .collect()
    })
}

/// The canonical provider catalog, loaded once from
/// `seeds/providers/providers.json`. The single source of provider identity/URL/
/// format data — the `Provider` enum is a discriminant only.
pub fn provider_catalog() -> &'static [ProviderSeed] {
    static CACHE: std::sync::OnceLock<Vec<ProviderSeed>> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| SeedLoader::new().load_providers())
}

/// Resolve the provider seed row for a (possibly aliased) provider string.
/// Matches by **variant equality** through `Provider::from_str_relaxed` (so
/// `"gemini"`/`"azure"`/`"open_ai"` resolve to the concrete variant's row —
/// never via the enum's serde Display, which differs from the ecosystem keys);
/// an added OpenAI-compatible SaaS maps to `Custom` and is matched by exact key.
/// `icon_only` rows are never returned.
pub fn provider_seed_for(provider: &str) -> Option<&'static ProviderSeed> {
    use streamscope_core::config::model_map::Provider;
    let want = Provider::from_str_relaxed(provider);
    if matches!(want, Provider::Custom) {
        let key = provider.to_ascii_lowercase();
        provider_catalog().iter().find(|p| !p.icon_only && p.provider == key)
    } else {
        provider_catalog()
            .iter()
            .find(|p| !p.icon_only && Provider::from_str_relaxed(&p.provider) == want)
    }
}

/// Canonical default upstream base URL for a provider, or `None` for self-hosted
/// providers (and unknown ones). Replaces the former hardcoded `default_url()`.
pub fn provider_default_url(provider: &str) -> Option<String> {
    provider_seed_for(provider).and_then(|p| p.default_url.clone())
}

/// Native upstream API format a freshly-added upstream defaults to, or `None`
/// when the provider is unknown (caller falls back to `chat_completions`).
pub fn provider_default_api_format(provider: &str) -> Option<String> {
    provider_seed_for(provider).map(|p| p.default_api_format.clone())
}

/// Provider seed's chat-completions endpoint-path override, or `None` (the
/// canonical `/v1/chat/completions`). Populated for OpenAI-compatible providers
/// whose chat endpoint sits at a non-canonical sub-path (e.g. Writer `/chat`).
pub fn provider_chat_endpoint_path(provider: &str) -> Option<String> {
    provider_seed_for(provider).and_then(|p| p.chat_endpoint_path.clone())
}

/// Provider seed's transport, or `None` (a plain bearer-auth endpoint). Set for
/// providers whose endpoint is shaped differently, so choosing the provider
/// selects the right transport with no extra operator step.
pub fn provider_default_transport(provider: &str) -> Option<String> {
    provider_seed_for(provider).and_then(|p| p.default_transport.clone())
}

/// A single entry in `seeds/tool-policy/frameworks.json` — a reference to an
/// external security framework category (OWASP LLM Top-10, MITRE ATLAS, CWE)
/// that the framework-aware expert cites when proposing rules, and that the
/// UI uses to render context when an operator clicks a framework chip.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct SecurityFramework {
    /// Stable id, prefixed by framework family
    /// (`OWASP-LLM01`, `MITRE-ATLAS-AML-T0048`, `CWE-78`, …).
    pub id: String,
    /// Family name — `OWASP-LLM-TOP-10`, `MITRE-ATLAS`, `CWE`, `OWASP-ASI`, ….
    pub framework: String,
    pub version: String,
    pub title: String,
    pub summary: String,
    /// Short bullet-list of tool-risk patterns that typically map to this
    /// framework entry. Surfaced to the agent + the UI side-panel.
    #[serde(default)]
    pub tool_risk_hints: Vec<String>,
}

/// One entry in the canonical `tool_id` taxonomy shipped with the engine.
/// `seeds/tool-policy/tool_ids.json` is documentation + UI hint, not an
/// enforced enum — operators can introduce custom ids via the modal.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ToolIdEntry {
    pub id: String,
    pub category: String,
    pub description: String,
}

/// Load the canonical `tool_id` taxonomy from
/// `seeds/tool-policy/tool_ids.json`. Cached once at process start — the seed is
/// source-shipped and static. Gracefully returns an empty slice if the file is
/// missing or malformed (logged) so the UI degrades to a free-form input.
pub fn load_tool_ids() -> &'static [ToolIdEntry] {
    load_id_taxonomy("tool_ids.json", "tool_id")
}

/// Load the canonical `resource_id` taxonomy from
/// `seeds/tool-policy/resource_ids.json`. Same shape as [`load_tool_ids`] —
/// surfaced via `GET /api/v1/admin/resource-ids` for the rule editor's
/// autocomplete.
pub fn load_resource_ids() -> &'static [ToolIdEntry] {
    load_id_taxonomy("resource_ids.json", "resource_id")
}

/// Load the canonical `prompt_id` taxonomy from
/// `seeds/tool-policy/prompt_ids.json`. Surfaced via
/// `GET /api/v1/admin/prompt-ids`.
pub fn load_prompt_ids() -> &'static [ToolIdEntry] {
    load_id_taxonomy("prompt_ids.json", "prompt_id")
}

/// Shared loader for the three id taxonomies. Each variant has its own
/// `OnceLock` cache (the closure captures the filename) so cached values
/// don't bleed across taxonomies.
fn load_id_taxonomy(filename: &'static str, kind: &'static str) -> &'static [ToolIdEntry] {
    use std::collections::HashMap;
    use std::sync::OnceLock;
    // OnceLock<HashMap> rather than a per-name macro to keep this concise;
    // first read populates, subsequent reads share.
    static CACHES: OnceLock<std::sync::Mutex<HashMap<&'static str, &'static [ToolIdEntry]>>> =
        OnceLock::new();
    let map = CACHES.get_or_init(|| std::sync::Mutex::new(HashMap::new()));
    {
        let guard = map.lock().expect("taxonomy cache mutex poisoned");
        if let Some(entries) = guard.get(filename) {
            return entries;
        }
    }
    let loader = SeedLoader::new();
    let path = loader.base_dir.join("tool-policy").join(filename);
    let entries: Vec<ToolIdEntry> = match std::fs::read_to_string(&path) {
        Ok(content) => match serde_json::from_str::<Vec<ToolIdEntry>>(&content) {
            Ok(entries) => {
                tracing::info!(count = entries.len(), kind, "loaded id taxonomy");
                entries
            }
            Err(e) => {
                tracing::warn!(error = %e, kind, "invalid id taxonomy seed — shipping empty taxonomy");
                Vec::new()
            }
        },
        Err(e) => {
            tracing::warn!(error = %e, kind, "failed to read id taxonomy seed — shipping empty taxonomy");
            Vec::new()
        }
    };
    let leaked: &'static [ToolIdEntry] = Box::leak(entries.into_boxed_slice());
    let mut guard = map.lock().expect("taxonomy cache mutex poisoned");
    guard.entry(filename).or_insert(leaked);
    leaked
}

/// Load the security-framework knowledge pack from
/// `seeds/tool-policy/frameworks.json`. Cached once at process start — the seed
/// is source-shipped and static. Gracefully returns an empty slice if the
/// file is missing or malformed (logged) so the system degrades without
/// blocking agent runs.
pub fn load_security_frameworks() -> &'static [SecurityFramework] {
    static CACHE: std::sync::OnceLock<Vec<SecurityFramework>> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| {
        let loader = SeedLoader::new();
        let path = loader.base_dir.join("tool-policy/frameworks.json");
        match std::fs::read_to_string(&path) {
            Ok(content) => match serde_json::from_str::<Vec<SecurityFramework>>(&content) {
                Ok(entries) => {
                    tracing::info!(count = entries.len(), "loaded security framework pack");
                    entries
                }
                Err(e) => {
                    tracing::warn!(error = %e, "invalid security framework seed — shipping empty pack");
                    Vec::new()
                }
            },
            Err(e) => {
                tracing::warn!(error = %e, "failed to read security framework seed — shipping empty pack");
                Vec::new()
            }
        }
    })
}

/// How a provider-form field's value is produced when the OAuth-setup guide
/// renders. `redirect`/`homepage` are resolved client-side from tenant settings
/// (they can't be baked into a static seed); `literal`/`note` carry their text.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OauthFieldValue {
    /// The gateway's server-derived OAuth redirect/callback URI (copyable).
    Redirect,
    /// The gateway's public homepage URL (copyable).
    Homepage,
    /// A fixed suggested value, e.g. an app name (copyable).
    Literal { text: String },
    /// A non-copyable instruction, e.g. "leave unchecked".
    Note { text: String },
}

/// One row in a provider's OAuth-app registration form.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct OauthProviderField {
    /// The label the provider's console uses for this field.
    pub label: String,
    pub value: OauthFieldValue,
    /// Optional short clarifier shown under the field.
    #[serde(default)]
    pub hint: Option<String>,
}

/// A provider-specific recipe for hand-registering a per-user-OAuth MCP
/// upstream: which console to open, the fields it asks for and the value to
/// paste into each, ordered steps, and suggested scopes. Static help content
/// shipped in `seeds/mcp_servers/oauth_provider_recipes.json`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct OauthProviderRecipe {
    pub id: String,
    pub label: String,
    /// Hostname needles matched (as suffixes) against the upstream/issuer host
    /// to auto-detect the provider. Empty for the generic fallback recipe.
    #[serde(default)]
    pub host_patterns: Vec<String>,
    /// Deep link to the provider page that creates an OAuth app.
    #[serde(default)]
    pub console_url: Option<String>,
    /// Whether the provider advertises RFC 7591 dynamic client registration
    /// (i.e. whether "Register client automatically" is expected to work).
    pub supports_dcr: bool,
    pub fields: Vec<OauthProviderField>,
    pub steps: Vec<String>,
    #[serde(default)]
    pub suggested_scopes: Vec<String>,
}

/// Load the OAuth provider setup guides from
/// `seeds/mcp_servers/oauth_provider_recipes.json`. Cached once at process
/// start — the seed is source-shipped and static. Gracefully returns an empty
/// slice if the file is missing or malformed (logged) so the modal degrades to
/// its manual-entry fields without the guide.
pub fn load_oauth_provider_recipes() -> &'static [OauthProviderRecipe] {
    static CACHE: std::sync::OnceLock<Vec<OauthProviderRecipe>> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| {
        let loader = SeedLoader::new();
        let path = loader.base_dir.join("mcp_servers/oauth_provider_recipes.json");
        match std::fs::read_to_string(&path) {
            Ok(content) => match serde_json::from_str::<Vec<OauthProviderRecipe>>(&content) {
                Ok(entries) => {
                    tracing::info!(count = entries.len(), "loaded OAuth provider recipes");
                    entries
                }
                Err(e) => {
                    tracing::warn!(error = %e, "invalid OAuth provider recipe seed — shipping empty set");
                    Vec::new()
                }
            },
            Err(e) => {
                tracing::warn!(error = %e, "failed to read OAuth provider recipe seed — shipping empty set");
                Vec::new()
            }
        }
    })
}

// ---------------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------------

/// Parse `// key = "value"` metadata from a Rhai script header.
fn parse_script(raw: &str) -> Option<ScriptDef> {
    let mut name = String::new();
    let mut description = String::new();
    let mut phase = "request".to_string();
    let mut scope = "global".to_string();
    let mut priority = 100;
    let mut enabled = false;
    let mut model_filter: Option<String> = None;
    let mut app_filter: Option<String> = None;
    let mut trigger_regex: Option<String> = None;
    let mut match_mode: Option<String> = None;
    let mut source_start = 0;

    for (i, line) in raw.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("// ") {
            if let Some((key, val)) = trimmed
                .trim_start_matches("// ")
                .split_once(" = ")
            {
                let val = val.trim_matches('"');
                match key {
                    "name" => name = val.to_string(),
                    "description" => description = val.to_string(),
                    "phase" => phase = val.to_string(),
                    "scope" => scope = val.to_string(),
                    "priority" => priority = val.parse().unwrap_or(100),
                    "enabled" => enabled = val == "true",
                    "model_filter" => model_filter = Some(val.to_string()),
                    "app_filter" => app_filter = Some(val.to_string()),
                    "trigger_regex" => trigger_regex = Some(val.to_string()),
                    "match_mode" => match_mode = Some(val.to_string()),
                    _ => {}
                }
            }
            source_start = i + 1;
        } else if trimmed.is_empty() && source_start == i {
            source_start = i + 1;
        } else {
            break;
        }
    }

    if name.is_empty() {
        return None;
    }

    let source: String = raw.lines().skip(source_start).collect::<Vec<_>>().join("\n");

    Some(ScriptDef {
        name,
        description,
        source,
        phase,
        scope,
        priority,
        enabled,
        model_filter,
        app_filter,
        trigger_regex,
        match_mode,
    })
}

/// Parse YAML frontmatter from an expert `.txt` file.
///
/// Format:
/// ```text
/// ---
/// axis: security
/// description: Detects prompt injection...
/// input_types: [session, memory]
/// output_types: [transform_suggestion, alert, memory]
/// ---
///
/// <prompt content>
/// ```
fn parse_expert_frontmatter(content: &str) -> Option<ExpertSeed> {
    let (frontmatter, body) = split_frontmatter(content)?;

    let mut axis = String::new();
    let mut description = String::new();
    let mut input_types = Vec::new();
    let mut output_types = Vec::new();
    let mut merge_enabled = true;

    for line in frontmatter.lines() {
        let trimmed = line.trim();
        if let Some((key, val)) = trimmed.split_once(':') {
            let key = key.trim();
            let val = val.trim();
            match key {
                "axis" => axis = val.to_string(),
                "description" => description = val.to_string(),
                "input_types" => input_types = parse_yaml_list(val),
                "output_types" => output_types = parse_yaml_list(val),
                "merge" => merge_enabled = val != "false",
                _ => {}
            }
        }
    }

    if axis.is_empty() {
        return None;
    }

    // Validate input/output type values against the typed enums so unknown
    // entries surface at seed-load time instead of producing silent runtime
    // warnings later. We only warn (not abort) so a single malformed expert
    // doesn't stop the rest of the seed pack from loading.
    use crate::agent::experts::{ExpertInput, ExpertOutput};
    for raw in &input_types {
        if let Err(e) = raw.parse::<ExpertInput>() {
            tracing::warn!(axis = %axis, value = %raw, "invalid expert input_type in seed: {e}");
        }
    }
    for raw in &output_types {
        if let Err(e) = raw.parse::<ExpertOutput>() {
            tracing::warn!(axis = %axis, value = %raw, "invalid expert output_type in seed: {e}");
        }
    }

    Some(ExpertSeed {
        axis,
        description,
        raw_prompt: body.to_string(),
        input_types,
        output_types,
        merge_enabled,
    })
}

/// Parse YAML frontmatter from a snippet `.md` file.
fn parse_snippet_frontmatter(content: &str) -> Option<SnippetEntry> {
    let (frontmatter, body) = split_frontmatter(content)?;

    let mut key = String::new();
    let mut label = String::new();

    for line in frontmatter.lines() {
        let trimmed = line.trim();
        if let Some((k, v)) = trimmed.split_once(':') {
            let k = k.trim();
            let v = v.trim();
            match k {
                "key" => key = v.to_string(),
                "label" => label = v.to_string(),
                _ => {}
            }
        }
    }

    if key.is_empty() {
        return None;
    }

    Some(SnippetEntry {
        key,
        label,
        content: body.to_string(),
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Split content at YAML frontmatter delimiters (`---`).
/// Returns `(frontmatter_text, body_text)`.
fn split_frontmatter(content: &str) -> Option<(&str, &str)> {
    let content = content.trim_start();
    if !content.starts_with("---") {
        return None;
    }
    // Find the closing ---
    let after_first = &content[3..].trim_start_matches(['\r', '\n']);
    let closing = after_first.find("\n---")?;
    let frontmatter = &after_first[..closing];
    let body = &after_first[closing + 4..]; // skip \n---
    // Skip the rest of the closing --- line
    let body = body.trim_start_matches(|c: char| c != '\n');
    let body = body.strip_prefix('\n').unwrap_or(body);
    Some((frontmatter, body))
}

/// Parse a simple YAML inline list: `[a, b, c]` → `vec!["a", "b", "c"]`.
fn parse_yaml_list(s: &str) -> Vec<String> {
    let s = s.trim().trim_start_matches('[').trim_end_matches(']');
    s.split(',')
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty())
        .collect()
}

/// Collect every file under `dir`, recursively, into `out` (unsorted).
///
/// Errors propagate: a directory that cannot be walked must not silently
/// produce a short file list, since [`SeedLoader::content_stamp`] would then
/// hash a partial tree and could match across genuinely different seed sets.
fn collect_files_recursive(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_files_recursive(&path, out)?;
        } else {
            out.push(path);
        }
    }
    Ok(())
}

/// Read all files with the given extension from a directory, sorted by name.
fn read_dir_sorted(dir: &Path, ext: &str) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        tracing::debug!(dir = %dir.display(), "seed directory not found, skipping");
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some(ext))
        .collect();
    paths.sort();
    paths
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_yaml_list_basic() {
        assert_eq!(
            parse_yaml_list("[session, memory]"),
            vec!["session", "memory"]
        );
    }

    #[test]
    fn parse_yaml_list_empty() {
        assert!(parse_yaml_list("[]").is_empty());
    }

    #[test]
    fn split_frontmatter_basic() {
        let content = "---\nkey: value\n---\nbody text";
        let (fm, body) = split_frontmatter(content).unwrap();
        assert_eq!(fm, "key: value");
        assert_eq!(body, "body text");
    }

    #[test]
    fn split_frontmatter_no_delimiters() {
        assert!(split_frontmatter("no frontmatter here").is_none());
    }

    #[test]
    fn parse_expert_frontmatter_valid() {
        let content = "\
---
axis: security
description: Detects threats
input_types: [session, memory]
output_types: [transform_suggestion, alert, memory]
---

You are a security expert.";
        let expert = parse_expert_frontmatter(content).unwrap();
        assert_eq!(expert.axis, "security");
        assert_eq!(expert.description, "Detects threats");
        assert_eq!(expert.input_types, vec!["session", "memory"]);
        assert_eq!(expert.output_types, vec!["transform_suggestion", "alert", "memory"]);
        assert!(expert.raw_prompt.contains("You are a security expert."));
    }

    #[test]
    fn parse_snippet_frontmatter_valid() {
        let content = "\
---
key: session
label: Session Analysis
---

## Session Analysis

Content here.";
        let snippet = parse_snippet_frontmatter(content).unwrap();
        assert_eq!(snippet.key, "session");
        assert_eq!(snippet.label, "Session Analysis");
        assert!(snippet.content.contains("## Session Analysis"));
    }

    #[test]
    fn parse_script_valid() {
        let raw = r#"// name = "test_script"
// description = "A test"
// phase = "request"
// scope = "global"
// priority = 50
// enabled = true

let x = 1;
"#;
        let script = parse_script(raw).unwrap();
        assert_eq!(script.name, "test_script");
        assert_eq!(script.description, "A test");
        assert_eq!(script.phase, "request");
        assert_eq!(script.scope, "global");
        assert_eq!(script.priority, 50);
        assert!(script.enabled);
        assert!(script.source.contains("let x = 1;"));
    }

    #[test]
    fn parse_script_with_filters() {
        let raw = r#"// name = "filtered"
// description = "test"
// phase = "request"
// scope = "tools"
// model_filter = "claude-3"
// app_filter = "claude-code"
// trigger_regex = "@"
// match_mode = "span"

let y = 2;
"#;
        let script = parse_script(raw).unwrap();
        assert_eq!(script.model_filter.as_deref(), Some("claude-3"));
        assert_eq!(script.app_filter.as_deref(), Some("claude-code"));
        assert_eq!(script.trigger_regex.as_deref(), Some("@"));
        assert_eq!(script.match_mode.as_deref(), Some("span"));
    }

    #[test]
    fn parse_script_missing_name() {
        let raw = "// description = \"no name\"\nlet x = 1;";
        assert!(parse_script(raw).is_none());
    }

    // ─── Seed-consistency: merged panel prompts compose cleanly ───
    //
    // Assembles the REAL default pools' merged prompts from seeds/ and asserts
    // the composition invariants: no cross-expert deference text, no solo
    // identity openers, no duplicated boilerplate, every axis section present
    // exactly once, snippet references resolvable, and output-channel mentions
    // consistent with each axis's schema slice. Keeps future seed edits from
    // silently reintroducing leak-inducing or contradictory panel text.

    #[test]
    fn every_seeded_list_parses_and_its_entries_are_canonical() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../seeds/destination_lists");
        let files = std::fs::read_dir(dir).expect("seed dir").count();
        let seeds = repo_seed_loader().load_destination_lists();
        assert_eq!(seeds.len(), files, "a seed file failed to load");
        let mut keys = std::collections::HashSet::new();
        let mut names = std::collections::HashSet::new();
        for s in &seeds {
            assert!(keys.insert(s.key.clone()), "duplicate seed key {}", s.key);
            assert!(names.insert(s.name.clone()), "duplicate seed name {}", s.name);
            assert!(!s.entries.is_empty(), "{} has no entries", s.key);
            assert_eq!(crate::routes::destination_lists::canonical_entries(&s.entries).unwrap(), s.entries, "{}", s.key);
        }
        assert!(seeds.iter().any(|s| s.sandbox_default == Some(crate::routes::destination_lists::DestinationMode::Allow)));
        assert!(seeds.iter().any(|s| s.sandbox_default == Some(crate::routes::destination_lists::DestinationMode::Block)));
    }

    fn repo_seed_loader() -> SeedLoader {
        SeedLoader {
            base_dir: PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../seeds")),
        }
    }

    /// The opening of each client's real system prompt (its latest release),
    /// and the app the prompt tier must name from it. The negatives are prompts
    /// that reach the gateway beside them: the gateway's own analysis agent, a
    /// title-generation side request, a plain SDK caller.
    const PROMPT_OPENINGS: &[(&str, Option<&str>)] = &[
        ("You are a general-purpose AI agent called goose, created by AAIF (Agentic AI Foundation). goose is being developed as an open-source software project.", Some("goose")),
        ("You are an agent in the Continue CLI. Given the user's prompt, you should use the tools available to you to answer the user's question.", Some("continue")),
        ("You are Mistral Vibe, an interactive coding agent.", Some("vibe")),
        ("You help users get complex tasks done. Act directly and proactively. Find relevant skills with the `skill` tool, discover additional tools with `search_tool_functions`, and call them using `run_typescript`.", Some("vibe")),
        ("You are a coding agent running in the Codex CLI, a terminal-based coding assistant. Codex CLI is an open source project led by OpenAI.", Some("codex")),
        ("You are Codex, based on GPT-5. You are running as a coding agent in the Codex CLI on a user's computer.", Some("codex")),
        ("You are Crush, a powerful AI Assistant that runs in the CLI. <critical_rules> These rules override everything else.", Some("crush")),
        ("You are Gemini CLI, an autonomous CLI agent specializing in software engineering tasks. You are currently operating in **YOLO** mode.", Some("gemini-cli")),
        ("You are Qwen Code, a non-interactive CLI agent developed by Alibaba Group, specializing in software engineering tasks.", Some("qwen-code")),
        ("You are opencode, an interactive CLI tool that helps users with software engineering tasks.", Some("opencode")),
        ("You are OpenCode, a coding agent that helps users with software engineering tasks.", Some("opencode")),
        ("You are OpenCode, an interactive general AI agent running on a user's computer.", Some("opencode")),
        ("x-anthropic-billing-header: cc_version=2.1.278.027; cc_entrypoint=sdk-cli; You are a Claude agent, built on Anthropic's Claude Agent SDK.", None),
        ("You are the `tool_policy` analysis expert. Confine your entire answer to this axis; ignore concerns that belong to other analysis dimensions.", None),
        ("Generate a short title (four words or less) for this conversation. Title what the work is ABOUT, not the mechanical activity.", None),
        ("You are a title generator. You output ONLY a thread title. Nothing else.", None),
        ("You are a helpful assistant.", None),
    ];

    /// A prompt pattern is tried against every request no header named, so a
    /// useful one names its own client from that client's real prompt and
    /// NOTHING else that reaches the gateway — one generic enough to occur in a
    /// neighbour's prompt would take the neighbour's traffic. Every shipped
    /// pattern must also be exercised here: one no opening matches has no
    /// evidence behind it.
    #[test]
    fn every_seeded_prompt_pattern_names_only_its_own_client() {
        use streamscope_core::config::AppPattern;
        use streamscope_core::middleware::attribution::{
            MIN_PROMPT_PATTERN_CHARS, infer_app_from_system_prompt, normalize_patterns,
        };

        let apps = repo_seed_loader().load_apps();
        // Every seeded pattern survives the normalization the proxy applies —
        // one it would drop can never match.
        for app in &apps {
            assert_eq!(
                normalize_patterns(&app.prompt_patterns, MIN_PROMPT_PATTERN_CHARS).len(),
                app.prompt_patterns.len(),
                "{}: a seeded prompt pattern is dropped by the proxy's normalization",
                app.id
            );
        }
        let patterns: Vec<AppPattern> = apps
            .into_iter()
            .map(|a| AppPattern {
                prompt_patterns: normalize_patterns(&a.prompt_patterns, MIN_PROMPT_PATTERN_CHARS),
                app_id: a.id,
                ..Default::default()
            })
            .collect();
        assert!(patterns.iter().any(|a| !a.prompt_patterns.is_empty()), "no seeded prompt pattern");

        for (opening, expected) in PROMPT_OPENINGS {
            assert_eq!(
                infer_app_from_system_prompt(opening, &patterns).as_deref(),
                *expected,
                "prompt opening: {opening}"
            );
        }
        for app in &patterns {
            for p in &app.prompt_patterns {
                assert!(
                    PROMPT_OPENINGS.iter().any(|(opening, expected)| {
                        *expected == Some(app.app_id.as_str()) && opening.to_ascii_lowercase().contains(p.as_str())
                    }),
                    "{}: prompt pattern {p:?} matches none of its client's real prompt openings",
                    app.app_id
                );
            }
        }
    }

    // ── Seed stamp ──────────────────────────────────────────────────────────
    //
    // The stamp gates whether a tenant's startup reconcile runs at all, so a
    // stamp that fails to change is a silent, permanent skip. These lock the
    // encoding.

    /// Build a throwaway seed tree. `name` keeps concurrent tests isolated —
    /// they run in parallel in one process.
    fn stamp_fixture(name: &str, files: &[(&str, &str)]) -> SeedLoader {
        let base = std::env::temp_dir().join(format!("ss-stamp-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&base);
        for (rel, body) in files {
            let path = base.join(rel);
            std::fs::create_dir_all(path.parent().expect("has parent")).expect("mkdir");
            std::fs::write(&path, body).expect("write");
        }
        SeedLoader { base_dir: base }
    }

    #[test]
    fn stamp_is_deterministic_and_tracks_seed_bytes() {
        let a = stamp_fixture("bytes-a", &[("apps/one.json", "{\"id\":\"x\"}")]);
        let first = a.content_stamp().expect("stamp");
        assert_eq!(first, a.content_stamp().expect("stamp"), "not deterministic");

        let b = stamp_fixture("bytes-b", &[("apps/one.json", "{\"id\":\"y\"}")]);
        assert_ne!(first, b.content_stamp().expect("stamp"), "byte change must restamp");
    }

    #[test]
    fn stamp_tracks_file_paths_not_just_contents() {
        // Renaming a seed file changes which builtin it defines, so identical
        // bytes at a different path must not hash the same.
        let a = stamp_fixture("path-a", &[("apps/alpha.json", "{}")]);
        let b = stamp_fixture("path-b", &[("apps/beta.json", "{}")]);
        assert_ne!(a.content_stamp().expect("stamp"), b.content_stamp().expect("stamp"));
    }

    #[test]
    fn stamp_length_prefixing_defeats_concatenation_collisions() {
        // The two trees must feed the hasher the SAME byte stream once the
        // length prefixes are removed, or this proves nothing: `"apps/ab" +
        // "c"` and `"apps/a" + "bc"` both concatenate to `apps/abc`, so only
        // the prefixes keep them apart. Do not "tidy" these into `.json`
        // names — a fixed suffix between the moved character and the content
        // makes the streams differ anyway, and the test would then pass even
        // with the prefixing deleted.
        let a = stamp_fixture("collide-a", &[("apps/ab", "c")]);
        let b = stamp_fixture("collide-b", &[("apps/a", "bc")]);
        assert_ne!(
            a.content_stamp().expect("stamp"),
            b.content_stamp().expect("stamp"),
            "concatenation ambiguity — length prefixes are load-bearing"
        );
    }

    #[test]
    fn stamp_is_none_when_the_tree_cannot_be_read() {
        // Must be None, never a stable value: the caller treats None as
        // "reconcile unconditionally". A stamp derived from an unreadable tree
        // would match across genuinely different seed sets and skip forever.
        let missing = SeedLoader {
            base_dir: std::env::temp_dir().join("ss-stamp-does-not-exist-zzz"),
        };
        assert!(missing.content_stamp().is_none());
    }

    /// The committed provider seed is the single root of provider data. This
    /// binds it to the `Provider` discriminant (one row per concrete variant),
    /// so a new enum variant or a mistyped/aliased seed key fails the build.
    #[test]
    fn provider_seed_consistency() {
        use std::collections::HashSet;
        use streamscope_core::config::model_map::Provider;

        let rows = repo_seed_loader().load_providers();
        assert!(!rows.is_empty(), "provider seed is empty");

        // Unique provider keys.
        let keys: HashSet<&str> = rows.iter().map(|r| r.provider.as_str()).collect();
        assert_eq!(keys.len(), rows.len(), "duplicate provider key in seed");

        // Unique FOLDED keys — the generated frontend module keys the icon map by
        // `provider` folded (lowercase, `_`/`-`/space stripped), so two rows that
        // fold equal (e.g. `x_ai` beside `xai`) would emit a duplicate TS object
        // key. Fail here, closer to the cause than a downstream svelte-check error.
        let folded: HashSet<String> = rows
            .iter()
            .map(|r| r.provider.to_lowercase().replace(['_', '-', ' '], ""))
            .collect();
        assert_eq!(folded.len(), rows.len(), "two provider keys fold to the same frontend key");

        // Field constraints per row.
        const VALID_FORMATS: &[&str] =
            &["chat_completions", "responses", "anthropic_messages", "google_gemini"];
        for r in &rows {
            assert!(!r.label.is_empty(), "{}: empty label", r.provider);
            assert!(!r.icon.is_empty(), "{}: empty icon", r.provider);
            assert!(
                VALID_FORMATS.contains(&r.default_api_format.as_str()),
                "{}: invalid default_api_format {:?}",
                r.provider,
                r.default_api_format
            );
            if let Some(f) = &r.byok_api_format {
                assert!(VALID_FORMATS.contains(&f.as_str()), "{}: invalid byok_api_format", r.provider);
            }
            // A transport says the endpoint is addressed some way other than the
            // canonical one, which only a deployment knows — so such a provider has no
            // fixed URL to ship and cannot be a built-in pass-through. Both halves are
            // asserted because a transport rewrites exactly the address `default_url`
            // states: the pair would describe an endpoint the provider does not serve.
            if r.default_transport.is_some() {
                assert!(
                    !r.byok_builtin,
                    "{}: a provider carrying default_transport cannot be byok_builtin",
                    r.provider
                );
                assert!(
                    r.default_url.is_none(),
                    "{}: a provider carrying default_transport must have null default_url",
                    r.provider
                );
            }
            if r.byok_builtin {
                assert!(r.default_url.is_some(), "{}: byok needs default_url", r.provider);
                assert!(r.byok_display_name.is_some(), "{}: byok needs display name", r.provider);
                assert!(!r.icon_only, "{}: byok row can't be icon_only", r.provider);
            } else if !r.icon_only {
                // Self-hosted / no fixed host: URL must be absent (operator supplies it).
                assert!(r.default_url.is_none(), "{}: non-byok row must have null default_url", r.provider);
            }
            // A chat-endpoint-path override is a rooted path and only meaningful
            // for the `chat_completions` protocol (other protocols' paths are fixed).
            if let Some(path) = &r.chat_endpoint_path {
                assert!(path.starts_with('/'), "{}: chat_endpoint_path must start with '/': {path}", r.provider);
                assert_eq!(
                    r.default_api_format, "chat_completions",
                    "{}: chat_endpoint_path only applies to chat_completions", r.provider
                );
            }
        }

        // BYOK keys must be unique: byok_display_name is the (tenant_id, name)
        // downstream upsert key (a dup silently skips the second provider's
        // downstream + grant).
        let mut byok_names: HashSet<&str> = HashSet::new();
        for r in rows.iter().filter(|r| r.byok_builtin) {
            let name = r.byok_display_name.as_deref().unwrap();
            assert!(byok_names.insert(name), "duplicate byok_display_name: {name}");
            // Structural URL guard: the proxy appends the hardcoded protocol path
            // (`/v1/chat/completions`, …) to this base, so a byok base must be a real
            // https URL with a host (a malformed one would 404 the pass-through).
            // Doesn't validate that the remote path exists.
            let url = r.default_url.as_deref().unwrap();
            assert!(url.starts_with("https://"), "{}: byok default_url must be https: {url}", r.provider);
            let host = url.split("://").nth(1).and_then(|s| s.split('/').next()).unwrap_or("");
            assert!(!host.is_empty(), "{}: byok default_url has no host: {url}", r.provider);
        }

        // Every concrete `Provider` variant is covered by exactly one non-icon_only
        // row; exactly one row is the literal `custom`; every other Custom-mapped
        // row is an added SaaS (maps to Custom, key != "custom").
        const ENUM_PROVIDERS: &[&str] = &[
            "openai", "anthropic", "groq", "together", "fireworks", "deepseek", "mistral",
            "openrouter", "nvidia", "ollama", "vllm", "azure_openai", "aws_bedrock",
            "google_vertex", "google_gemini",
        ];
        for p in ENUM_PROVIDERS {
            assert!(
                !matches!(Provider::from_str_relaxed(p), Provider::Custom),
                "test list stale: {p} no longer a concrete variant"
            );
            let matched: Vec<&ProviderSeed> = rows
                .iter()
                .filter(|r| !r.icon_only && Provider::from_str_relaxed(&r.provider) == Provider::from_str_relaxed(p))
                .collect();
            assert_eq!(matched.len(), 1, "variant {p} must have exactly one seed row, found {}", matched.len());
        }
        let custom_rows: Vec<&ProviderSeed> =
            rows.iter().filter(|r| !r.icon_only && r.provider == "custom").collect();
        assert_eq!(custom_rows.len(), 1, "exactly one `custom` row required");
        // Every remaining non-icon_only row is an added OpenAI-compatible SaaS: it
        // maps to `Custom` (routes by its explicit format) and is not the literal
        // `custom`. A row that instead collided with a concrete variant's alias
        // would have been caught above as a second row for that variant.
        for r in rows.iter().filter(|r| {
            !r.icon_only && r.provider != "custom" && !ENUM_PROVIDERS.contains(&r.provider.as_str())
        }) {
            assert!(
                matches!(Provider::from_str_relaxed(&r.provider), Provider::Custom),
                "added provider {} must map to Custom (route by explicit format)",
                r.provider
            );
        }
    }

    fn seed_expert_to_expert(seed: &ExpertSeed) -> crate::agent::experts::Expert {
        let snippet_keys =
            crate::agent::experts::default_snippet_keys(&seed.input_types, &seed.output_types);
        crate::agent::experts::Expert {
            axis: seed.axis.clone(),
            description: Some(seed.description.clone()),
            prompt: String::new(),
            raw_prompt: seed.raw_prompt.clone(),
            input_types: seed.input_types.clone(),
            output_types: seed.output_types.clone(),
            model_override: None,
            color: None,
            snippet_keys,
        }
    }

    #[test]
    fn seed_expert_bodies_carry_no_cross_expert_text() {
        let experts = repo_seed_loader().load_experts();
        assert!(experts.len() >= 7, "expected the 7 seeded experts, got {}", experts.len());

        let banned = [
            "another expert",
            "other experts",
            "owned by another",
            "defer to",
            "defers to",
        ];
        for e in &experts {
            let lower = e.raw_prompt.to_lowercase();
            for phrase in banned {
                assert!(
                    !lower.contains(phrase),
                    "{}: body contains banned cross-expert phrase {phrase:?}",
                    e.axis
                );
            }
            // No solo identity opener — the panel preamble (or the generated
            // solo preamble) supplies the identity.
            let first_line = e
                .raw_prompt
                .lines()
                .find(|l| !l.trim().is_empty())
                .unwrap_or("");
            assert!(
                !first_line.trim_start().starts_with("You are"),
                "{}: body opens with a solo identity claim: {first_line:?}",
                e.axis
            );
        }
    }

    #[test]
    fn seed_merged_panel_prompts_compose_consistently() {
        let loader = repo_seed_loader();
        let experts = loader.load_experts();
        let snippets: std::collections::HashMap<String, String> = loader
            .load_snippets()
            .into_iter()
            .map(|s| (s.key, s.content))
            .collect();
        assert!(
            snippets.contains_key(crate::agent::experts::PANEL_SNIPPET_KEY),
            "panel contract snippet missing from seeds/snippets"
        );

        // Default pools mirror the runtime grouping: same primary input path,
        // merge-enabled, default routing/scope.
        let session_pool: Vec<_> = experts
            .iter()
            .filter(|e| e.merge_enabled && e.input_types.iter().any(|t| t == "session"))
            .map(seed_expert_to_expert)
            .collect();
        let cluster_pool: Vec<_> = experts
            .iter()
            .filter(|e| e.merge_enabled && e.input_types.iter().any(|t| t == "session_cluster"))
            .map(seed_expert_to_expert)
            .collect();
        assert!(session_pool.len() >= 2, "session pool unexpectedly small");
        assert!(cluster_pool.len() >= 2, "cluster pool unexpectedly small");

        for (pool_name, pool) in [("session", &session_pool), ("cluster", &cluster_pool)] {
            let members: Vec<&crate::agent::experts::Expert> = pool.iter().collect();
            let prompt = crate::agent::experts::assemble_group_prompt(&members, &snippets);

            // Panel contract present, each axis section present exactly once.
            assert!(prompt.contains("## Analysis Panel"), "{pool_name}: panel contract missing");
            for m in &members {
                let heading = format!("# Axis: {}", m.axis);
                let count = prompt.matches(&heading).count();
                assert_eq!(count, 1, "{pool_name}: axis heading {heading:?} appears {count} times");
                // Roster line present for attribution.
                assert!(
                    prompt.contains(&format!("`{}`", m.axis)),
                    "{pool_name}: roster missing axis `{}`",
                    m.axis
                );
            }

            // No paragraph duplicated (normalized, substantial ones only —
            // short list items legitimately repeat shapes).
            let mut seen = std::collections::HashMap::new();
            for para in prompt.split("\n\n") {
                let norm = para.split_whitespace().collect::<Vec<_>>().join(" ");
                if norm.len() < 200 {
                    continue;
                }
                if let Some(prev) = seen.insert(norm.clone(), para) {
                    panic!(
                        "{pool_name}: duplicated paragraph in merged prompt:\n{}",
                        prev.chars().take(160).collect::<String>()
                    );
                }
            }

            // Every "appended … snippet" reference resolves within the pool's
            // snippet union.
            let union: std::collections::HashSet<&str> = members
                .iter()
                .flat_map(|m| m.snippet_keys.iter().map(String::as_str))
                .collect();
            for (phrase, key) in [
                ("Tool Risk Rules Output snippet", "tool_rules"),
                ("Field Profile Suggestions snippet", "field_profile_suggestion"),
                ("Session Label Output snippet", "session_label"),
                ("Session Label snippet", "session_label"),
            ] {
                if prompt.contains(phrase) {
                    assert!(
                        union.contains(key),
                        "{pool_name}: prompt references {phrase:?} but snippet {key:?} not in union"
                    );
                }
            }

            // A body may only mention an output channel its axis carries.
            for m in &members {
                for (token, output_type) in [
                    ("proposed_tool_rules", "tool_rules"),
                    ("proposed_field_profiles", "field_profile_suggestion"),
                    ("session_labels", "session_label"),
                ] {
                    if m.raw_prompt.contains(token) {
                        assert!(
                            m.output_types.iter().any(|t| t == output_type),
                            "{pool_name}/{}: body mentions {token} but lacks output type {output_type}",
                            m.axis
                        );
                    }
                }
            }
        }

        // The two cluster axes: anomaly analyzes singletons, linkage doesn't —
        // the singleton note must be in the cluster prompt.
        let members: Vec<&crate::agent::experts::Expert> = cluster_pool.iter().collect();
        let cluster_prompt = crate::agent::experts::assemble_group_prompt(&members, &snippets);
        assert!(
            cluster_prompt.contains("SINGLE session"),
            "cluster prompt missing the singleton-cluster note"
        );
    }

    /// The spawn-tool vocabulary the judge is taught (seed prose) MUST match the
    /// code's single source of truth (`conversation::spawn::SPAWN_TOOL_NAMES`) —
    /// detection and the prompt hint would silently drift otherwise. Both snippets
    /// carry the exact backticked, comma-separated run built from the constant.
    #[test]
    fn seed_spawn_tool_list_matches_constant() {
        let expected = crate::conversation::spawn::SPAWN_TOOL_NAMES
            .iter()
            .map(|n| format!("`{n}`"))
            .collect::<Vec<_>>()
            .join(", ");
        let snippets: std::collections::HashMap<String, String> = repo_seed_loader()
            .load_snippets()
            .into_iter()
            .map(|s| (s.key, s.content))
            .collect();
        for key in ["session_label", "session_cluster"] {
            let content = snippets
                .get(key)
                .unwrap_or_else(|| panic!("snippet {key} missing from seeds/snippets"));
            assert!(
                content.contains(&expected),
                "snippet {key} spawn-tool list drifted from SPAWN_TOOL_NAMES; expected the run: {expected}"
            );
        }
    }

    #[test]
    fn seed_expert_frontmatter_matches_default_pools() {
        // The seeded topology this release ships: 5 session-path axes (incl.
        // tool_policy's session leg), 2 cluster-path axes (linkage + anomaly),
        // everything merge-enabled.
        let experts = repo_seed_loader().load_experts();
        let by_axis: std::collections::HashMap<&str, &ExpertSeed> =
            experts.iter().map(|e| (e.axis.as_str(), e)).collect();

        let anomaly = by_axis["anomaly"];
        assert!(
            anomaly.input_types.iter().any(|t| t == "session_cluster"),
            "anomaly is cross-session by definition — its input must be session_cluster"
        );
        assert!(!anomaly.input_types.iter().any(|t| t == "session"));

        let link = by_axis["session_linkage"];
        assert!(link.input_types.iter().any(|t| t == "session_cluster"));

        for axis in ["security", "compliance", "cost_efficiency", "quality", "tool_policy"] {
            assert!(
                by_axis[axis].input_types.iter().any(|t| t == "session"),
                "{axis} should run the session path"
            );
        }
        for e in &experts {
            assert!(e.merge_enabled, "{}: seeded experts default to merge-enabled", e.axis);
        }
    }

    /// Every provider the model catalog is keyed by must be reachable from the
    /// provider vocabulary a server can actually be created with.
    ///
    /// Pricing resolves only from a catalog row whose provider matches the
    /// server's, both sides folded through `canonical_provider_key`. So a catalog
    /// provider string that no selectable provider folds onto can never price
    /// anything — its rows are dead weight, and every model under it silently
    /// reports as unpriced. `google` is the case that motivated this: it is an
    /// `icon_only` vendor row, never a selectable upstream, so catalog rows
    /// carrying it must fold onto `google_gemini`.
    ///
    /// Deliberately NOT an equality check between the two vocabularies: a catalog
    /// may legitimately carry a vendor we do not model as an upstream (its rows
    /// still supply capabilities, which cross providers). What must hold is that
    /// anything claiming to be a *modelled* provider actually reaches one.
    #[test]
    fn catalog_providers_reach_the_provider_vocabulary() {
        use crate::routes::upstreams::canonical_provider_key;

        // `repo_seed_loader`, not `provider_catalog()`: the latter resolves the
        // seed tree relative to the runtime CWD, which under `cargo test` is the
        // package directory, so it reads as empty and every assertion below would
        // pass vacuously.
        let providers = repo_seed_loader().load_providers();
        assert!(!providers.is_empty(), "provider seed must not be empty");
        let selectable: std::collections::HashSet<String> = providers
            .iter()
            .filter(|p| !p.icon_only)
            .map(|p| canonical_provider_key(&p.provider))
            .collect();

        // An icon-only vendor row is never a server's provider, so a catalog row
        // carrying one must fold onto something selectable.
        for row in providers.iter().filter(|p| p.icon_only) {
            assert!(
                selectable.contains(&canonical_provider_key(&row.provider)),
                "icon-only provider `{}` folds to `{}`, which no selectable provider \
                 matches — catalog rows carrying it could never price a server",
                row.provider,
                canonical_provider_key(&row.provider),
            );
        }

        // Any catalog provider that collides with a selectable one after folding
        // is fine; one that folds to something unreachable is only acceptable for
        // a vendor we genuinely do not model as an upstream.
        let entries = repo_seed_loader().load_catalog();
        assert!(!entries.is_empty(), "catalog seed must not be empty");
        let unreachable: std::collections::BTreeSet<String> = entries
            .iter()
            .map(|e| canonical_provider_key(&e.provider))
            .filter(|k| !selectable.contains(k))
            .collect();
        // Keep this list explicit: a NEW unreachable provider is either a typo in
        // the generator's provider map or a vendor that needs adding to
        // providers.json, and both should be noticed here rather than shipped.
        let known_unmodelled: std::collections::BTreeSet<String> =
            ["qwen".to_string()].into_iter().collect();
        assert_eq!(
            unreachable, known_unmodelled,
            "catalog providers that no server can match changed; \
             add the provider to seeds/providers/providers.json, fix the \
             generator's PROVIDER_MAP, or extend the known-unmodelled list"
        );
    }

    /// Every unit key the catalog seed publishes must be one this build knows.
    ///
    /// `Rates` deliberately DROPS an unrecognised unit rather than failing, so a
    /// newer admin's rate map folds in cleanly. That tolerance is also what makes
    /// a misspelled key in the generator invisible: the entry deserializes, the
    /// rate is gone, and the model quietly reports as unpriced. Reading the raw
    /// file is the only place the dropped keys are still visible.
    #[test]
    fn catalog_rate_units_are_all_recognised() {
        use streamscope_core::pricing::Unit;

        let raw = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../seeds/models/models.json"
        ))
        .expect("catalog seed must be readable");
        let entries: Vec<serde_json::Value> =
            serde_json::from_str(&raw).expect("catalog seed must be valid JSON");
        assert!(!entries.is_empty(), "catalog seed must not be empty");

        for entry in &entries {
            let Some(units) = entry.pointer("/rates/units").and_then(|u| u.as_object()) else {
                continue;
            };
            for key in units.keys() {
                assert!(
                    Unit::from_wire(key).is_some(),
                    "{}/{}: rate unit `{key}` is not a known pricing unit, so it is \
                     dropped on load and the model reads as unpriced",
                    entry["provider"],
                    entry["model"],
                );
            }
        }
    }

    /// Seeded rates must stay in each unit's natural scale — per 1M for token
    /// units, per unit otherwise.
    ///
    /// A scale slip (per-token where per-1M is meant, or the reverse) leaves
    /// every number in the file looking plausible while mis-billing by a factor
    /// of a million, and no downstream check can see it. Anchoring models whose
    /// published price is stable is what catches it. Bands are wide enough that
    /// an ordinary repricing does not trip them.
    #[test]
    fn catalog_rates_are_in_each_unit_s_natural_scale() {
        use streamscope_core::pricing::Unit;

        let entries = repo_seed_loader().load_catalog();
        assert!(!entries.is_empty(), "catalog seed must not be empty");

        let priced = entries.iter().filter(|e| !e.rates.is_empty()).count();
        assert!(
            priced * 2 > entries.len(),
            "only {priced} of {} catalog entries carry a rate map; a transform that \
             emptied them would leave every model unpriced",
            entries.len(),
        );

        for (provider, model, lo, hi) in [
            ("anthropic", "claude-sonnet-4-5", 1.0, 10.0),
            ("openai", "gpt-4o", 1.0, 10.0),
            ("openai", "gpt-4o-mini", 0.01, 1.0),
        ] {
            let anchor = entries
                .iter()
                .find(|e| e.provider == provider && e.model == model)
                .unwrap_or_else(|| panic!("price anchor {provider}/{model} left the catalog"));
            let rate = anchor
                .rates
                .units
                .get(&Unit::InputToken)
                .unwrap_or_else(|| panic!("price anchor {provider}/{model} lost its input rate"))
                .resolve(0);
            assert!(
                (lo..=hi).contains(&rate),
                "price anchor {provider}/{model}: input {rate} outside ${lo}-${hi}/1M",
            );
        }
    }

    /// The seeded long-context surcharges must load as step tables and bill
    /// above their threshold.
    ///
    /// `Rate` is an untagged union, so a step table the catalog publishes but
    /// this build cannot read does not fail the load — it drops to the other
    /// arm or takes the unit with it, and the model quietly reverts to one
    /// price for prompts of every length. Nothing else notices: the base rate
    /// stays correct, which is the only rate the price anchors check.
    /// Resolving each table on both sides of its threshold is what sees it.
    #[test]
    fn catalog_long_context_surcharges_load_and_bill() {
        use streamscope_core::pricing::Rate;

        let entries = repo_seed_loader().load_catalog();
        let mut tiered = 0usize;
        for entry in &entries {
            for (unit, rate) in &entry.rates.units {
                let Rate::Tiered { rate: base, tiers } = rate else {
                    continue;
                };
                tiered += 1;
                let top = tiers
                    .iter()
                    .max_by_key(|t| t.above)
                    .expect("a step table with no steps is a flat rate wearing a costume");
                let (provider, model) = (&entry.provider, &entry.model);
                assert!(
                    top.above > 0,
                    "{provider}/{model} {unit:?}: a threshold of 0 surcharges every request",
                );
                // What applies exactly AT the top threshold is the step below it,
                // since the engine selects on a strict `>` — the base only when
                // `top` is the sole step. Asserting the base unconditionally
                // would fail a correct multi-step table, and blame the strict
                // comparison for it.
                let below_top = tiers
                    .iter()
                    .filter(|t| t.above < top.above)
                    .max_by_key(|t| t.above)
                    .map_or(*base, |t| t.rate);
                assert_eq!(
                    rate.resolve(top.above),
                    below_top,
                    "{provider}/{model} {unit:?}: the surcharge starts AT its threshold, \
                     not above it",
                );
                assert_eq!(
                    rate.resolve(top.above + 1),
                    top.rate,
                    "{provider}/{model} {unit:?}: a prompt past the threshold is still \
                     billed at the base rate",
                );
            }
        }
        // Below the observed count with headroom, like the generator's own gate:
        // this catches the surcharges vanishing wholesale, not their churn.
        assert!(
            tiered >= 40,
            "only {tiered} seeded rates carry a long-context surcharge; the catalog \
             generator has stopped emitting them, so every long prompt is billed at \
             the short-prompt price",
        );
    }
}
