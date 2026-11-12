//! Wire types for client-config profiles and their templates. Profiles are
//! seeded from `seeds/client_profiles/*.json`, stored per-tenant one row per
//! profile in the `client_profiles` table, and consumed by both the web
//! quickstart and the `ssai` CLI provisioning bundle.

use std::collections::BTreeMap;

/// Lexical format of a client-config template body. Drives both the
/// syntax-highlight hint on the UI side and the per-format escape mode the
/// renderer applies to substituted values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum TemplateFormat {
    Json,
    Yaml,
    Toml,
    Shell,
    /// Plain instructions (e.g. Cursor settings panel walkthrough). No
    /// substitution escaping, no post-render parser validation.
    Text,
}

/// What kind of credential the template uses. Drives wizard step gating: a
/// `combined` template needs both an LLM key and an MCP key; a `mcp` template
/// only an MCP key; an `instructions` template carries no secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum TemplateKind {
    Llm,
    Mcp,
    Combined,
    Instructions,
}

impl TemplateKind {
    /// Whether templates of this kind carry an LLM section — i.e. need a
    /// provider to render against. The single source of truth for the
    /// kind→requirements mapping; server validation and the CLI's prompts
    /// must agree on it (a drift is a cross-version skew the render parity
    /// check can't catch).
    pub fn needs_llm(self) -> bool {
        matches!(self, Self::Llm | Self::Combined | Self::Instructions)
    }
}

/// How the client authenticates with the MCP gateway. Drives the MCP step
/// of the wizard: `static` binds a workspace key into `Authorization: Bearer …`;
/// `spec_oauth` issues no key and lets the client run the MCP-spec OAuth 2.1
/// dance against the gateway on first use.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum McpAuthMode {
    /// Bearer-token auth using a workspace key (`sk-` proxy-issued, or `vk-`
    /// forward-auth). The wizard mints or reuses the key as part of the render
    /// call; the same key spans the LLM and MCP surfaces.
    #[default]
    Static,
    /// MCP spec OAuth 2.1 — the client auto-discovers
    /// `/.well-known/oauth-protected-resource` on the gateway and runs the
    /// authorization-code flow on first use. No static key is minted.
    SpecOauth,
}

/// How the gateway key reaches the user for a given template.
///
/// `Config` is the ordinary case: the key must be reachable from what a render
/// hands over — the rendered body, the rendered instructions (for
/// `kind = instructions`, where the prose IS the deliverable), or one of the
/// template's companions; a print-only snippet may also lean on an
/// LLM-bearing sibling template, but a template that writes a file may not.
///
/// `Environment` states that the tool reads the key ONLY from a process
/// environment variable the user exports, and loads no file we could write
/// (Zed). Nothing can deliver it but the portal showing the plaintext once at
/// render time, so declaring it here is what turns that from an accident into
/// a stated claim — and it is the only thing that exempts a template from the
/// key-deliverability check.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum KeyDelivery {
    #[default]
    Config,
    Environment,
}

/// Whether a template has a form for a LOCAL MCP server — one the developer's
/// own machine starts from a command line, written as the client's stdio
/// entry — and where it writes it. A declaration, never inferred from the
/// body: the server merges local servers only into a template that declares a
/// form, and says so for every other selected client instead of dropping them
/// silently.
///
/// A local server is an `mcp_servers[]` item with `local = true`, appended
/// after the gateway's: it carries `slug`, `name`, `command`, `args` (a list
/// of `{value}`) and `env` (a list of `{name, value}`), and none of a gateway
/// item's `url` / `headers`. A template with a form branches on
/// `{{#if local}}` inside its `{{#each mcp_servers}}` loop.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum LocalMcpForm {
    /// No form: the template is never handed a local server.
    #[default]
    None,
    /// The body, or a companion written in every scope, writes it.
    Config,
    /// Only a file written under a project scope writes it (Claude Code's
    /// `.mcp.json`): the template's other parts skip a local item.
    Project,
}

impl LocalMcpForm {
    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }
}

/// A part of a template's configuration that is not its body: a credential
/// the tool reads from its own secrets or `.env` file, a part of the config
/// the tool reads from a file of its own (Claude Code's project MCP servers),
/// or a snippet the user runs because no file can carry it (Claude Code's
/// user-scope MCP servers live in a file the tool keeps its own state in, so
/// they are added with its own command). This is the
/// DECLARED form — `body` and `instructions` are Handlebars templates rendered
/// with the same placeholder map and the same sentinel contract as the owning
/// template's body. `path` is a literal and is deliberately NOT rendered, so
/// the set of files a profile can write stays reviewable in a seed diff.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CompanionTemplate {
    /// Destination path, `~/`-anchored. The CLI writes here; the quickstart
    /// shows it as the snippet's filename. `None` ⇒ no file outside a
    /// project: with a `project_path`, the companion exists only under a
    /// project scope; without one, it is a snippet shown and never written.
    #[serde(default)]
    pub path: Option<String>,
    /// Where the file goes under a project scope, relative to the project
    /// root. `None` ⇒ the `~/` path re-anchored at the project root.
    #[serde(default)]
    pub project_path: Option<String>,
    pub format: TemplateFormat,
    /// User-facing title for the snippet header.
    pub title: String,
    /// Why this file exists, rendered above the snippet.
    #[serde(default)]
    pub instructions: String,
    pub body: String,
}

/// Where a companion goes under a project scope, relative to the project
/// root: its declared `project_path` (whatever its `path`), else its `~/`
/// path re-anchored there. `None` ⇒ an absolute path with no project path,
/// written where it says in either scope, or a snippet with no path. The one
/// reading of the rule — the CLI places files by it and profile validation
/// checks clashes by it.
pub fn companion_project_path<'a>(path: Option<&'a str>, project_path: Option<&'a str>) -> Option<&'a str> {
    project_path.or_else(|| path?.strip_prefix("~/"))
}

/// One copy-paste config template within a `ClientProfile`. The body is a
/// raw template string with `{{ident}}` placeholders and optional one-level
/// `{{#if ident}} … {{/if}}` conditional sections (line-stripped on
/// tag-only lines). See the render engine module for substitution semantics.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ClientProfileTemplate {
    pub kind: TemplateKind,
    /// Client-facing protocol the rendered snippet will hit (e.g.
    /// `"responses"` for a snippet that posts to `/v1/responses`). Selects
    /// the `{{base_url_*}}` placeholder variant. It does NOT constrain
    /// which upstream the rendered snippet can be paired with — the proxy
    /// translates between any client protocol and any upstream protocol.
    #[serde(default)]
    pub protocol: Option<String>,
    /// Optional route-tag filter for the quickstart renderer. When set, the
    /// renderer's `routes` block is restricted to downstream routes whose
    /// `tags` array contains this value (e.g. `"opencode"`, `"claude-code"`),
    /// and the top-level `{{model_alias}}` resolves to a route whose
    /// `default_for_tags` contains it. Falls back to all enabled routes when
    /// no route under the provider is tagged this way — keeps the renderer
    /// usable on tenants that haven't tagged anything yet.
    #[serde(default)]
    pub route_tag: Option<String>,
    /// Where the user should put the body. `None` for instructions / shell
    /// snippets that aren't a file (e.g. curl one-liners, env exports).
    #[serde(default)]
    pub filename: Option<String>,
    /// Project-local destination, RELATIVE to the project root, used when
    /// provisioned with `--local`/`--dir` (e.g. `.claude/settings.json`).
    /// `None` ⇒ the client has no project-local form; in a project run it is
    /// written to its global `filename` (the global scope) instead.
    #[serde(default)]
    pub project_filename: Option<String>,
    pub format: TemplateFormat,
    pub title: String,
    /// Short user-facing prose rendered above the snippet. Optional.
    #[serde(default)]
    pub instructions: Option<String>,
    /// Only meaningful on `kind = mcp` and `kind = combined` templates;
    /// ignored otherwise. Defaults to `static`.
    #[serde(default)]
    pub mcp_auth_mode: McpAuthMode,
    /// How the user gets the gateway key into this client. `Environment` is
    /// the only exemption from the key-deliverability check — see
    /// [`KeyDelivery`].
    #[serde(default)]
    pub key_delivery: KeyDelivery,
    /// Files this template's configuration needs beside its body. Omitted from
    /// the wire when empty, so a profile that declares none carries no extra
    /// key.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub companions: Vec<CompanionTemplate>,
    /// Arrays of the body that the CLI merges ENTRY BY ENTRY instead of
    /// replacing whole: a JSON pointer into the rendered document (`/models`,
    /// or `/providers` for a TOML `[[providers]]`) → the field that identifies
    /// an entry (`name`). Provisioning then writes, updates and removes only
    /// the entries it rendered, and keeps the ones the user added beside them;
    /// an array not listed here is still replaced whole. Every rendered entry
    /// must be an object carrying a scalar identity (or, with a composite
    /// field `a+b`, a scalar in each named field), unique within its array —
    /// or, with the field [`STRING_ENTRIES`], a string identified by
    /// [`string_entry_identity`] (`set-env: ["NAME=value"]`) in JSON or YAML.
    /// Checked when the profile is saved. Omitted from the wire when empty.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub keyed_arrays: BTreeMap<String, String>,
    /// Whether, and where, this template writes a local MCP server — see
    /// [`LocalMcpForm`]. Omitted from the wire when it has no form.
    #[serde(default, skip_serializing_if = "LocalMcpForm::is_none")]
    pub local_mcp: LocalMcpForm,
    pub body: String,
}

/// The `keyed_arrays` field naming an array of strings rather than objects:
/// each entry is identified by [`string_entry_identity`].
pub const STRING_ENTRIES: &str = "=";

/// A string entry's identity: the name before its first `=`, trimmed as Aider
/// trims it (`ANTHROPIC_API_BASE = https://…` → `ANTHROPIC_API_BASE`), the
/// whole trimmed string when it has none — so a rendered `NAME=value` replaces
/// the user's entry for that name and leaves their other entries alone.
pub fn string_entry_identity(entry: &str) -> &str {
    entry.split_once('=').map_or(entry, |(name, _)| name).trim()
}

/// The identity of one entry of a keyed array, as the save-time check and the
/// CLI's JSON and YAML writers all read it: with `key` = [`STRING_ENTRIES`] a
/// string's [`string_entry_identity`]; otherwise the entry's `key` field when
/// it is a scalar — a string, or a number or boolean in its written form (a
/// model alias of `42` parses as a number) — or, for a composite `key`
/// (`action+resource`), every named field (see [`composite_identity`]).
/// `None` when it has none.
pub fn keyed_entry_identity(entry: &serde_json::Value, key: &str) -> Option<String> {
    if key == STRING_ENTRIES {
        return entry.as_str().map(|s| string_entry_identity(s).to_string());
    }
    composite_identity(key, |field| scalar_identity(entry.get(field)?))
}

/// A keyed-array identity read through `field_of` (one field's written form):
/// a plain `key` names one field; a composite `a+b` names several, all of which
/// must be present, and identifies the entry by all of them together — for an
/// array whose entries are unique only as a pair (an OpenCode policy is unique
/// by `action` AND `resource`). The parts are joined as a JSON array, so two
/// different tuples never share an identity whatever their values hold.
pub fn composite_identity(key: &str, field_of: impl Fn(&str) -> Option<String>) -> Option<String> {
    if !key.contains('+') {
        return field_of(key);
    }
    let parts: Option<Vec<String>> = key.split('+').map(&field_of).collect();
    serde_json::to_string(&parts?).ok()
}

/// An identity field's value in its written form — a string, or a number or
/// boolean as text; `None` for anything else.
pub fn scalar_identity(field: &serde_json::Value) -> Option<String> {
    use serde_json::Value;
    match field {
        Value::String(s) => Some(s.clone()),
        v @ (Value::Number(_) | Value::Bool(_)) => Some(v.to_string()),
        _ => None,
    }
}

impl ClientProfileTemplate {
    /// The name a user picks this template by (`ssai provision
    /// --template <client>=<name>`), derived from the template so a profile
    /// needs no extra field and a reorder of its templates never changes it:
    /// `chat` / `responses` / `anthropic` / `gemini` by protocol for an
    /// LLM-bearing template, `mcp` / `instructions` by kind, plus `-oauth`
    /// when the MCP half authenticates by spec OAuth. Unique among a
    /// profile's file-writing templates — checked by the seed tests.
    pub fn variant_name(&self) -> String {
        let base = match (self.kind, self.protocol.as_deref()) {
            (TemplateKind::Mcp, _) => "mcp",
            (TemplateKind::Instructions, _) => "instructions",
            (_, Some("chat_completions")) => "chat",
            (_, Some("responses")) => "responses",
            (_, Some("anthropic_messages")) => "anthropic",
            (_, Some("google_gemini")) => "gemini",
            (_, Some(other)) => other,
            (TemplateKind::Llm, None) => "llm",
            (TemplateKind::Combined, None) => "combined",
        };
        match self.mcp_auth_mode {
            McpAuthMode::SpecOauth => format!("{base}-oauth"),
            McpAuthMode::Static => base.to_string(),
        }
    }
}

/// The LLM template a client is provisioned with by default — on the CLI and
/// in the web quickstart alike. Against a BYOK pass-through, `native` is the
/// protocol its server speaks, and the template speaking it comes first: the
/// client's own credential is forwarded, and one a vendor issues for its own
/// wire (a subscription token) works on nothing else. Otherwise its first
/// OpenAI-compatible (`chat_completions`) one, which works on every upstream
/// whatever a provider load-balances across, else its first LLM template — the
/// static-MCP-key one of an MCP auth-mode pair every time. A preference over
/// the profile's order, never a reorder: an installation records its template
/// by position.
pub fn default_llm_template_index(templates: &[ClientProfileTemplate], native: Option<&str>) -> Option<usize> {
    let llm = |t: &ClientProfileTemplate| matches!(t.kind, TemplateKind::Combined | TemplateKind::Llm);
    let speaks = |t: &ClientProfileTemplate, p: &str| t.protocol.as_deref() == Some(p);
    let chat = |t: &ClientProfileTemplate| speaks(t, "chat_completions");
    let fixed_key = |t: &ClientProfileTemplate| matches!(t.mcp_auth_mode, McpAuthMode::Static);
    let native_first = native.and_then(|p| {
        templates
            .iter()
            .position(|t| llm(t) && speaks(t, p) && fixed_key(t))
            .or_else(|| templates.iter().position(|t| llm(t) && speaks(t, p)))
    });
    native_first
        .or_else(|| templates.iter().position(|t| llm(t) && chat(t) && fixed_key(t)))
        .or_else(|| templates.iter().position(|t| llm(t) && chat(t)))
        .or_else(|| templates.iter().position(|t| llm(t) && fixed_key(t)))
        .or_else(|| templates.iter().position(llm))
}

/// A client-config profile loaded from `seeds/client_profiles/<id>.json`.
/// One profile per client app (Claude Code, OpenCode, Cursor, …); each
/// carries one or more `templates` covering different downstream protocols
/// or use modes (LLM-only / MCP-only / combined / GUI instructions).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ClientProfile {
    pub id: String,
    pub label: String,
    /// Link to the upstream project's docs — surfaced in the UI as a "Why
    /// these settings?" link.
    #[serde(default)]
    pub homepage: String,
    pub supports_llm: bool,
    pub supports_mcp: bool,
    /// Command that launches the tool once provisioned (e.g. `claude`,
    /// `opencode`). `None` for GUI clients (Cursor, Zed) that the user restarts
    /// instead — the CLI then prints a "Restart <label>" hint.
    #[serde(default)]
    pub launch_command: Option<String>,
    pub templates: Vec<ClientProfileTemplate>,
    /// Set by the loader (`true` when read from disk) and by the seed-sync
    /// (`false` when an admin overrides the profile on a tenant).
    #[serde(default)]
    pub builtin: bool,
}
