//! Stable test placeholder dictionary used to validate template bodies
//! without a live tenant: admin save-time validation renders every edited
//! template against it, and the crate's seed test renders every shipped
//! profile against it. Values are chosen to be syntactically safe in every
//! format and to resolve every documented placeholder, so a body whose only
//! invalid syntax lives inside an `{{#each}}` block still fails fast (the
//! lists below are non-empty for exactly that reason).

use std::collections::BTreeMap;

use crate::render::{
    mcp_client_header_placeholder, mcp_header_item, mcp_local_server_item, Value, API_KEY_PLACEHOLDER,
};
use crate::types::{
    companion_project_path, ClientProfile, KeyDelivery, LocalMcpForm, TemplateFormat, TemplateKind,
};
use crate::RenderError;

/// Build the canonical validation placeholder map. Keep the key set in sync
/// with the server-side placeholder builder — every placeholder the server
/// can emit must resolve here, or admins could save templates that validate
/// but break at render time.
pub fn validation_placeholders() -> BTreeMap<String, Value> {
    let mut phs: BTreeMap<String, Value> = BTreeMap::new();
    // Stable test values — chosen to be syntactically safe in every format.
    let strs = [
        ("api_key", "<paste-your-api-key-here>"),
        ("api_key_name", "test-key"),
        ("api_key_prefix", "sk-test-1234"),
        ("tenant_slug", "acme"),
        ("tenant_name", "Acme"),
        ("provider_name", "anthropic"),
        ("provider_key", "streamscope_acme_anthropic"),
        ("provider_id", "00000000-0000-0000-0000-000000000000"),
        ("provider_icon", ""),
        ("model_alias", "claude-sonnet-4-5"),
        ("model_slot_default", "claude-sonnet-4-5"),
        ("model_slot_fast", "claude-haiku-4-5"),
        ("model_slot_plan", "claude-opus-4-8"),
        ("upstream_model", "claude-sonnet-4-5"),
        ("model_type", "text"),
        ("upstream_api_format", "anthropic_messages"),
        ("reasoning_effort", "medium"),
        ("base_url", "https://gw.example.com"),
        ("endpoint_chat_completions", "https://gw.example.com/v1/chat/completions"),
        ("endpoint_responses", "https://gw.example.com/v1/responses"),
        ("endpoint_anthropic_messages", "https://gw.example.com/v1/messages"),
        ("endpoint_gemini_generate", "https://gw.example.com/v1beta/models/x:generateContent"),
        ("endpoint_gemini_stream", "https://gw.example.com/v1beta/models/x:streamGenerateContent"),
    ];
    for (k, v) in strs {
        phs.insert(k.into(), Value::String(v.into()));
    }
    for k in [
        "supports_vision", "supports_reasoning", "supports_function_calling",
        "supports_caching", "supports_audio_input", "supports_audio_output",
        "supports_video_input", "supports_pdf_input", "supports_response_schema",
        "supports_system_messages",
    ] {
        phs.insert(k.into(), Value::Bool(true));
    }
    for k in ["context_window", "max_output_tokens", "client_context_window"] {
        phs.insert(k.into(), Value::Int(200_000));
    }

    // Seed a representative `routes` list so `{{#each routes}}…{{/each}}`
    // bodies actually iterate at validation time.
    let mut item: BTreeMap<String, Value> = BTreeMap::new();
    item.insert("model_alias".into(), Value::String("claude-sonnet-4-5".into()));
    item.insert("upstream_model".into(), Value::String("claude-sonnet-4-5".into()));
    item.insert("upstream_api_format".into(), Value::String("anthropic_messages".into()));
    item.insert("base_url".into(), Value::String("https://gw.example.com/v1".into()));
    item.insert("context_window".into(), Value::Int(200_000));
    item.insert("max_output_tokens".into(), Value::Int(8192));
    for k in [
        "supports_vision", "supports_reasoning", "supports_function_calling",
        "supports_caching", "supports_audio_input", "supports_audio_output",
        "supports_video_input", "supports_pdf_input", "supports_response_schema",
        "supports_system_messages",
    ] {
        item.insert(k.into(), Value::Bool(true));
    }
    // Two DISTINCT aliases: a real routes list is one entry per alias, and a
    // keyed array's identities must be unique.
    let mut second = item.clone();
    second.insert("model_alias".into(), Value::String("claude-haiku-4-5".into()));
    second.insert("upstream_model".into(), Value::String("claude-haiku-4-5".into()));
    phs.insert("routes".into(), Value::List(vec![item, second]));

    // Seed two MCP servers so `{{#each mcp_servers}}` bodies actually iterate
    // at validation time — same rationale as the `routes` list above.
    phs.insert(
        "mcp_servers".into(),
        Value::List(vec![mcp_server_item("fs", true), mcp_server_item("web", true)]),
    );

    phs
}

/// The client header every validation MCP server declares beside the gateway
/// key: a header the user's client sends itself (a client-filled input).
pub const FIXTURE_CLIENT_HEADER: &str = "X-Client-Token";

/// One validation `mcp_servers[]` item, shaped as the server's placeholder
/// builder shapes it. `gateway_key` puts the gateway key's
/// `Authorization: Bearer …` first in `headers` — a static-key template on the
/// `/mcp/<slug>` mount; without it the list carries the client header only, as
/// for a spec-OAuth template, whose client signs in instead.
pub fn mcp_server_item(slug: &str, gateway_key: bool) -> BTreeMap<String, Value> {
    let mut m: BTreeMap<String, Value> = BTreeMap::new();
    m.insert("slug".into(), Value::String(slug.into()));
    m.insert("name".into(), Value::String(format!("{slug} server")));
    m.insert("description".into(), Value::String(format!("{slug} mcp")));
    m.insert(
        "url".into(),
        Value::String(format!("https://gw.example.com/mcp/{slug}")),
    );
    // DELIBERATELY NOT `API_KEY_PLACEHOLDER`, which is what production
    // gateway mode actually puts here and in the gateway header. The
    // divergence is load-bearing: it is the only thing that lets a single
    // substring test tell the GATEWAY credential apart from an MCP key nested
    // inside an `{{#each mcp_servers}}` block, which is what both delivery
    // rules in `validate_profile` turn on. Aligning this with production would
    // silently gut them.
    let key = format!("<paste-your-{slug}-mcp-key-here>");
    let mut headers = Vec::new();
    if gateway_key {
        headers.push(mcp_header_item("Authorization", format!("Bearer {key}")));
    }
    headers.push(mcp_header_item(
        FIXTURE_CLIENT_HEADER,
        mcp_client_header_placeholder(slug, FIXTURE_CLIENT_HEADER),
    ));
    m.insert("api_key".into(), Value::String(key));
    m.insert("headers".into(), Value::List(headers));
    m.insert("fwd_prefix".into(), Value::String("https://gw.example.com/fwd/".into()));
    m.insert(
        "transport_hint".into(),
        Value::String("streamable_http".into()),
    );
    m.insert(
        "oauth_authorize_url".into(),
        Value::String(format!("https://gw.example.com/mcp/{slug}/oauth/authorize")),
    );
    // The `/mcp/<slug>` mount: `true` is the `/fwd/{key}/mcp/<slug>` one, which
    // a server whose client sends its own `Authorization` is reached on.
    m.insert("forward_auth".into(), Value::Bool(false));
    m.insert(
        "auth_mode".into(),
        Value::String(if gateway_key { "static" } else { "spec_oauth" }.into()),
    );
    m
}

/// The command of the validation local MCP server: a string no gateway item
/// and no template text holds, so its presence in a render is the local form
/// having written it.
pub const FIXTURE_LOCAL_COMMAND: &str = "fixture-local-mcp-runner";

/// The validation local MCP server, shaped as the server's placeholder builder
/// shapes one: arguments that need escaping in every format, arguments and a
/// value that read as a number or a boolean and must stay strings (`--port
/// 8080`, `--python 3.12`, `DEBUG=true`), and one variable left for the
/// developer.
pub fn mcp_local_item(slug: &str) -> BTreeMap<String, Value> {
    mcp_local_server_item(
        slug,
        &format!("{slug} server"),
        Some(&format!("{slug} local mcp")),
        FIXTURE_LOCAL_COMMAND,
        &[
            "-y".to_string(),
            "@scope/pkg@1.0.0".to_string(),
            "a \"quoted\" arg".to_string(),
            "--port".to_string(),
            "8080".to_string(),
            "--python".to_string(),
            "3.12".to_string(),
        ],
        &[
            ("LOG_LEVEL".to_string(), Some("info".to_string())),
            ("DEBUG".to_string(), Some("true".to_string())),
            ("API_TOKEN".to_string(), None),
        ],
    )
}

/// The validation placeholders a template is rendered with: the shared map,
/// plus — for a template that declares a local form, as the server merges a
/// local server only into such a template — one local MCP server appended to
/// `mcp_servers`.
pub fn validation_placeholders_for(template: &crate::types::ClientProfileTemplate) -> BTreeMap<String, Value> {
    let mut phs = validation_placeholders();
    append_local(&mut phs, template.local_mcp);
    phs
}

fn append_local(phs: &mut BTreeMap<String, Value>, form: LocalMcpForm) {
    if form.is_none() {
        return;
    }
    if let Some(Value::List(servers)) = phs.get_mut("mcp_servers")
        && !servers.is_empty()
    {
        servers.push(mcp_local_item("localfs"));
    }
}

/// The fixture's number-looking arguments and boolean-looking environment
/// value, as a YAML document must NOT hold them: the number 8080 or 3.12
/// anywhere, or a non-string under the key `DEBUG`. `None` when the document
/// holds neither.
fn retyped_local_value(doc: &yaml_serde::Value) -> Option<&'static str> {
    use yaml_serde::Value as Y;
    match doc {
        Y::Number(n) if n.as_f64().is_some_and(|f| f == 8080.0 || f == 3.12) => Some("argument"),
        Y::Sequence(items) => items.iter().find_map(retyped_local_value),
        Y::Mapping(map) => map.iter().find_map(|(k, v)| {
            if k.as_str() == Some("DEBUG") && !v.is_string() {
                return Some("environment value");
            }
            retyped_local_value(k).or_else(|| retyped_local_value(v))
        }),
        _ => None,
    }
}

/// Drop the optional, server-omittable placeholders (`context_window`,
/// `reasoning_effort`) from the top-level map AND every `routes` item, so the
/// validation exercises the `{{#if …}}`-absent branch of each template — a
/// self-hosted route resolves none of these, and a body that renders broken
/// config when they're missing must fail at build time, not in the field.
fn strip_optional_fields(phs: &mut BTreeMap<String, Value>) {
    for k in ["context_window", "reasoning_effort"] {
        phs.remove(k);
    }
    if let Some(Value::List(routes)) = phs.get_mut("routes") {
        for item in routes.iter_mut() {
            item.remove("context_window");
            item.remove("reasoning_effort");
        }
    }
}

/// Why a profile is not savable. Render failures are reported before the
/// delivery rules, so an unparseable body is never misreported as a delivery
/// problem.
#[derive(Debug, thiserror::Error)]
pub enum ProfileInvalid {
    /// A body, instructions block, or companion body failed to render, or
    /// produced invalid output for its declared format.
    #[error("template '{title}' failed validation: {error}")]
    Render { title: String, error: RenderError },
    /// An LLM-bearing template renders a config with the gateway key nowhere
    /// in it and no companion carries one — nor, for a print-only snippet, an
    /// LLM-bearing sibling.
    #[error(
        "template '{title}' renders an LLM config with no API key in it — add \
         {{{{api_key}}}} to the body, add a companion file that carries it, or set \
         key_delivery = \"environment\" if the tool reads the key from the shell"
    )]
    KeyUnreachable { title: String },
    /// A non-LLM template declares a companion carrying the GATEWAY key. That
    /// placeholder is never populated for such a render, so the file would
    /// land with an empty credential.
    #[error(
        "template '{title}' companion '{path}' uses the gateway key, but this template's \
         kind never resolves one — the file would be written with an empty credential"
    )]
    CompanionOutOfScope { title: String, path: String },
    /// A companion path the CLI would refuse, or should never be asked, to
    /// write. Checked here rather than at the write so a seed diff and an
    /// admin save both see it.
    #[error("template '{title}' companion path '{path}' is invalid: {reason}")]
    CompanionPathInvalid {
        title: String,
        path: String,
        reason: &'static str,
    },
    /// A declared keyed array the CLI could not merge entry by entry: the
    /// declaration itself is malformed, or a render puts something there that
    /// is not an array of objects each carrying a unique string identity.
    #[error("template '{title}' keyed array '{pointer}' is invalid: {reason}")]
    KeyedArrayInvalid {
        title: String,
        pointer: String,
        reason: String,
    },
    /// A template declares a local MCP form and a render handed a local server
    /// writes its command nowhere: the developer would be told the server is
    /// configured and find nothing.
    #[error(
        "template '{title}' declares local_mcp = \"{form}\" but a render with a local MCP server \
         writes its command nowhere — write it inside {{{{#each mcp_servers}}}} under {{{{#if local}}}}, \
         or remove the declaration"
    )]
    LocalMcpUnwritten { title: String, form: &'static str },
    /// A YAML template writes a local MCP server's argument or environment
    /// value where YAML reads it as a number or a boolean: `--port 8080` would
    /// reach the client as the integer 8080.
    #[error(
        "template '{title}' writes a local MCP server's {what} in a bare YAML position, where it is \
         read as a number or a boolean instead of a string — write it with {{{{quoted value}}}}"
    )]
    LocalMcpValueRetyped { title: String, what: &'static str },
    /// A template declares its local MCP form project-only and writes a local
    /// server outside a project too.
    #[error(
        "template '{title}' declares local_mcp = \"project\" but writes a local MCP server outside a \
         project scope — declare \"config\", or skip local items there with {{{{#unless local}}}}"
    )]
    LocalMcpOutsideProject { title: String },
}

/// What one template hands the user, observed on a real render rather than by
/// reading its source. Recorded on the gateway-mode pass only — see
/// [`validate_profile`].
#[derive(Default, Clone, Copy)]
struct Delivered {
    body: bool,
    instructions: bool,
    companion: bool,
}

impl Delivered {
    /// Whether a render of this template puts the gateway key in the user's
    /// hands. `Instructions` templates count their prose because prose is that
    /// template's whole deliverable (Cursor's settings-panel walkthrough).
    fn delivers(self, kind: TemplateKind) -> bool {
        self.body
            || self.companion
            || (matches!(kind, TemplateKind::Instructions) && self.instructions)
    }

    /// Keep only what BOTH passes delivered — a channel that carries the key
    /// on one optional-field shape and not the other does not deliver.
    fn and(self, other: Self) -> Self {
        Self {
            body: self.body && other.body,
            instructions: self.instructions && other.instructions,
            companion: self.companion && other.companion,
        }
    }
}

/// Why the CLI could not merge the array at `pointer` of this rendered `body`
/// entry by entry, keyed by `key` — `None` when it can. Checked on a RENDER
/// because what sits at the pointer is decided by the template's data, not its
/// source. An absent or null value is fine: the render then contributes no
/// entries, and the ones it wrote before are removed.
fn keyed_array_error(format: TemplateFormat, body: &str, pointer: &str, key: &str) -> Option<String> {
    if !pointer.starts_with('/') {
        return Some("must be a JSON pointer, e.g. `/models`".into());
    }
    if key.trim().is_empty() {
        return Some("names no identity field".into());
    }
    if key == crate::types::STRING_ENTRIES && matches!(format, TemplateFormat::Toml) {
        return Some("a TOML array of strings cannot be merged entry by entry".into());
    }
    // An unreadable render is refused here too, not waved through: the CLI's
    // writer parses the same body and would fail on every provision.
    let parsed: Option<serde_json::Value> = match format {
        TemplateFormat::Json => serde_json::from_str(body).ok(),
        TemplateFormat::Yaml => yaml_serde::from_str::<yaml_serde::Value>(body)
            .ok()
            .and_then(|v| serde_json::to_value(v).ok()),
        TemplateFormat::Toml => toml::from_str::<toml::Table>(body)
            .ok()
            .and_then(|v| serde_json::to_value(v).ok()),
        TemplateFormat::Shell | TemplateFormat::Text => {
            return Some(format!("a {format:?} file has no arrays to merge"));
        }
    };
    let Some(doc) = parsed else {
        return Some(format!("the render does not parse as {format:?}"));
    };
    let entries = match doc.pointer(pointer) {
        None | Some(serde_json::Value::Null) => return None,
        Some(serde_json::Value::Array(entries)) => entries,
        Some(_) => return Some("the render puts something other than an array there".into()),
    };
    // A scalar identifies an entry — a numeric-looking alias parses as a
    // number — as the CLI's writers read it.
    let mut seen: Vec<String> = Vec::new();
    for entry in entries {
        let Some(id) = crate::types::keyed_entry_identity(entry, key) else {
            return Some(if key == crate::types::STRING_ENTRIES {
                "an entry is not a string".into()
            } else {
                format!("an entry has no `{key}` to identify it by")
            });
        };
        if seen.contains(&id) {
            return Some(format!("two entries share `{key}` = {id:?}"));
        }
        seen.push(id);
    }
    None
}

/// Reject a companion path the CLI must never be handed. `path` is a literal
/// (never rendered), so this is decidable here.
fn companion_path_error(path: &str) -> Option<&'static str> {
    if path.trim().is_empty() {
        return Some("empty");
    }
    if path.split(['/', '\\']).any(|seg| seg == "..") {
        return Some("contains a `..` segment");
    }
    None
}

/// A declared project-scope path is relative to the project root and stays
/// under it.
fn companion_project_path_error(path: &str) -> Option<&'static str> {
    if path.trim().is_empty() {
        return Some("empty project path");
    }
    if path.trim() != path {
        return Some("project path starts or ends with a space");
    }
    if path.starts_with(['/', '\\', '~']) || path.chars().nth(1) == Some(':') {
        return Some("project path is not relative to the project");
    }
    if path.split(['/', '\\']).any(|seg| seg == "..") {
        return Some("project path contains a `..` segment");
    }
    if path.ends_with(['/', '\\']) || path.split(['/', '\\']).all(|seg| seg.is_empty() || seg == ".") {
        return Some("project path names a folder, not a file");
    }
    None
}

/// Validate a profile: every template — body, instructions and companions —
/// renders cleanly for its declared format, and every LLM-bearing template can
/// actually put the gateway key in the user's hands.
///
/// Rendering runs across the matrix of:
///   * `forward_auth` — gateway (`false`) and BYOK host-only (`true`), so a
///     `{{#unless forward_auth}}` block stays valid in either branch;
///   * optional-field presence — full placeholders AND the minimal set with the
///     optional fields stripped and no MCP server selected, so a body that
///     breaks when a route omits `context_window` / `reasoning_effort`, or
///     when a run wires no MCP server, fails here.
///
/// The two delivery rules read the **rendered** output of the gateway-mode
/// passes — the full-placeholder one AND the minimal one, which wires no MCP
/// server — never the template source. Two reasons, both of
/// which have bitten:
///   * a raw `contains("{{api_key}}")` cannot tell a gateway key from a
///     per-server MCP bearer nested in `{{#each mcp_servers}}` — gemini-cli's
///     LLM template carries only the latter, so a source scan passes it while
///     a render with no MCP servers selected delivers nothing at all;
///   * a source scan also misses `{{ api_key }}`, `{{{api_key}}}` and
///     `{{../api_key}}`, reading each as "does not deliver".
///
/// Gateway mode specifically: under BYOK the sentinel is embedded in
/// `base_url` (`/fwd/<sentinel>/v1`), so any body mentioning `{{base_url}}`
/// would "deliver" trivially and the rule would be vacuous.
pub fn validate_profile(profile: &ClientProfile) -> Result<(), ProfileInvalid> {
    // `None` until the first gateway pass fills it; later gateway passes AND
    // into it, so a template counts as delivering only where it delivers on
    // EVERY optional-field shape. A key reachable only under
    // `{{#if context_window}}` is not delivered by a self-hosted route that
    // resolves none of those fields — which is the shape `strip_optional_fields`
    // exists to exercise.
    let mut delivered: Vec<Option<Delivered>> = vec![None; profile.templates.len()];

    // `project_scope` is a third axis: a body that is broken only in its
    // project-local branch must fail here, not on a user's `--local` run.
    let passes = [false, true].into_iter().flat_map(|f| {
        [false, true].into_iter().flat_map(move |m| [false, true].map(|p| (f, m, p)))
    });
    for (forward_auth, minimal, project_scope) in passes {
        let mut phs = validation_placeholders();
        if minimal {
            strip_optional_fields(&mut phs);
            // A key reached only through an MCP server's loop
            // (`{{../api_key}}` inside `{{#each mcp_servers}}`) is not
            // delivered by a run that wires none.
            phs.insert("mcp_servers".into(), Value::List(Vec::new()));
        }
        phs.insert("forward_auth".into(), Value::Bool(forward_auth));
        phs.insert(crate::render::PROJECT_SCOPE.into(), Value::Bool(project_scope));
        // Delivery is read on the gateway passes only: under BYOK the
        // sentinel rides `base_url` (`/fwd/<sentinel>/v1`), so any body
        // mentioning `{{base_url}}` would "deliver" and the rule would be
        // vacuous.
        let observing = !forward_auth;

        for (i, tmpl) in profile.templates.iter().enumerate() {
            let fail = |error: RenderError| ProfileInvalid::Render {
                title: tmpl.title.clone(),
                error,
            };
            // A template that declares a local form is rendered with a local
            // server beside the gateway's (the minimal pass wires none).
            let with_local;
            let phs = if tmpl.local_mcp.is_none() {
                &phs
            } else {
                with_local = {
                    let mut p = phs.clone();
                    append_local(&mut p, tmpl.local_mcp);
                    p
                };
                &with_local
            };
            let body = crate::render::render(&tmpl.body, tmpl.format, phs).map_err(fail)?;
            let instructions = match tmpl.instructions.as_deref() {
                Some(text) => crate::render::render(text, TemplateFormat::Text, phs)
                    .map_err(fail)?,
                None => String::new(),
            };
            let companions =
                crate::companions::companion_files(tmpl, phs).map_err(fail)?;

            // A local server may be the only one selected: the same template
            // must render valid output with no gateway server before it (a
            // separator written for "the next gateway item" breaks only then).
            if !minimal && !tmpl.local_mcp.is_none() {
                let mut local_only = phs.clone();
                local_only.insert("mcp_servers".into(), Value::List(vec![mcp_local_item("localfs")]));
                crate::render::render(&tmpl.body, tmpl.format, &local_only).map_err(fail)?;
                crate::companions::companion_files(tmpl, &local_only).map_err(fail)?;
            }

            // A local server's arguments and values are strings, whatever
            // they read as. In YAML a bare position would retype the
            // fixture's `8080`, `3.12` and `true`.
            if !minimal && !tmpl.local_mcp.is_none() {
                let yaml_docs = std::iter::once((tmpl.format, body.as_str()))
                    .chain(companions.iter().map(|c| (c.format, c.body.as_str())))
                    .filter(|(format, _)| *format == TemplateFormat::Yaml);
                for (_, text) in yaml_docs {
                    if let Ok(doc) = yaml_serde::from_str::<yaml_serde::Value>(text)
                        && let Some(what) = retyped_local_value(&doc)
                    {
                        return Err(ProfileInvalid::LocalMcpValueRetyped { title: tmpl.title.clone(), what });
                    }
                }
            }

            // The declared local form is a claim about the render: a local
            // server's command lands in a file the CLI writes (the body, or a
            // companion with a path) in every scope the form names, and in no
            // file outside them.
            if !minimal && !tmpl.local_mcp.is_none() {
                let written = body.contains(FIXTURE_LOCAL_COMMAND)
                    || companions
                        .iter()
                        .filter(|c| c.path.is_some() || c.project_path.is_some())
                        .any(|c| c.body.contains(FIXTURE_LOCAL_COMMAND));
                let anywhere = written || companions.iter().any(|c| c.body.contains(FIXTURE_LOCAL_COMMAND));
                match (tmpl.local_mcp, project_scope) {
                    (LocalMcpForm::Config, _) | (LocalMcpForm::Project, true) if !written => {
                        return Err(ProfileInvalid::LocalMcpUnwritten {
                            title: tmpl.title.clone(),
                            form: if tmpl.local_mcp == LocalMcpForm::Config { "config" } else { "project" },
                        });
                    }
                    (LocalMcpForm::Project, false) if anywhere => {
                        return Err(ProfileInvalid::LocalMcpOutsideProject { title: tmpl.title.clone() });
                    }
                    _ => {}
                }
            }

            if observing {
                let seen = Delivered {
                    body: body.contains(API_KEY_PLACEHOLDER),
                    instructions: instructions.contains(API_KEY_PLACEHOLDER),
                    // A step (no path) is printed, never written: it
                    // delivers no key to the config the CLI writes.
                    companion: companions
                        .iter()
                        .filter(|c| c.path.is_some() || c.project_path.is_some())
                        .any(|c| c.body.contains(API_KEY_PLACEHOLDER)),
                };
                delivered[i] = Some(match delivered[i] {
                    None => seen,
                    Some(prev) => prev.and(seen),
                });
            }

            for (pointer, key) in &tmpl.keyed_arrays {
                if let Some(reason) = keyed_array_error(tmpl.format, &body, pointer, key) {
                    return Err(ProfileInvalid::KeyedArrayInvalid {
                        title: tmpl.title.clone(),
                        pointer: pointer.clone(),
                        reason,
                    });
                }
            }

            // Path and scope are pass-independent claims, checked on every
            // pass so a sentinel that only appears in one branch cannot
            // slip past.
            for (n, declared) in tmpl.companions.iter().enumerate() {
                let path_error = declared
                    .path
                    .as_deref()
                    .and_then(|path| companion_path_error(path).map(|reason| (path, reason)))
                    .or_else(|| {
                        let project = declared.project_path.as_deref()?;
                        let reason = if tmpl.project_filename.is_none() {
                            // The CLI writes no part of this template in a project.
                            Some("the template has no project form to place it in")
                        } else {
                            companion_project_path_error(project)
                        };
                        reason.map(|reason| (project, reason))
                    });
                if let Some((path, reason)) = path_error {
                    return Err(ProfileInvalid::CompanionPathInvalid {
                        title: tmpl.title.clone(),
                        path: path.to_string(),
                        reason,
                    });
                }
                // One file written twice: the CLI refuses the whole setup
                // ("writes … twice"). Paths are compared as the CLI places
                // them — untrimmed, component by component, a `.` component
                // ignored (`~/a//b`, `~/a/./b` and `./a` under a root are one
                // file each) — in both scopes: globally beside the template's
                // own `~/` file (a bare name is placed per platform, a
                // resolution not repeated here), and in a project, where a
                // companion moves under the project root
                // (`companion_project_path`) beside `project_filename`. The
                // CLI also resolves symlinks on the user's disk; no check here
                // can. A snippet (no path at all) is written nowhere.
                let as_path = |p: &str| -> std::path::PathBuf {
                    std::path::Path::new(p)
                        .components()
                        .filter(|c| !matches!(c, std::path::Component::CurDir))
                        .collect()
                };
                let path = declared.path.as_deref().map(as_path);
                let own = tmpl.filename.as_deref().filter(|f| f.starts_with("~/")).map(as_path);
                let in_project = |c: &crate::types::CompanionTemplate| {
                    companion_project_path(c.path.as_deref(), c.project_path.as_deref()).map(as_path)
                };
                let here = in_project(declared);
                let project_own = tmpl.project_filename.as_deref().map(as_path);
                let clash = (path.is_some() && own == path)
                    || (here.is_some() && here == project_own)
                    || tmpl.companions[..n].iter().any(|prev| {
                        (path.is_some() && prev.path.as_deref().map(as_path) == path)
                            || (here.is_some() && in_project(prev) == here)
                    });
                if clash {
                    return Err(ProfileInvalid::CompanionPathInvalid {
                        title: tmpl.title.clone(),
                        path: declared.path.clone().or_else(|| declared.project_path.clone()).unwrap_or_default(),
                        reason: "names a file the template already writes",
                    });
                }
            }
            // Rule B — an MCP-only template's companions never carry the
            // gateway key: a checked property of the data, not a branch in
            // `companion_files`.
            for c in &companions {
                if !tmpl.kind.needs_llm() && c.body.contains(API_KEY_PLACEHOLDER) {
                    return Err(ProfileInvalid::CompanionOutOfScope {
                        title: tmpl.title.clone(),
                        path: c.path.clone().unwrap_or_else(|| c.title.clone()),
                    });
                }
            }
        }
    }

    // Rule A — key deliverability. A template that writes a file must deliver
    // the key itself: the CLI writes that file and nothing else, so a key
    // shown only by a sibling never reaches it. A print-only snippet may lean
    // on an LLM-bearing sibling, since the Quickstart shows them side by side.
    let delivers = |t: &crate::types::ClientProfileTemplate, d: Option<Delivered>| {
        d.is_some_and(|d| d.delivers(t.kind))
    };
    let a_sibling_delivers = profile
        .templates
        .iter()
        .zip(&delivered)
        .any(|(t, d)| t.kind.needs_llm() && delivers(t, *d));

    for (tmpl, d) in profile.templates.iter().zip(&delivered) {
        if !tmpl.kind.needs_llm() || matches!(tmpl.key_delivery, KeyDelivery::Environment) {
            continue;
        }
        if !delivers(tmpl, *d) && (tmpl.filename.is_some() || !a_sibling_delivers) {
            return Err(ProfileInvalid::KeyUnreachable {
                title: tmpl.title.clone(),
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ClientProfileTemplate, CompanionTemplate, McpAuthMode};
    use std::path::Path;

    fn seed_dir() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../seeds/client_profiles")
    }

    /// Every `*.json` under `seeds/client_profiles`, parsed.
    fn seed_profiles() -> Vec<(std::path::PathBuf, ClientProfile)> {
        let entries = std::fs::read_dir(seed_dir())
            .unwrap_or_else(|e| panic!("read {}: {e}", seed_dir().display()));
        let mut out = Vec::new();
        for entry in entries {
            let path = entry.expect("dir entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let raw = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            let profile: ClientProfile = serde_json::from_str(&raw)
                .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
            out.push((path, profile));
        }
        out
    }

    fn seed(id: &str) -> ClientProfile {
        seed_profiles()
            .into_iter()
            .map(|(_, p)| p)
            .find(|p| p.id == id)
            .unwrap_or_else(|| panic!("no seed profile {id}"))
    }

    /// Render one template's single companion in the given auth mode.
    fn render_only_companion(t: &ClientProfileTemplate, forward_auth: bool) -> CompanionFileBody {
        let mut phs = validation_placeholders();
        phs.insert("forward_auth".into(), Value::Bool(forward_auth));
        if forward_auth {
            // BYOK: the credential the user pastes is their OWN upstream key,
            // and the gateway identity rides in the base URL's `/fwd/` path —
            // exactly what `populate_provider_placeholders` emits.
            phs.insert(
                "api_key".into(),
                Value::String(crate::render::UPSTREAM_API_KEY_PLACEHOLDER.into()),
            );
            phs.insert(
                "base_url".into(),
                Value::String(format!("https://gw.example.com/fwd/{API_KEY_PLACEHOLDER}/v1")),
            );
        }
        let mut rendered = crate::companions::companion_files(t, &phs).expect("renders");
        assert_eq!(rendered.len(), 1, "expected exactly one companion");
        let c = rendered.remove(0);
        CompanionFileBody { path: c.path.unwrap_or_default(), body: c.body }
    }

    struct CompanionFileBody {
        path: String,
        body: String,
    }

    fn template(kind: TemplateKind, body: &str) -> ClientProfileTemplate {
        ClientProfileTemplate {
            kind,
            protocol: None,
            route_tag: None,
            filename: None,
            project_filename: None,
            format: TemplateFormat::Shell,
            title: "t".into(),
            instructions: None,
            mcp_auth_mode: McpAuthMode::default(),
            key_delivery: KeyDelivery::default(),
            companions: Vec::new(),
            keyed_arrays: BTreeMap::new(),
            local_mcp: Default::default(),
            body: body.into(),
        }
    }

    fn profile(templates: Vec<ClientProfileTemplate>) -> ClientProfile {
        ClientProfile {
            id: "test".into(),
            label: "Test".into(),
            homepage: String::new(),
            supports_llm: true,
            supports_mcp: false,
            launch_command: None,
            templates,
            builtin: false,
        }
    }

    fn companion(path: &str, body: &str) -> CompanionTemplate {
        CompanionTemplate {
            path: Some(path.into()),
            project_path: None,
            format: TemplateFormat::Shell,
            title: "c".into(),
            instructions: String::new(),
            body: body.into(),
        }
    }

    // -----------------------------------------------------------------------
    // Seed-wide guards
    // -----------------------------------------------------------------------

    /// Every shipped seed client profile must render cleanly through the
    /// engine — including the `{{#each mcp_servers}}` multi-server MCP blocks
    /// and every declared companion. Runs in `cargo test` so template typos
    /// surface in the build, never in the end-to-end suite.
    #[test]
    fn seed_client_profiles_render() {
        let profiles = seed_profiles();
        for (path, profile) in &profiles {
            if let Err(e) = validate_profile(profile) {
                panic!("{}: {e}", path.display());
            }
        }
        assert!(
            profiles.len() >= 8,
            "expected >= 8 seed profiles, found {}",
            profiles.len()
        );
    }

    /// Every client that ships several LLM protocols defaults to its
    /// OpenAI-compatible template — it works on every upstream, whatever a
    /// provider load-balances across. The same function picks the CLI's
    /// default; the web quickstart's twin is locked by its own seed test.
    #[test]
    fn every_multi_protocol_client_defaults_to_chat_completions() {
        let mut multi = 0;
        for (path, profile) in seed_profiles() {
            let mut protocols: Vec<_> = profile
                .templates
                .iter()
                .filter(|t| matches!(t.kind, TemplateKind::Combined | TemplateKind::Llm))
                .map(|t| t.protocol.as_deref())
                .collect();
            protocols.sort();
            protocols.dedup();
            let Some(i) = crate::types::default_llm_template_index(&profile.templates, None) else {
                continue;
            };
            let chosen = &profile.templates[i];
            if protocols.len() < 2 {
                continue;
            }
            multi += 1;
            assert_eq!(
                chosen.protocol.as_deref(),
                Some("chat_completions"),
                "{}: default is {:?}",
                path.display(),
                chosen.title
            );
            assert!(
                chosen.filename.is_some() || profile.templates.iter().all(|t| t.filename.is_none()),
                "{}: default {:?} writes no file though a sibling does",
                path.display(),
                chosen.title
            );
        }
        // Positive control: aider, cline, continue, crush, opencode, curl-generic.
        assert!(multi >= 6, "expected >= 6 multi-protocol seed clients, found {multi}");
        // The rule is a preference, not the profile's order: opencode still
        // lists its Native Anthropic template first.
        let oc = seed("opencode");
        assert_eq!(oc.templates[0].protocol.as_deref(), Some("anthropic_messages"));
        assert_eq!(crate::types::default_llm_template_index(&oc.templates, None), Some(1));
    }

    #[test]
    fn the_default_prefers_the_static_key_one_of_an_auth_mode_pair() {
        let with = |protocol: &str, auth| {
            let mut t = template(TemplateKind::Combined, "");
            t.protocol = Some(protocol.into());
            t.mcp_auth_mode = auth;
            t
        };
        use McpAuthMode::{SpecOauth, Static};
        let oauth_first = [with("chat_completions", SpecOauth), with("chat_completions", Static)];
        assert_eq!(crate::types::default_llm_template_index(&oauth_first, None), Some(1));
        let native_only = [with("anthropic_messages", SpecOauth), with("anthropic_messages", Static)];
        assert_eq!(crate::types::default_llm_template_index(&native_only, None), Some(1));
        // A lone OAuth chat template still beats a static native one.
        let chat_oauth = [with("anthropic_messages", Static), with("chat_completions", SpecOauth)];
        assert_eq!(crate::types::default_llm_template_index(&chat_oauth, None), Some(1));
    }

    /// `provision` offers the project-or-global choice from the default
    /// template before a BYOK client's variant is re-picked for its
    /// pass-through: sound only while every file-writing LLM variant of one
    /// client has a project form exactly when the others do.
    #[test]
    fn a_clients_llm_variants_share_their_project_form() {
        for (path, profile) in seed_profiles() {
            let forms: Vec<bool> = profile
                .templates
                .iter()
                .filter(|t| matches!(t.kind, TemplateKind::Combined | TemplateKind::Llm) && t.filename.is_some())
                .map(|t| t.project_filename.is_some())
                .collect();
            assert!(forms.windows(2).all(|w| w[0] == w[1]), "{}: variants differ in project form", path.display());
        }
    }

    /// Against a BYOK pass-through the template speaking its protocol wins —
    /// the static-key one of a pair first — and a protocol the client has no
    /// template for falls back to the ordinary default.
    #[test]
    fn a_pass_through_defaults_to_the_template_speaking_its_protocol() {
        let with = |protocol: &str, auth| {
            let mut t = template(TemplateKind::Combined, "");
            t.protocol = Some(protocol.into());
            t.mcp_auth_mode = auth;
            t
        };
        use McpAuthMode::{SpecOauth, Static};
        let pick = |ts: &[ClientProfileTemplate], native| crate::types::default_llm_template_index(ts, native);
        let profile = [
            with("chat_completions", Static),
            with("anthropic_messages", SpecOauth),
            with("anthropic_messages", Static),
        ];
        assert_eq!(pick(&profile, Some("anthropic_messages")), Some(2));
        assert_eq!(pick(&profile, Some("google_gemini")), Some(0), "no gemini template: the ordinary default");
        assert_eq!(pick(&profile, None), Some(0));
        let oauth_only = [with("chat_completions", Static), with("anthropic_messages", SpecOauth)];
        assert_eq!(pick(&oauth_only, Some("anthropic_messages")), Some(1));
        // Every seed client that ships an Anthropic template lands on it.
        let cline = seed("cline");
        let i = pick(&cline.templates, Some("anthropic_messages")).expect("cline has a default");
        assert_eq!(cline.templates[i].protocol.as_deref(), Some("anthropic_messages"));
    }

    /// Aider's Native Anthropic config carries the gateway key and address in
    /// the file itself, and its `set-env` list merges by variable name.
    #[test]
    fn a_file_writing_aider_config_carries_its_key_and_address() {
        let aider = seed("aider");
        let anthropic = aider
            .templates
            .iter()
            .find(|t| t.filename.is_some() && t.protocol.as_deref() == Some("anthropic_messages"))
            .expect("aider's anthropic config");
        let mut phs = validation_placeholders();
        phs.insert("forward_auth".into(), Value::Bool(false));
        let out = crate::render::render(&anthropic.body, anthropic.format, &phs).expect("renders");
        let doc: yaml_serde::Value = yaml_serde::from_str(&out).expect("yaml");
        assert_eq!(doc["anthropic-api-key"].as_str(), Some(API_KEY_PLACEHOLDER));
        assert_eq!(
            doc["set-env"][0].as_str(),
            Some("ANTHROPIC_API_BASE=https://gw.example.com"),
            "{out}"
        );
        assert_eq!(
            anthropic.keyed_arrays.get("/set-env").map(String::as_str),
            Some(crate::types::STRING_ENTRIES)
        );
    }

    /// Each Aider config file ships `~/.aider.model.metadata.json`, naming
    /// the models the config selects (by the same provider-prefixed id): the
    /// main model with the route's output cap and, when known, its window, and
    /// a distinct weak model on its own. Aider looks a model up there before
    /// anywhere else: with no entry it warns of an unknown window on every
    /// start and downloads a public model list. Every key is named once (the
    /// weak model is the main one until an admin fills the fast slot). A BYOK
    /// render ships none — the gateway does not know the model the user names.
    #[test]
    fn every_aider_config_names_its_models_window_beside_it() {
        let aider = seed("aider");
        let configs: Vec<_> = aider.templates.iter().filter(|t| t.format == TemplateFormat::Yaml).collect();
        assert_eq!(configs.len(), 2);
        for t in configs {
            // (fast slot, window known): a distinct fast model, the main model
            // in both slots, and a route with no known window.
            for (fast, window) in [("claude-haiku-4-5", true), ("qwen3:8b", true), ("claude-haiku-4-5", false)] {
                let mut phs = validation_placeholders();
                phs.insert("forward_auth".into(), Value::Bool(false));
                phs.insert("model_alias".into(), Value::String("qwen3:8b".into()));
                phs.insert("model_slot_fast".into(), Value::String(fast.into()));
                if !window {
                    phs.remove("context_window");
                }
                let config: yaml_serde::Value =
                    yaml_serde::from_str(&crate::render::render(&t.body, t.format, &phs).unwrap()).unwrap();
                let model = config["model"].as_str().unwrap().to_string();
                let weak = config["weak-model"].as_str().unwrap().to_string();
                let companions = crate::companions::companion_files(t, &phs).expect("renders");
                let [meta] = companions.as_slice() else { panic!("{}: {companions:?}", t.title) };
                assert_eq!(meta.path.as_deref(), Some("~/.aider.model.metadata.json"));
                let doc: serde_json::Value = serde_json::from_str(&meta.body).expect("json");
                let provider = model.split('/').next().unwrap();
                assert_eq!(doc[&model]["litellm_provider"].as_str(), Some(provider), "{}", meta.body);
                assert_eq!(doc[&model]["max_input_tokens"].as_i64(), window.then_some(200_000), "{}", meta.body);
                assert_eq!(doc[&model]["max_output_tokens"].as_i64(), Some(200_000), "{}", meta.body);
                assert_eq!(doc[&weak]["litellm_provider"].as_str(), Some(provider), "{}", meta.body);
                // One entry per distinct model, each key written once.
                let entries = doc.as_object().unwrap().len();
                assert_eq!(entries, if weak == model { 1 } else { 2 }, "{}", meta.body);
                assert_eq!(meta.body.matches("\"litellm_provider\"").count(), entries, "{}", meta.body);
            }
            let mut byok = validation_placeholders();
            byok.insert("forward_auth".into(), Value::Bool(true));
            assert!(crate::companions::companion_files(t, &byok).expect("renders").is_empty(), "{}", t.title);
        }
    }

    #[test]
    fn a_string_keyed_array_is_identified_by_the_name_before_its_equals_sign() {
        let check = |format, body: &str| keyed_array_error(format, body, "/e", "=");
        assert_eq!(check(TemplateFormat::Yaml, "e:\n  - A=1\n  - B=2\n  - C\n"), None);
        assert_eq!(check(TemplateFormat::Json, r#"{"e": ["openai", "x"]}"#), None);
        // Two entries setting one name, an entry that is not a string, TOML.
        assert!(check(TemplateFormat::Yaml, "e:\n  - A=1\n  - A=2\n").is_some());
        assert!(check(TemplateFormat::Json, r#"{"e": ["x", "x"]}"#).is_some());
        assert!(check(TemplateFormat::Yaml, "e:\n  - name: a\n").is_some());
        assert!(check(TemplateFormat::Toml, "e = [\"A=1\"]\n").is_some());
        assert!(check(TemplateFormat::Toml, "x = 1\n").is_some(), "refused even where unrendered");
    }

    /// A key reached only inside the MCP servers' loop is not delivered by a
    /// run that wires no MCP server.
    #[test]
    fn a_key_only_inside_the_mcp_loop_does_not_deliver() {
        let body = "{{#each mcp_servers}}K={{../api_key}}\n{{/each}}BASE={{base_url}}\n";
        let mut t = template(TemplateKind::Combined, body);
        t.filename = Some("~/.tool.env".into());
        assert!(matches!(
            validate_profile(&profile(vec![t.clone()])),
            Err(ProfileInvalid::KeyUnreachable { .. })
        ));
        // Positive control: the same key outside the loop delivers.
        t.body = "K={{api_key}}\nBASE={{base_url}}\n".into();
        assert!(validate_profile(&profile(vec![t])).is_ok());
    }

    /// `ssai provision --template <client>=<variant>` picks by the
    /// derived name; among the templates that write a file it must name one.
    #[test]
    fn variant_names_are_unique_among_file_writing_templates() {
        let mut oauth = 0;
        for (path, profile) in seed_profiles() {
            let mut seen = std::collections::BTreeSet::new();
            for t in profile.templates.iter().filter(|t| t.filename.is_some()) {
                let name = t.variant_name();
                oauth += usize::from(name.ends_with("-oauth"));
                assert!(
                    seen.insert(name.clone()),
                    "{}: two file-writing templates are both {name:?}",
                    path.display()
                );
            }
        }
        // Positive control: the spec-OAuth siblings (claude-code, cursor) are
        // what the suffix exists for.
        assert!(oauth >= 2, "expected >= 2 -oauth variants, found {oauth}");
    }

    #[test]
    fn variant_name_follows_protocol_kind_and_auth() {
        let named = |kind, protocol: Option<&str>, auth| {
            let mut t = template(kind, "");
            t.protocol = protocol.map(str::to_string);
            t.mcp_auth_mode = auth;
            t.variant_name()
        };
        use McpAuthMode::{SpecOauth, Static};
        assert_eq!(named(TemplateKind::Combined, Some("chat_completions"), Static), "chat");
        assert_eq!(named(TemplateKind::Llm, Some("responses"), Static), "responses");
        assert_eq!(named(TemplateKind::Combined, Some("anthropic_messages"), Static), "anthropic");
        assert_eq!(named(TemplateKind::Llm, Some("google_gemini"), Static), "gemini");
        assert_eq!(
            named(TemplateKind::Combined, Some("anthropic_messages"), SpecOauth),
            "anthropic-oauth"
        );
        assert_eq!(named(TemplateKind::Mcp, None, Static), "mcp");
        assert_eq!(named(TemplateKind::Mcp, None, SpecOauth), "mcp-oauth");
        assert_eq!(named(TemplateKind::Instructions, None, Static), "instructions");
    }

    fn str_of(phs: &BTreeMap<String, Value>, key: &str) -> String {
        match &phs[key] {
            Value::String(s) => s.clone(),
            _ => panic!("{key} is not a string placeholder"),
        }
    }

    /// Every client with more than one model setting names the gateway's
    /// slot models where it reads them: the fast model for its background
    /// work, the plan model for its planner. Validation gives each slot a
    /// distinct value, so a setting rendered from the wrong slot shows.
    #[test]
    fn every_multi_model_client_names_its_slot_models() {
        let phs = validation_placeholders();
        let (default, fast, plan) =
            (str_of(&phs, "model_slot_default"), str_of(&phs, "model_slot_fast"), str_of(&phs, "model_slot_plan"));
        assert!(default != fast && fast != plan && default != plan);
        let rendered = |client: &str| -> Vec<String> {
            let profile = seed(client);
            let bodies: Vec<String> = profile
                .templates
                .iter()
                // A template that names no model (a shell export of the
                // address and key) has no slot to name either. A model may be
                // spliced alone or joined to a prefix (`{{concat "openai/" model_alias}}`).
                .filter(|t| t.kind.needs_llm() && t.body.contains("model_alias"))
                .map(|t| {
                    let mut phs = validation_placeholders();
                    phs.insert("forward_auth".into(), Value::Bool(false));
                    crate::render::render(&t.body, t.format, &phs).expect("renders")
                })
                .collect();
            assert!(!bodies.is_empty(), "{client}: no LLM template");
            bodies
        };
        for body in rendered("claude-code") {
            let env = &serde_json::from_str::<serde_json::Value>(&body).unwrap()["env"];
            assert_eq!(env["ANTHROPIC_DEFAULT_SONNET_MODEL"], default.as_str());
            assert_eq!(env["ANTHROPIC_DEFAULT_OPUS_MODEL"], plan.as_str());
            assert_eq!(env["ANTHROPIC_DEFAULT_HAIKU_MODEL"], fast.as_str());
            assert!(env.get("ANTHROPIC_SMALL_FAST_MODEL").is_none(), "the deprecated variable is gone");
        }
        for body in rendered("crush") {
            let doc: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert!(doc.get("default_model").is_none(), "Crush has no `default_model` key");
            assert_eq!(doc["models"]["large"]["model"], default.as_str());
            assert_eq!(doc["models"]["small"]["model"], fast.as_str());
            let provider = doc["models"]["small"]["provider"].as_str().unwrap();
            assert!(doc["providers"].get(provider).is_some(), "the slot names a provider the file defines");
        }
        for body in rendered("zed") {
            let agent = &serde_json::from_str::<serde_json::Value>(&body).unwrap()["agent"];
            // The agent's own model is the user's pick in the Agent Panel, which
            // Zed saves to `default_model`: a template owning it would undo it.
            assert!(agent.get("default_model").is_none(), "{agent}");
            assert_eq!(agent["commit_message_model"]["model"], fast.as_str());
            assert_eq!(agent["thread_summary_model"]["model"], fast.as_str());
        }
        let mut aider_shell = 0;
        for body in rendered("aider") {
            // The shell variant exports the weak model; the config files name it.
            let weak = match body.lines().find_map(|l| l.strip_prefix("export AIDER_WEAK_MODEL=")) {
                Some(weak) => {
                    aider_shell += 1;
                    weak.to_string()
                }
                None => {
                    let doc: yaml_serde::Value = yaml_serde::from_str(&body).unwrap();
                    doc["weak-model"].as_str().unwrap().to_string()
                }
            };
            assert!(weak.ends_with(&format!("/{fast}")), "{weak}");
        }
        assert_eq!(aider_shell, 1, "aider's shell variant names its weak model");
        for body in rendered("goose") {
            let doc: yaml_serde::Value = yaml_serde::from_str(&body).unwrap();
            assert_eq!(doc["GOOSE_PLANNER_MODEL"].as_str(), Some(plan.as_str()));
            assert_eq!(doc["GOOSE_PLANNER_PROVIDER"], doc["GOOSE_PROVIDER"]);
        }
    }

    /// A model id reaches every shipped YAML config as the client must read
    /// it, whatever characters it holds. The YAML escape quotes a value that
    /// needs it (an Ollama tag `llama3.1:8b`, the BYOK `<your-model-name>`
    /// sentinel) as a WHOLE scalar, so a template writing literal text beside a
    /// placeholder (`openai/{{model_alias}}`) ships `openai/"llama3.1:8b"` — a
    /// model no route serves. Such a value is built with `concat`. Every body
    /// and companion, on every pass, is rendered with ids that force quoting,
    /// top-level and per route.
    #[test]
    fn a_model_id_needing_quotes_reaches_every_yaml_config_unquoted() {
        fn strings(v: &yaml_serde::Value, out: &mut Vec<String>) {
            match v {
                yaml_serde::Value::String(s) => out.push(s.clone()),
                yaml_serde::Value::Sequence(items) => items.iter().for_each(|i| strings(i, out)),
                yaml_serde::Value::Mapping(map) => map.iter().for_each(|(k, v)| {
                    strings(k, out);
                    strings(v, out);
                }),
                _ => {}
            }
        }
        let mut phs = validation_placeholders();
        let mut planted = Vec::new();
        for (k, v) in [
            ("model_alias", "alias:1"),
            ("model_slot_default", "default:1"),
            ("model_slot_fast", "fast:1"),
            ("model_slot_plan", "plan:1"),
            ("upstream_model", "upstream:1"),
        ] {
            phs.insert(k.into(), Value::String(v.into()));
            planted.push(v.to_string());
        }
        if let Some(Value::List(routes)) = phs.get_mut("routes") {
            for (n, route) in routes.iter_mut().enumerate() {
                for k in ["model_alias", "upstream_model"] {
                    let id = format!("route-{n}:{k}");
                    route.insert(k.into(), Value::String(id.clone()));
                    planted.push(id);
                }
            }
        }
        let mut checked = 0;
        let mut aider_models = 0;
        for (path, profile) in seed_profiles() {
            for (forward_auth, project_scope) in [(false, false), (false, true), (true, false), (true, true)] {
                phs.insert("forward_auth".into(), Value::Bool(forward_auth));
                phs.insert(crate::render::PROJECT_SCOPE.into(), Value::Bool(project_scope));
                for t in &profile.templates {
                    let mut outputs = Vec::new();
                    if t.format == TemplateFormat::Yaml {
                        outputs.push(
                            crate::render::render(&t.body, t.format, &phs)
                                .unwrap_or_else(|e| panic!("{}: {e}", path.display())),
                        );
                    }
                    for c in crate::companions::companion_files(t, &phs)
                        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
                    {
                        if c.format == TemplateFormat::Yaml {
                            outputs.push(c.body);
                        }
                    }
                    for body in outputs {
                        let doc: yaml_serde::Value = yaml_serde::from_str(&body).unwrap();
                        let mut values = Vec::new();
                        strings(&doc, &mut values);
                        for value in &values {
                            assert!(
                                !planted.iter().any(|id| value.contains(&format!("\"{id}\""))),
                                "{}: `{value}` keeps the escape's quotes:\n{body}",
                                path.display()
                            );
                        }
                        if profile.id == "aider" && !forward_auth {
                            assert!(values.iter().any(|v| v.ends_with("/alias:1")), "{body}");
                            assert!(values.iter().any(|v| v.ends_with("/fast:1")), "{body}");
                            aider_models += 1;
                        }
                        checked += 1;
                    }
                }
            }
        }
        // Positive control: the planted ids did reach Aider's two YAML configs
        // (on both gateway passes), so the walk saw the values it judges.
        assert_eq!(aider_models, 4, "aider ships two YAML configs");
        assert!(checked > aider_models, "only {checked} YAML outputs checked");
    }

    /// OpenCode 2 resolves a model per agent, and a home-directory
    /// `agents.<id>.model` pin outranks a project's top-level `model`, so a
    /// project form that names only `model` still runs `build`, `plan`, … on
    /// the user's global provider. Both forms therefore pin every built-in
    /// agent to the provisioned provider and model: in the global form a pin
    /// the user left on a built-in agent would send `opencode` elsewhere just
    /// the same. Both forms deny OpenCode's own hosted provider, whose free
    /// models would otherwise be offered beside the gateway's. The project form
    /// states nothing else: policies are evaluated broadest config last, so a
    /// project pair can neither lift a global deny nor hide a global allow.
    /// The deny comes first, so the merge keeps the allow last. The global form appends one
    /// statement allowing its provider: inside one file the last
    /// matching statement wins, so it lifts a user's `deny *` written before
    /// it. `update` is honoured only in the global file, so only the global
    /// form carries it — a project copy would read as a guarantee OpenCode does
    /// not give.
    #[test]
    fn opencode_pins_every_agent_and_allows_its_provider_at_home() {
        // The built-in agent set of OpenCode 2 (`plugin/agent.ts` + `plugin/plan.ts`).
        const BUILTIN_AGENTS: [&str; 7] =
            ["build", "plan", "general", "explore", "compaction", "title", "summary"];
        let profile = seed("opencode");
        let mut checked = 0;
        for t in profile.templates.iter().filter(|t| t.kind.needs_llm()) {
            for project_scope in [false, true] {
                let mut phs = validation_placeholders();
                phs.insert("forward_auth".into(), Value::Bool(false));
                phs.insert(crate::render::PROJECT_SCOPE.into(), Value::Bool(project_scope));
                let body = crate::render::render(&t.body, t.format, &phs).expect("renders");
                let doc: serde_json::Value = serde_json::from_str(&body).expect("json");
                let (provider_key, alias) =
                    doc["model"].as_str().expect("model").split_once('/').expect("provider/model");
                assert!(doc["providers"].get(provider_key).is_some(), "{}", t.title);
                let agents = doc["agents"].as_object().expect("every form pins agents");
                let mut ids: Vec<&str> = agents.keys().map(String::as_str).collect();
                ids.sort_unstable();
                let mut want = BUILTIN_AGENTS;
                want.sort_unstable();
                assert_eq!(ids, want, "{}", t.title);
                for (id, agent) in agents {
                    let slot = match id.as_str() {
                        "plan" => "model_slot_plan",
                        "title" | "explore" => "model_slot_fast",
                        _ => "model_alias",
                    };
                    let want = str_of(&phs, slot);
                    assert_eq!(
                        agent["model"],
                        serde_json::json!({ "providerID": provider_key, "model": want }),
                        "{}: agent {id}",
                        t.title
                    );
                }
                assert_eq!(alias, str_of(&phs, "model_alias"), "{}", t.title);
                if project_scope {
                    assert_eq!(
                        doc["experimental"]["policies"],
                        serde_json::json!([
                            {"action": "provider.use", "resource": "opencode", "effect": "deny"},
                        ]),
                        "{}",
                        t.title
                    );
                    assert!(doc.get("update").is_none(), "{}: project form carries update", t.title);
                    assert_eq!(
                        t.project_filename.as_deref(),
                        Some(".opencode/opencode.json"),
                        "{}",
                        t.title
                    );
                } else {
                    assert_eq!(
                        doc["experimental"]["policies"],
                        serde_json::json!([
                            {"action": "provider.use", "resource": "opencode", "effect": "deny"},
                            {"action": "provider.use", "resource": provider_key, "effect": "allow"},
                        ]),
                        "{}",
                        t.title
                    );
                    assert_eq!(doc["update"], "disable", "{}", t.title);
                }
                assert!(t.keyed_arrays.contains_key("/experimental/policies"), "{}", t.title);
            }
            checked += 1;
        }
        assert_eq!(checked, 2, "both opencode LLM variants are checked");
    }

    /// Every OpenCode render is the v2 native shape: a provider on a built-in
    /// package with `settings`, models declaring `capabilities`, and MCP
    /// servers under `mcp.servers` with Code Mode off (so the gateway's tool
    /// policy sees each MCP call by name) and OAuth off (the static bearer is
    /// the credential). No v1 key survives — v2 drops `reasoning` and
    /// `attachment` and would read `npm`/`options`/`enabled` as a v1 file.
    #[test]
    fn opencode_renders_the_v2_native_shape() {
        let profile = seed("opencode");
        let mut servers = 0;
        for (t, project_scope) in profile.templates.iter().flat_map(|t| [(t, false), (t, true)]) {
            let mut phs = validation_placeholders();
            phs.insert("forward_auth".into(), Value::Bool(false));
            phs.insert(crate::render::PROJECT_SCOPE.into(), Value::Bool(project_scope));
            let body = crate::render::render(&t.body, t.format, &phs).expect("renders");
            let doc: serde_json::Value = serde_json::from_str(&body).expect("json");
            for v1_key in ["provider", "autoupdate", "enabled_providers", "$schema"] {
                assert!(doc.get(v1_key).is_none(), "{}: v1 key {v1_key}", t.title);
            }
            // Nothing leaves for OpenCode's own services by default: no session
            // sharing, and its own web search off and not offered to the model.
            assert_eq!(doc["share"], "disabled", "{}", t.title);
            assert_eq!(doc["websearch"], false, "{}", t.title);
            assert!(
                doc["permissions"].as_array().is_some_and(|p| p.contains(&serde_json::json!(
                    {"action": "websearch", "resource": "*", "effect": "deny"}
                ))),
                "{}: websearch is still offered",
                t.title
            );
            assert!(t.keyed_arrays.contains_key("/permissions"), "{}: user permissions would be replaced", t.title);
            if t.kind.needs_llm() {
                let (_, provider) = doc["providers"].as_object().unwrap().iter().next().unwrap();
                assert!(provider["package"].as_str().unwrap().starts_with("@opencode/ai/providers/"));
                assert!(provider["settings"]["apiKey"].is_string(), "{}", t.title);
                assert!(provider["settings"]["baseURL"].is_string(), "{}", t.title);
                for (alias, model) in provider["models"].as_object().unwrap() {
                    assert!(model["capabilities"]["tools"].is_boolean(), "{}: {alias}", t.title);
                    assert_eq!(model["capabilities"]["input"][0], "text", "{}: {alias}", t.title);
                    for v1_key in ["tool_call", "reasoning", "attachment", "modalities"] {
                        assert!(model.get(v1_key).is_none(), "{}: {alias} carries {v1_key}", t.title);
                    }
                }
            }
            for (slug, server) in doc["mcp"]["servers"].as_object().expect("mcp.servers") {
                assert_eq!(server["type"], "remote", "{}: {slug}", t.title);
                assert_eq!(server["oauth"], false, "{}: {slug}", t.title);
                assert_eq!(server["codemode"], false, "{}: {slug}", t.title);
                assert!(server["headers"]["Authorization"].as_str().unwrap().starts_with("Bearer "));
                assert!(server.get("enabled").is_none(), "{}: {slug}", t.title);
                servers += 1;
            }
        }
        assert_eq!(servers, 12, "two servers in each of the three templates, in both scopes");
    }

    /// A client the render mints a key for must have somewhere to PUT it.
    ///
    /// The defect this closes shipped: Goose reads its credential from
    /// `secrets.yaml`, so `config.yaml` carries no `{{api_key}}` — the CLI
    /// wrote the companion from a hardcoded arm of its own and the web
    /// quickstart, which knew nothing about companions, rendered a config file
    /// with the key nowhere in it. Nothing failed; the user just got a config
    /// that could not authenticate.
    ///
    /// The rule now lives in `validate_profile` and runs on every admin save
    /// too, so this test's job is to prove it still BITES on the seed tree:
    /// stripping a companion from a keyless LLM profile must fail.
    #[test]
    fn every_llm_template_can_deliver_its_key() {
        // Positive control: the rule is only meaningful if the seed tree still
        // contains LLM templates whose own body carries no key. Counting them
        // is what stops this test passing because the scan stopped finding
        // anything to check.
        let mut keyless = 0;
        for (_, profile) in seed_profiles() {
            let mut phs = validation_placeholders();
            phs.insert("forward_auth".into(), Value::Bool(false));
            for tmpl in &profile.templates {
                if !tmpl.kind.needs_llm() {
                    continue;
                }
                let body = crate::render::render(&tmpl.body, tmpl.format, &phs).expect("renders");
                if !body.contains(API_KEY_PLACEHOLDER) {
                    keyless += 1;
                }
            }
        }
        assert!(
            keyless >= 3,
            "expected >= 3 keyless LLM templates in the seed tree, found {keyless} — the scan \
             stopped finding them rather than the templates gaining inline keys"
        );

        // The guard bites: take a shipped profile that depends on its
        // companion, remove the companion, and the rule must reject it.
        let mut goose = seed("goose");
        assert!(
            !goose.templates[0].companions.is_empty(),
            "goose is the fixture for this check because its key lives in a companion"
        );
        goose.templates[0].companions.clear();
        assert!(
            matches!(
                validate_profile(&goose),
                Err(ProfileInvalid::KeyUnreachable { .. })
            ),
            "removing goose's companion must make the profile unsavable"
        );
    }

    /// Every seed profile must declare which client release/schema its
    /// templates were last validated against. The field is a seed-file
    /// annotation only (the runtime `ClientProfile` drops it) — its job is to
    /// make config-schema drift reviewable: a client that changes its config
    /// format on its own cadence (e.g. gemini-cli's `selectedAuthType` →
    /// `security.auth.selectedType` move) leaves the recorded version stale,
    /// flagging the template for a re-check. A new profile can't land without
    /// stating what it targets.
    #[test]
    fn every_seed_declares_targeted_client_version() {
        let entries = std::fs::read_dir(seed_dir()).expect("read seed dir");
        let mut checked = 0;
        for entry in entries {
            let path = entry.expect("dir entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let raw = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            let value: serde_json::Value = serde_json::from_str(&raw)
                .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
            let version = value.get("targeted_client_version").and_then(|v| v.as_str());
            assert!(
                version.is_some_and(|s| !s.trim().is_empty()),
                "{}: missing/empty `targeted_client_version` — record the client \
                 release or schema date this profile was validated against",
                path.display()
            );
            checked += 1;
        }
        assert!(checked >= 8, "expected >= 8 seed profiles, found {checked}");
    }

    // -----------------------------------------------------------------------
    // Byte-exact output of the three companions that used to be Rust constants.
    // These assert the SHIPPED seed's render, not a fixture copy, so they prove
    // the migration from `format!` to the template engine preserved the bytes.
    // -----------------------------------------------------------------------

    /// Replaces the constant at the former `companions.rs` goose arm. The seed
    /// body is a BARE scalar (`OPENAI_API_KEY: {{api_key}}`) because
    /// `yaml_escape` quotes any value containing `<`/`>` — writing the quotes
    /// by hand would double them and fail the post-render YAML parse.
    #[test]
    fn goose_secrets_yaml_renders_the_quoted_scalar() {
        let goose = seed("goose");
        let gateway = render_only_companion(&goose.templates[0], false);
        assert_eq!(gateway.path, "~/.config/goose/secrets.yaml");
        assert_eq!(
            gateway.body,
            format!("OPENAI_API_KEY: \"{API_KEY_PLACEHOLDER}\"\n")
        );

        let byok = render_only_companion(&goose.templates[0], true);
        assert_eq!(
            byok.body,
            format!(
                "OPENAI_API_KEY: \"{}\"\n",
                crate::render::UPSTREAM_API_KEY_PLACEHOLDER
            )
        );
    }

    /// Goose resolves the provider from `active_provider` before the flat
    /// `GOOSE_PROVIDER`, and the model from `providers.<active>.model` before
    /// `GOOSE_MODEL` (`config/providers.rs`, `get_active_provider` /
    /// `get_active_model`). A user config Goose itself wrote carries the
    /// structured keys, so a render naming the model only in `GOOSE_MODEL`
    /// runs the user's old model. Every field Goose reads the model or the
    /// provider from must name the provisioned one.
    #[test]
    fn goose_names_the_provisioned_model_in_every_field_goose_reads() {
        let goose = seed("goose");
        let t = &goose.templates[0];
        let mut phs = validation_placeholders();
        phs.insert("forward_auth".into(), Value::Bool(false));
        let body = crate::render::render(&t.body, t.format, &phs).expect("renders");
        let doc: yaml_serde::Value = yaml_serde::from_str(&body).expect("yaml");
        // `model_alias` in `validation_placeholders`.
        let alias = "claude-sonnet-4-5";
        assert_eq!(doc["active_provider"].as_str(), Some("openai"), "{body}");
        assert_eq!(doc["GOOSE_PROVIDER"].as_str(), Some("openai"), "{body}");
        assert_eq!(doc["providers"]["openai"]["model"].as_str(), Some(alias), "{body}");
        assert_eq!(doc["providers"]["openai"]["enabled"].as_bool(), Some(true), "{body}");
        assert_eq!(doc["GOOSE_MODEL"].as_str(), Some(alias), "{body}");
    }

    /// Continue validates a remote MCP server's `type` against `sse` |
    /// `streamable-http` (its config schema, `@continuedev/cli` 1.5) and
    /// rejects the whole config on any other value — the CLI then refuses to
    /// start. Every template that writes `mcpServers` must use one of the two.
    #[test]
    fn continue_mcp_servers_use_a_transport_continue_accepts() {
        let profile = seed("continue");
        let mut servers = 0;
        for t in &profile.templates {
            let mut phs = validation_placeholders();
            phs.insert("forward_auth".into(), Value::Bool(false));
            let body = crate::render::render(&t.body, t.format, &phs).expect("renders");
            let doc: yaml_serde::Value = yaml_serde::from_str(&body).expect("yaml");
            for server in doc["mcpServers"].as_sequence().into_iter().flatten() {
                let ty = server["type"].as_str();
                std::assert_matches!(ty, Some("sse" | "streamable-http"), "{}", t.title);
                assert!(server["url"].as_str().is_some(), "{}", t.title);
                servers += 1;
            }
        }
        assert!(servers >= 2, "no template rendered an MCP server ({servers})");
    }

    /// Every config the gateway writes turns the client's own vendor traffic
    /// off — telemetry, usage statistics, crash reports, update checks — in
    /// every template, both auth modes and both scopes. This holds that each
    /// template renders its knobs; that the client reads them is a fact about
    /// its release, settled against its reference and binary when the knob
    /// is added. A client whose config file has no such knob (Continue,
    /// Cline, Cursor) has no row. OpenCode's are held by
    /// `opencode_renders_the_v2_native_shape`.
    #[test]
    fn every_provisioned_config_turns_the_clients_vendor_traffic_off() {
        use serde_json::json;
        fn doc_of(format: TemplateFormat, s: &str) -> serde_json::Value {
            match format {
                TemplateFormat::Json => serde_json::from_str(s).expect("json"),
                TemplateFormat::Toml => serde_json::to_value(s.parse::<toml::Table>().expect("toml")).unwrap(),
                TemplateFormat::Yaml => {
                    serde_json::to_value(yaml_serde::from_str::<yaml_serde::Value>(s).expect("yaml")).unwrap()
                }
                // `KEY=VALUE` lines, `export` or not: every value a string.
                _ => serde_json::Value::Object(
                    s.lines()
                        .filter_map(|l| l.trim_start_matches("export ").split_once('='))
                        .map(|(k, v)| (k.to_string(), json!(v)))
                        .collect(),
                ),
            }
        }
        let off: &[(&str, &[(&str, serde_json::Value)])] = &[
            ("claude-code", &[("/env/CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", json!("1"))]),
            (
                "gemini-cli",
                &[
                    ("/privacy/usageStatisticsEnabled", json!(false)),
                    ("/general/enableAutoUpdate", json!(false)),
                    ("/general/enableAutoUpdateNotification", json!(false)),
                ],
            ),
            (
                "codex",
                &[
                    ("/check_for_update_on_startup", json!(false)),
                    ("/analytics/enabled", json!(false)),
                    ("/feedback/enabled", json!(false)),
                    ("/otel/metrics_exporter", json!("none")),
                ],
            ),
            (
                "crush",
                &[("/options/disable_metrics", json!(true)), ("/options/disable_provider_auto_update", json!(true))],
            ),
            ("goose", &[("/GOOSE_TELEMETRY_ENABLED", json!(false))]),
            (
                "vibe",
                &[
                    ("/enable_telemetry", json!(false)),
                    ("/enable_update_checks", json!(false)),
                    ("/enable_auto_update", json!(false)),
                ],
            ),
            (
                "zed",
                &[
                    ("/telemetry/diagnostics", json!(false)),
                    ("/telemetry/metrics", json!(false)),
                    ("/auto_update", json!(false)),
                ],
            ),
        ];
        let aider_yaml = [
            ("/analytics-disable", json!(true)),
            ("/check-update", json!(false)),
            ("/show-release-notes", json!(false)),
        ];
        let aider_shell = [
            ("/AIDER_ANALYTICS_DISABLE", json!("true")),
            ("/AIDER_CHECK_UPDATE", json!("false")),
            ("/AIDER_SHOW_RELEASE_NOTES", json!("false")),
        ];
        let qwen_settings =
            [("/privacy/usageStatisticsEnabled", json!(false)), ("/general/enableAutoUpdate", json!(false))];
        let rows = off
            .iter()
            .map(|(id, knobs)| (*id, None, *knobs))
            .chain([
                ("aider", Some(TemplateFormat::Yaml), &aider_yaml[..]),
                ("aider", Some(TemplateFormat::Shell), &aider_shell[..]),
                ("qwen-code", None, &qwen_settings[..]),
            ]);
        let mut checked = 0;
        for (id, only_format, knobs) in rows {
            let profile = seed(id);
            for t in profile.templates.iter().filter(|t| only_format.is_none_or(|f| f == t.format)) {
                for (forward_auth, project_scope) in [(false, false), (false, true), (true, false), (true, true)] {
                    let mut phs = validation_placeholders();
                    phs.insert("forward_auth".into(), Value::Bool(forward_auth));
                    phs.insert(crate::render::PROJECT_SCOPE.into(), Value::Bool(project_scope));
                    // Qwen Code's settings live in its settings.json companion.
                    let (format, body) = if id == "qwen-code" {
                        let companions = crate::companions::companion_files(t, &phs).expect("renders");
                        let c = companions.into_iter().find(|c| c.path.as_deref() == Some("~/.qwen/settings.json"));
                        (TemplateFormat::Json, c.expect("Qwen Code's settings.json companion").body)
                    } else {
                        (t.format, crate::render::render(&t.body, t.format, &phs).expect("renders"))
                    };
                    let doc = doc_of(format, &body);
                    for (pointer, want) in knobs {
                        assert_eq!(doc.pointer(pointer), Some(want), "{id} · {}: {pointer} in\n{body}", t.title);
                    }
                }
                checked += 1;
            }
        }
        // claude-code 4, gemini-cli 2, codex 1, crush 3, goose 1, vibe 1, zed 1, aider 3, qwen-code 1.
        assert_eq!(checked, 17, "a template was skipped or added without its row");
    }

    /// Codex, Qwen Code, Goose and Mistral Vibe each wire every gateway MCP
    /// server in the shape its own config reference names for a remote
    /// streamable-HTTP server with a static bearer, and a run with no server
    /// writes no MCP block at all. Shapes from each vendor's reference: Codex
    /// `[mcp_servers.<name>]` `url` + `http_headers`; Qwen Code
    /// `mcpServers.<name>.httpUrl` + `headers` (`url` is its SSE transport);
    /// Goose `extensions.<key>` `type: streamable_http` + `uri` + `headers`;
    /// Vibe `[[mcp_servers]]` `transport = "streamable-http"` + static `auth`.
    #[test]
    fn codex_qwen_goose_and_vibe_wire_each_mcp_server_as_their_reference_names_it() {
        fn toml_of(s: &str) -> serde_json::Value {
            serde_json::to_value(s.parse::<toml::Table>().expect("toml")).unwrap()
        }
        fn yaml_of(s: &str) -> serde_json::Value {
            serde_json::to_value(yaml_serde::from_str::<yaml_serde::Value>(s).expect("yaml")).unwrap()
        }
        let docs = |id: &str, with_servers: bool| -> serde_json::Value {
            let profile = seed(id);
            assert!(profile.supports_mcp, "{id} must declare MCP support");
            let t = &profile.templates[0];
            let mut phs = validation_placeholders();
            phs.insert("forward_auth".into(), Value::Bool(false));
            if !with_servers {
                phs.remove("mcp_servers");
            }
            let body = crate::render::render(&t.body, t.format, &phs).expect("renders");
            let mut merged = match t.format {
                TemplateFormat::Toml => toml_of(&body),
                TemplateFormat::Yaml => yaml_of(&body),
                _ => serde_json::json!({}),
            };
            for c in crate::companions::companion_files(t, &phs).expect("companions render") {
                if c.format == TemplateFormat::Json {
                    let v: serde_json::Value = serde_json::from_str(&c.body).expect("json");
                    merged.as_object_mut().unwrap().extend(v.as_object().unwrap().clone());
                }
            }
            merged
        };
        let bearer = |slug: &str| format!("Bearer <paste-your-{slug}-mcp-key-here>");
        for slug in ["fs", "web"] {
            let url = format!("https://gw.example.com/mcp/{slug}");

            let codex = &docs("codex", true)["mcp_servers"][slug];
            assert_eq!(codex["url"], url.as_str(), "codex");
            assert_eq!(codex["http_headers"]["Authorization"], bearer(slug).as_str(), "codex");

            let qwen = &docs("qwen-code", true)["mcpServers"][slug];
            assert_eq!(qwen["httpUrl"], url.as_str(), "qwen-code");
            assert_eq!(qwen["headers"]["Authorization"], bearer(slug).as_str(), "qwen-code");

            let goose = &docs("goose", true)["extensions"][slug];
            assert_eq!(goose["type"], "streamable_http", "goose");
            assert_eq!(goose["enabled"], true, "goose");
            assert_eq!(goose["name"], slug, "goose");
            assert_eq!(goose["uri"], url.as_str(), "goose");
            assert_eq!(goose["headers"]["Authorization"], bearer(slug).as_str(), "goose");

            let vibe_doc = docs("vibe", true);
            let vibe = vibe_doc["mcp_servers"]
                .as_array()
                .and_then(|a| a.iter().find(|s| s["name"] == slug))
                .unwrap_or_else(|| panic!("vibe has no {slug} server"));
            assert_eq!(vibe["transport"], "streamable-http", "vibe");
            assert_eq!(vibe["url"], url.as_str(), "vibe");
            assert_eq!(vibe["auth"]["type"], "static", "vibe");
            assert_eq!(vibe["auth"]["headers"]["Authorization"], bearer(slug).as_str(), "vibe");
        }
        assert!(seed("vibe").templates[0].keyed_arrays.get("/mcp_servers").is_some_and(|k| k == "name"),
            "vibe's servers merge by name beside the user's own");
        for (id, key) in [("codex", "mcp_servers"), ("qwen-code", "mcpServers"), ("goose", "extensions"), ("vibe", "mcp_servers")] {
            assert!(docs(id, false).get(key).is_none(), "{id} writes {key} with no server");
        }
    }

    /// Every template that wires MCP servers writes every header of every
    /// server — the gateway key's and each one the client sends itself — where
    /// its client reads a server's headers, in the template's own format: on
    /// a static-key template (gateway key + client header on `/mcp/<slug>`,
    /// client headers only on the `/fwd` mount) and a spec-OAuth one (client
    /// headers only), under a gateway and a BYOK key, user and project scope.
    /// A profile that writes a fixed `Authorization` instead of the loop
    /// loses the client header and fails here. Claude Code's static gateway
    /// key is the one header written as a reference (`${STREAMSCOPE_MCP_KEY}`,
    /// which its settings' `env` carries — see
    /// `claude_code_wires_its_mcp_servers_where_claude_code_reads_them`).
    #[test]
    fn every_mcp_template_writes_each_header() {
        fn parsed(format: TemplateFormat, s: &str) -> Vec<serde_json::Value> {
            match format {
                TemplateFormat::Json => vec![serde_json::from_str(s).expect("json")],
                TemplateFormat::Yaml => vec![serde_json::to_value(
                    yaml_serde::from_str::<yaml_serde::Value>(s).expect("yaml"),
                )
                .unwrap()],
                TemplateFormat::Toml => {
                    vec![serde_json::to_value(s.parse::<toml::Table>().expect("toml")).unwrap()]
                }
                // A command line carries its server as a single-quoted JSON argument.
                TemplateFormat::Shell | TemplateFormat::Text => s
                    .split('\'')
                    .skip(1)
                    .step_by(2)
                    .filter_map(|arg| serde_json::from_str(arg).ok())
                    .collect(),
            }
        }
        // A header map entry, or an `mcp-remote --header Name:Value` argument.
        fn holds(v: &serde_json::Value, name: &str, value: &str) -> bool {
            match v {
                serde_json::Value::Object(m) => {
                    m.get(name).and_then(|x| x.as_str()) == Some(value)
                        || m.values().any(|x| holds(x, name, value))
                }
                serde_json::Value::Array(a) => a.iter().any(|x| holds(x, name, value)),
                serde_json::Value::String(s) => *s == format!("{name}:{value}"),
                _ => false,
            }
        }
        // The `/fwd/{key}/mcp/<slug>` mount: the client sends its own
        // `Authorization`, so no gateway header.
        let fwd_item = |slug: &str| {
            let mut m = mcp_server_item(slug, false);
            m.insert("url".into(), Value::String(format!("https://gw.example.com/fwd/{API_KEY_PLACEHOLDER}/mcp/{slug}")));
            m.insert("forward_auth".into(), Value::Bool(true));
            let Some(Value::List(headers)) = m.get_mut("headers") else { unreachable!() };
            headers.insert(0, mcp_header_item("Authorization", mcp_client_header_placeholder(slug, "Authorization")));
            m
        };
        let mut checked: Vec<String> = Vec::new();
        for (_, profile) in seed_profiles() {
            if !profile.supports_mcp {
                continue;
            }
            for t in &profile.templates {
                let wires = t.body.contains("mcp_servers")
                    || t.companions.iter().any(|c| c.body.contains("mcp_servers"));
                if !wires {
                    continue;
                }
                let is_static = t.mcp_auth_mode == McpAuthMode::Static;
                let mut server_sets = vec![vec![mcp_server_item("fs", is_static), mcp_server_item("web", is_static)]];
                if is_static {
                    server_sets.push(vec![mcp_server_item("fs", true), fwd_item("web")]);
                }
                for servers in server_sets {
                    for (forward_auth, project_scope) in [(false, false), (false, true), (true, false), (true, true)] {
                        // A template with no project form is written in its global form.
                        if project_scope && t.project_filename.is_none() {
                            continue;
                        }
                        let ctx = format!("{} byok={forward_auth} project={project_scope}", t.title);
                        let mut phs = validation_placeholders();
                        phs.insert("forward_auth".into(), Value::Bool(forward_auth));
                        phs.insert(crate::render::PROJECT_SCOPE.into(), Value::Bool(project_scope));
                        phs.insert("mcp_servers".into(), Value::List(servers.clone()));
                        let body = crate::render::render(&t.body, t.format, &phs).expect("renders");
                        let mut docs = parsed(t.format, &body);
                        for c in crate::companions::companion_files(t, &phs).expect("companions render") {
                            docs.extend(parsed(c.format, &c.body));
                        }
                        for server in &servers {
                            let (Some(Value::String(slug)), Some(Value::List(headers)), Some(Value::Bool(fwd))) =
                                (server.get("slug"), server.get("headers"), server.get("forward_auth"))
                            else {
                                unreachable!()
                            };
                            for h in headers {
                                let (Some(Value::String(name)), Some(Value::String(value))) = (h.get("name"), h.get("value"))
                                else {
                                    unreachable!()
                                };
                                let by_reference = profile.id == "claude-code"
                                    && name == "Authorization"
                                    && !fwd
                                    && !forward_auth;
                                let expect = if by_reference { "Bearer ${STREAMSCOPE_MCP_KEY}" } else { value.as_str() };
                                assert!(
                                    docs.iter().any(|d| holds(d, name, expect)),
                                    "{ctx}: {slug} {name}: {expect} is not written\n{body}"
                                );
                            }
                        }
                    }
                }
                checked.push(format!("{}/{}", profile.id, t.title));
            }
        }
        // Every MCP-capable profile has a template here: 12 profiles, 23 templates.
        let profiles: std::collections::BTreeSet<&str> =
            checked.iter().map(|c| c.split('/').next().unwrap_or_default()).collect();
        assert_eq!((profiles.len(), checked.len()), (12, 23), "{checked:#?}");
    }

    /// Claude Code reads MCP servers only from `~/.claude.json` (user scope)
    /// or a project's `.mcp.json`, never from `settings.json`; it keeps its own
    /// state in `~/.claude.json`, and loads a project's servers unprompted only
    /// when a trusted folder's settings enable them by name; it expands
    /// `${VAR}` in a server's headers from the `env` its settings set (each
    /// checked on 2.1.308). So: a user-scope render shows one `claude mcp
    /// add-json --scope user` command per server and writes no MCP file; a
    /// project render writes `.mcp.json` and enables each server; a static
    /// key reaches the servers only through `STREAMSCOPE_MCP_KEY` in the
    /// settings `env` (under a BYOK key each header is written as given); a run with
    /// no server shows and writes nothing for MCP.
    #[test]
    fn claude_code_keeps_the_key_out_of_a_fwd_server_url() {
        // A server on the `/fwd/{key}/mcp/<slug>` mount (its client sends its own
        // Authorization): with a gateway key, the URL reads the key from the
        // environment variable like the header does, so `.mcp.json` and the
        // `claude mcp add-json` line never hold it; with a BYOK key (which the
        // file holds anyway) the URL is written as rendered.
        let profile = seed("claude-code");
        let t = profile
            .templates
            .iter()
            .find(|t| t.mcp_auth_mode == McpAuthMode::Static && t.project_filename.is_some())
            .expect("a static project template");
        for (project_scope, byok) in [(true, false), (false, false), (true, true)] {
            let mut item = mcp_server_item("gh", true);
            item.insert("forward_auth".into(), Value::Bool(true));
            // On `/fwd` the key rides the path: the item carries no gateway header.
            item.insert(
                "headers".into(),
                Value::List(vec![mcp_header_item("Authorization", mcp_client_header_placeholder("gh", "Authorization"))]),
            );
            item.insert("url".into(), Value::String("https://gw.example.com/fwd/<paste-your-gh-mcp-key-here>/mcp/gh".into()));
            let mut phs = validation_placeholders();
            phs.insert("forward_auth".into(), Value::Bool(byok));
            phs.insert(crate::render::PROJECT_SCOPE.into(), Value::Bool(project_scope));
            phs.insert("mcp_servers".into(), Value::List(vec![item]));
            let companions = crate::companions::companion_files(t, &phs).expect("renders");
            let body = &companions[0].body;
            if byok {
                assert!(body.contains("https://gw.example.com/fwd/<paste-your-gh-mcp-key-here>/mcp/gh"), "{body}");
            } else {
                assert!(body.contains("https://gw.example.com/fwd/${STREAMSCOPE_MCP_KEY}/mcp/gh"), "{body}");
                assert!(!body.contains("<paste-your-gh-mcp-key-here>"), "the key is in the file: {body}");
            }
        }
    }

    #[test]
    fn claude_code_wires_its_mcp_servers_where_claude_code_reads_them() {
        let profile = seed("claude-code");
        let passes = [(true, false, false), (true, true, false), (true, false, true), (true, true, true), (false, false, false), (false, true, false)];
        for t in &profile.templates {
            let is_static = t.mcp_auth_mode == McpAuthMode::Static;
            for (with_servers, project_scope, forward_auth) in passes {
                let ctx = format!("{} servers={with_servers} project={project_scope} byok={forward_auth}", t.title);
                let mut phs = validation_placeholders();
                phs.insert("forward_auth".into(), Value::Bool(forward_auth));
                phs.insert(crate::render::PROJECT_SCOPE.into(), Value::Bool(project_scope));
                let servers = if with_servers {
                    vec![mcp_server_item("fs", is_static), mcp_server_item("web", is_static)]
                } else {
                    Vec::new()
                };
                phs.insert("mcp_servers".into(), Value::List(servers));
                let body = crate::render::render(&t.body, t.format, &phs).expect("renders");
                let doc: serde_json::Value = serde_json::from_str(&body).expect("json");
                assert!(doc.get("mcpServers").is_none(), "{ctx}: settings.json carries mcpServers");
                let key_var = doc["env"].get("STREAMSCOPE_MCP_KEY");
                let expect_var = with_servers && is_static && !forward_auth;
                assert_eq!(key_var, expect_var.then(|| serde_json::json!("<paste-your-fs-mcp-key-here>")).as_ref(), "{ctx}");
                let project = project_scope && t.project_filename.is_some();
                let enabled = doc.get("enabledMcpjsonServers");
                assert_eq!(enabled, (project && with_servers).then(|| serde_json::json!(["fs", "web"])).as_ref(), "{ctx}");

                let companions = crate::companions::companion_files(t, &phs).expect("renders");
                if !with_servers || (project_scope && t.project_filename.is_none()) {
                    assert!(companions.is_empty(), "{ctx}: {companions:?}");
                    continue;
                }
                assert_eq!(companions.len(), 1, "{ctx}: {companions:?}");
                let c = &companions[0];
                assert_eq!(c.path, None, "{ctx}: no MCP file outside a project");
                let bearer = |slug: &str| match (is_static, forward_auth) {
                    (false, _) => None,
                    (true, false) => Some("Bearer ${STREAMSCOPE_MCP_KEY}".to_string()),
                    (true, true) => Some(format!("Bearer <paste-your-{slug}-mcp-key-here>")),
                };
                let servers: Vec<(String, serde_json::Value)> = if project {
                    assert_eq!(c.project_path.as_deref(), Some(".mcp.json"), "{ctx}");
                    let file: serde_json::Value = serde_json::from_str(&c.body).expect("json");
                    file["mcpServers"].as_object().expect("servers").clone().into_iter().collect()
                } else {
                    assert_eq!((c.project_path.as_deref(), c.format), (None, TemplateFormat::Text), "{ctx}");
                    c.body
                        .lines()
                        .map(|line| {
                            let (remove, add) = line.split_once("; ").expect("remove; add");
                            let slug = add.split(' ').nth(5).expect("slug").to_string();
                            assert_eq!(remove, format!("claude mcp remove --scope user {slug} >/dev/null 2>&1"), "{ctx}");
                            assert!(add.starts_with(&format!("claude mcp add-json --scope user {slug} '")), "{ctx}: {add}");
                            let json = add.split_once('\'').expect("quoted").1.strip_suffix('\'').expect("quoted");
                            (slug, serde_json::from_str(json).expect("json"))
                        })
                        .collect()
                };
                let slugs: Vec<&str> = servers.iter().map(|(s, _)| s.as_str()).collect();
                assert_eq!(slugs, ["fs", "web"], "{ctx}");
                for (slug, server) in &servers {
                    assert_eq!(server["type"], "http", "{ctx}");
                    assert_eq!(server["url"], format!("https://gw.example.com/mcp/{slug}").as_str(), "{ctx}");
                    assert_eq!(server["headers"]["Authorization"].as_str().map(str::to_string), bearer(slug), "{ctx}");
                    // The header the client sends itself lands verbatim, in every mode.
                    assert_eq!(
                        server["headers"][FIXTURE_CLIENT_HEADER],
                        format!("<paste-your-{slug}-x-client-token-here>").as_str(),
                        "{ctx}"
                    );
                }
            }
        }
    }

    /// Qwen Code sizes replies and compaction for a model it does not know
    /// against a 200 000-token window, which a smaller model refuses. Every
    /// template hands it the route's output cap in the `.env` it auto-loads,
    /// pins the OpenAI auth type that makes it read that file, and, when the
    /// route knows it, the window in `settings.json` (a BYOK pass-through
    /// knows none).
    #[test]
    fn qwen_is_given_the_routes_output_cap_and_window() {
        let qwen = seed("qwen-code");
        for t in &qwen.templates {
            for (forward_auth, window) in [(false, Some(65_536)), (true, Some(65_536)), (true, None)] {
                let mut phs = validation_placeholders();
                phs.insert("forward_auth".into(), Value::Bool(forward_auth));
                phs.insert("max_output_tokens".into(), Value::Int(12_345));
                match window {
                    Some(w) => phs.insert("context_window".into(), Value::Int(w)),
                    None => phs.remove("context_window"),
                };
                let ctx = format!("{} forward_auth={forward_auth} window={window:?}", t.title);
                let body = crate::render::render(&t.body, t.format, &phs).expect("renders");
                let caps: Vec<&str> =
                    body.lines().filter(|l| l.starts_with("QWEN_CODE_MAX_OUTPUT_TOKENS=")).collect();
                assert_eq!(caps, ["QWEN_CODE_MAX_OUTPUT_TOKENS=12345"], "{ctx}");

                let companions = crate::companions::companion_files(t, &phs).expect("renders");
                let settings: Vec<_> =
                    companions.iter().filter(|c| c.path.as_deref() == Some("~/.qwen/settings.json")).collect();
                assert_eq!(settings.len(), 1, "{ctx}");
                let mut doc: serde_json::Value = serde_json::from_str(&settings[0].body).expect("json");
                // The MCP servers and the vendor-traffic switches it also
                // carries are asserted on their own.
                for k in ["mcpServers", "privacy", "general"] {
                    doc.as_object_mut().unwrap().remove(k);
                }
                let mut expected = serde_json::json!({"security": {"auth": {"selectedType": "openai"}}});
                if let Some(w) = window {
                    expected["model"] = serde_json::json!({"generationConfig": {"contextWindowSize": w}});
                }
                assert_eq!(doc, expected, "{ctx}");
            }
        }
    }

    /// Replaces the constant at the former `companions.rs` vibe arm.
    #[test]
    fn vibe_env_writes_the_var_config_toml_names() {
        let vibe = seed("vibe");
        let c = render_only_companion(&vibe.templates[0], false);
        assert_eq!(c.path, "~/.vibe/.env");
        assert_eq!(c.body, format!("STREAMSCOPE_API_KEY={API_KEY_PLACEHOLDER}\n"));
    }

    /// Replaces the two constants at the former `companions.rs` gemini-cli
    /// arm. The `{{#unless}}` tags sit inline with their content, so no
    /// standalone-line stripping is involved — the byte comparison is the
    /// proof, not the whitespace rule.
    #[test]
    fn gemini_env_sets_both_vars_in_gateway_mode_and_only_the_url_under_byok() {
        let gemini = seed("gemini-cli");
        let gateway = render_only_companion(&gemini.templates[0], false);
        assert_eq!(gateway.path, "~/.gemini/.env");
        assert_eq!(
            gateway.body,
            format!(
                "GEMINI_API_KEY={API_KEY_PLACEHOLDER}\n\
                 GOOGLE_GEMINI_BASE_URL=https://gw.example.com\n"
            )
        );

        // BYOK: the user's own Google credential must be left alone — writing
        // the gateway key as GEMINI_API_KEY would forward it upstream, which
        // the provider rejects.
        let byok = render_only_companion(&gemini.templates[0], true);
        assert!(
            !byok.body.contains("GEMINI_API_KEY="),
            "BYOK must not set GEMINI_API_KEY; got:\n{}",
            byok.body
        );
        assert_eq!(
            byok.body,
            format!("GOOGLE_GEMINI_BASE_URL=https://gw.example.com/fwd/{API_KEY_PLACEHOLDER}/v1\n")
        );
    }

    /// The MCP-only leg of a dual-template client declares no credential
    /// companion — the property that replaced the old `kind.needs_llm()` gate
    /// inside `companion_files`.
    #[test]
    fn the_mcp_only_template_of_a_dual_client_declares_no_companion() {
        let gemini = seed("gemini-cli");
        let mcp = gemini
            .templates
            .iter()
            .find(|t| !t.kind.needs_llm())
            .expect("gemini-cli has an MCP-only template");
        assert!(mcp.companions.is_empty());
    }

    // -----------------------------------------------------------------------
    // The delivery rules, each with its positive control.
    // -----------------------------------------------------------------------

    #[test]
    fn a_profile_whose_llm_template_delivers_no_key_is_rejected() {
        let p = profile(vec![template(TemplateKind::Llm, "BASE={{base_url}}\n")]);
        assert!(matches!(
            validate_profile(&p),
            Err(ProfileInvalid::KeyUnreachable { .. })
        ));
    }

    /// Positive control for the rule above: without it, the rejection keeps
    /// "passing" after the predicate stops working.
    #[test]
    fn the_same_profile_with_a_companion_is_accepted() {
        let mut t = template(TemplateKind::Llm, "BASE={{base_url}}\n");
        t.companions = vec![companion("~/.tool/.env", "KEY={{api_key}}\n")];
        assert!(validate_profile(&profile(vec![t])).is_ok());
    }

    /// A step is printed, never written: the key in one is not delivered.
    #[test]
    fn a_key_only_in_a_step_is_not_delivered() {
        let mut t = template(TemplateKind::Llm, "BASE={{base_url}}\n");
        let mut step = companion("~/unused", "tool login {{api_key}}\n");
        step.path = None;
        t.companions = vec![step];
        assert!(matches!(
            validate_profile(&profile(vec![t])),
            Err(ProfileInvalid::KeyUnreachable { .. })
        ));
    }

    #[test]
    fn an_inline_key_in_the_body_is_accepted() {
        let t = template(TemplateKind::Llm, "KEY={{api_key}}\n");
        assert!(validate_profile(&profile(vec![t])).is_ok());
    }

    /// The escape is a declaration, not a hardcoded client-id list.
    #[test]
    fn an_environment_delivery_declaration_is_the_escape() {
        let mut t = template(TemplateKind::Llm, "BASE={{base_url}}\n");
        t.key_delivery = KeyDelivery::Environment;
        assert!(validate_profile(&profile(vec![t.clone()])).is_ok());
        // …and it is the ONLY thing exempting it — the default is not.
        t.key_delivery = KeyDelivery::Config;
        assert!(validate_profile(&profile(vec![t])).is_err());
    }

    /// A key reachable only when an OPTIONAL field resolves is not delivered:
    /// a self-hosted route resolves neither `context_window` nor
    /// `reasoning_effort`, so that render hands the user a keyless config. The
    /// rule therefore reads both optional-field shapes, not just the full one.
    #[test]
    fn a_key_only_reachable_under_an_optional_field_does_not_count_as_delivered() {
        let t = template(
            TemplateKind::Llm,
            "{{#if context_window}}KEY={{api_key}}\n{{/if}}BASE={{base_url}}\n",
        );
        assert!(matches!(
            validate_profile(&profile(vec![t])),
            Err(ProfileInvalid::KeyUnreachable { .. })
        ));
    }

    /// Positive control for the pass above: the same body without the
    /// conditional is accepted, so the rejection is about reachability and not
    /// about the template shape.
    #[test]
    fn the_same_key_outside_the_conditional_is_delivered() {
        let t = template(TemplateKind::Llm, "KEY={{api_key}}\nBASE={{base_url}}\n");
        assert!(validate_profile(&profile(vec![t])).is_ok());
    }

    /// Rule B is checked on every render pass, so a sentinel that only appears
    /// in one branch cannot slip past it.
    #[test]
    fn a_conditional_gateway_key_in_an_mcp_companion_is_still_refused() {
        let mut t = template(TemplateKind::Mcp, "{}\n");
        t.companions = vec![companion(
            "~/.tool/.env",
            "{{#if forward_auth}}TOKEN={{api_key}}\n{{/if}}X=1\n",
        )];
        assert!(matches!(
            validate_profile(&profile(vec![t])),
            Err(ProfileInvalid::CompanionOutOfScope { .. })
        ));
    }

    #[test]
    fn an_llm_bearing_sibling_satisfies_the_rule() {
        let p = profile(vec![
            template(TemplateKind::Llm, "BASE={{base_url}}\n"),
            template(TemplateKind::Llm, "KEY={{api_key}}\n"),
        ]);
        assert!(validate_profile(&p).is_ok());
    }

    /// The CLI writes a file-writing template alone, so a sibling showing the
    /// key does not deliver it there.
    #[test]
    fn a_sibling_does_not_deliver_for_a_file_writing_template() {
        let mut file = template(TemplateKind::Llm, "BASE={{base_url}}\n");
        file.filename = Some("~/.tool.env".into());
        let keyed = template(TemplateKind::Llm, "KEY={{api_key}}\n");
        assert!(matches!(
            validate_profile(&profile(vec![file.clone(), keyed])),
            Err(ProfileInvalid::KeyUnreachable { .. })
        ));
        // Positive control: the same file carrying the key is accepted.
        file.body = "BASE={{base_url}}\nKEY={{api_key}}\n".into();
        assert!(validate_profile(&profile(vec![file])).is_ok());
    }

    /// Rule B: a non-LLM template's companion may not carry the gateway key —
    /// that placeholder is never populated for such a render, so the file
    /// would be written with an empty credential.
    #[test]
    fn an_mcp_only_companion_may_not_carry_the_gateway_key() {
        let mut t = template(TemplateKind::Mcp, "{}\n");
        t.companions = vec![companion("~/.tool/.env", "TOKEN={{api_key}}\n")];
        assert!(matches!(
            validate_profile(&profile(vec![t])),
            Err(ProfileInvalid::CompanionOutOfScope { .. })
        ));
    }

    /// Positive control for Rule B: a per-server MCP bearer inside
    /// `{{#each mcp_servers}}` is a DIFFERENT credential and must pass. This
    /// is what the fixture's distinct per-server `api_key` value buys — see
    /// the comment in `validation_placeholders`.
    #[test]
    fn an_mcp_companion_may_carry_a_per_server_bearer() {
        let mut t = template(TemplateKind::Mcp, "{}\n");
        t.companions = vec![companion(
            "~/.tool/.env",
            "{{#each mcp_servers}}TOKEN_{{slug}}={{api_key}}\n{{/each}}",
        )];
        assert!(validate_profile(&profile(vec![t])).is_ok());
    }

    /// A source scan reading `{{api_key}}` out of the template text cannot
    /// tell these apart: gemini-cli's LLM template carries the identifier ONLY
    /// inside `{{#each mcp_servers}}`, where it resolves to the per-server
    /// bearer. Rendering is what makes the distinction, and it is why the
    /// profile genuinely needs its companion.
    #[test]
    fn a_gateway_key_is_not_confused_with_a_bearer_nested_in_an_each_block() {
        let mut t = template(
            TemplateKind::Combined,
            "{{#each mcp_servers}}AUTH={{api_key}}\n{{/each}}",
        );
        // No companion, no sibling: the only `{{api_key}}` is the MCP bearer.
        assert!(matches!(
            validate_profile(&profile(vec![t.clone()])),
            Err(ProfileInvalid::KeyUnreachable { .. })
        ));
        // Exactly the shape gemini-cli ships, and it passes.
        t.companions = vec![companion("~/.gemini/.env", "GEMINI_API_KEY={{api_key}}\n")];
        assert!(validate_profile(&profile(vec![t])).is_ok());
    }

    #[test]
    fn a_companion_path_escaping_its_directory_is_refused() {
        for bad in ["", "   ", "~/../../etc/shadow", "~/a/../../b"] {
            let mut t = template(TemplateKind::Llm, "KEY={{api_key}}\n");
            t.companions = vec![companion(bad, "X=1\n")];
            assert!(
                matches!(
                    validate_profile(&profile(vec![t])),
                    Err(ProfileInvalid::CompanionPathInvalid { .. })
                ),
                "path {bad:?} should be refused"
            );
        }
        // Positive control: an ordinary `~/`-anchored path is accepted.
        let mut t = template(TemplateKind::Llm, "KEY={{api_key}}\n");
        t.companions = vec![companion("~/.config/tool/secrets.yaml", "X=1\n")];
        assert!(validate_profile(&profile(vec![t])).is_ok());
    }

    #[test]
    fn two_companions_at_one_path_are_refused() {
        let mut t = template(TemplateKind::Llm, "KEY={{api_key}}\n");
        for second in ["~/.tool//.env", "~/.tool/./.env"] {
            t.companions = vec![companion("~/.tool/.env", "A=1\n"), companion(second, "B=2\n")];
            assert!(
                matches!(
                    validate_profile(&profile(vec![t.clone()])),
                    Err(ProfileInvalid::CompanionPathInvalid { .. })
                ),
                "{second:?} names the first companion's file"
            );
        }
        // A companion at the template's own config file is the same file too.
        let mut own = t.clone();
        own.filename = Some("~/.tool/config.json".into());
        own.companions = vec![companion("~/.tool/config.json", "B=2\n")];
        assert!(matches!(
            validate_profile(&profile(vec![own.clone()])),
            Err(ProfileInvalid::CompanionPathInvalid { .. })
        ));
        // In a project a `~/` companion moves beside the project config.
        let mut project = t.clone();
        project.project_filename = Some(".tool/config.json".into());
        project.companions = vec![companion("~/.tool/config.json", "B=2\n")];
        assert!(matches!(
            validate_profile(&profile(vec![project.clone()])),
            Err(ProfileInvalid::CompanionPathInvalid { .. })
        ));
        project.project_filename = Some("./.tool/config.json".into());
        assert!(matches!(
            validate_profile(&profile(vec![project.clone()])),
            Err(ProfileInvalid::CompanionPathInvalid { .. })
        ));
        project.companions = vec![companion("~/.tool/.env", "B=2\n")];
        assert!(validate_profile(&profile(vec![project.clone()])).is_ok());
        // A declared project path is placed as written: it may not land on the
        // project config or on another companion's project file, and stays
        // relative to the project.
        let declared = |path: &str, project_path: &str| CompanionTemplate {
            project_path: Some(project_path.into()),
            ..companion(path, "B=2\n")
        };
        project.project_filename = Some(".tool/config.json".into());
        for clash in [
            vec![declared("~/.tool.env", ".tool/config.json")],
            vec![companion("~/.tool/.env", "A=1\n"), declared("~/.other.env", ".tool/.env")],
        ] {
            project.companions = clash;
            assert!(matches!(
                validate_profile(&profile(vec![project.clone()])),
                Err(ProfileInvalid::CompanionPathInvalid { .. })
            ));
        }
        for outside in ["/etc/tool.env", "~/tool.env", "../tool.env", "a/../../tool.env", "C:\\tool.env", " ", " .mcp.json", ".", "./", ".tool/"] {
            project.companions = vec![declared("~/.tool.env", outside)];
            assert!(
                matches!(
                    validate_profile(&profile(vec![project.clone()])),
                    Err(ProfileInvalid::CompanionPathInvalid { path, .. }) if path == outside
                ),
                "{outside:?} is refused, under its own name"
            );
        }
        project.companions = vec![declared("~/.tool.env", ".tool/servers.env")];
        assert!(validate_profile(&profile(vec![project.clone()])).is_ok());
        // A project path on a template with no project form is never used.
        project.project_filename = None;
        assert!(matches!(
            validate_profile(&profile(vec![project])),
            Err(ProfileInvalid::CompanionPathInvalid { path, .. }) if path == ".tool/servers.env"
        ));
        // `\` is an ordinary character in a file name where the CLI runs.
        t.companions = vec![companion("~/.tool/.env", "A=1\n"), companion("~/.tool\\.env", "B=2\n")];
        assert!(validate_profile(&profile(vec![t.clone()])).is_ok());
        // A bare file name is placed per platform by the CLI: not compared.
        own.filename = Some("config.json".into());
        own.companions = vec![companion("~/config.json", "B=2\n")];
        assert!(validate_profile(&profile(vec![own])).is_ok());
        // Positive control: one file name in two directories is two files.
        t.companions = vec![companion("~/.tool/.env", "A=1\n"), companion("~/.other/.env", "B=2\n")];
        assert!(validate_profile(&profile(vec![t])).is_ok());
    }

    /// A render failure must be reported as a render failure, never
    /// misattributed to the delivery rules — the operator would hunt a syntax
    /// error that does not exist, or vice versa.
    #[test]
    fn a_render_failure_outranks_a_delivery_failure() {
        let mut t = template(TemplateKind::Llm, "{\"a\": }\n");
        t.format = TemplateFormat::Json; // invalid JSON AND no key
        assert!(matches!(
            validate_profile(&profile(vec![t])),
            Err(ProfileInvalid::Render { .. })
        ));
    }

    /// A keyed YAML sequence of per-route entries, one per alias.
    fn keyed_yaml(body: &str, pointer: &str, key: &str) -> ClientProfileTemplate {
        let mut t = template(TemplateKind::Llm, body);
        t.format = TemplateFormat::Yaml;
        t.keyed_arrays = BTreeMap::from([(pointer.to_string(), key.to_string())]);
        t
    }

    const PER_ROUTE_MODELS: &str =
        "key: {{api_key}}\nmodels:\n{{#each routes}}  - name: {{model_alias}}\n{{/each}}";

    /// Positive control: one entry per route carries a unique `name`.
    #[test]
    fn a_keyed_array_with_a_unique_identity_per_entry_is_accepted() {
        let t = keyed_yaml(PER_ROUTE_MODELS, "/models", "name");
        assert!(validate_profile(&profile(vec![t])).is_ok());
    }

    #[test]
    fn a_keyed_array_whose_entries_share_an_identity_is_refused() {
        // Every route renders the same constant name.
        let t = keyed_yaml("key: {{api_key}}\nmodels:\n{{#each routes}}  - name: gw\n{{/each}}", "/models", "name");
        assert!(matches!(
            validate_profile(&profile(vec![t])),
            Err(ProfileInvalid::KeyedArrayInvalid { reason, .. }) if reason.contains("share")
        ));
    }

    #[test]
    fn a_keyed_array_is_refused_where_the_identity_or_the_array_is_missing() {
        for (pointer, key) in [("/models", "id"), ("/key", "name"), ("models", "name"), ("/models", " ")] {
            let t = keyed_yaml(PER_ROUTE_MODELS, pointer, key);
            assert!(
                matches!(validate_profile(&profile(vec![t])), Err(ProfileInvalid::KeyedArrayInvalid { .. })),
                "{pointer} → {key} was accepted"
            );
        }
        // An env file has no arrays at all.
        let mut t = template(TemplateKind::Llm, "KEY={{api_key}}\n");
        t.keyed_arrays = BTreeMap::from([("/models".to_string(), "name".to_string())]);
        assert!(matches!(
            validate_profile(&profile(vec![t])),
            Err(ProfileInvalid::KeyedArrayInvalid { .. })
        ));
    }

    #[test]
    fn a_keyed_array_in_a_body_that_does_not_parse_is_refused() {
        assert!(keyed_array_error(TemplateFormat::Yaml, "models: [unclosed", "/models", "name").is_some());
        assert!(keyed_array_error(TemplateFormat::Toml, "[[models]\nname = 1", "/models", "name").is_some());
        // Positive control: the same arrays, well-formed.
        assert!(keyed_array_error(TemplateFormat::Yaml, "models:\n  - name: a\n", "/models", "name").is_none());
        assert!(keyed_array_error(TemplateFormat::Toml, "[[models]]\nname = \"a\"\n", "/models", "name").is_none());
    }

    /// Absent from a render is not an error: the render contributes no entries,
    /// and the ones it wrote before are removed.
    #[test]
    fn a_keyed_array_the_render_leaves_out_is_accepted() {
        let t = keyed_yaml("key: {{api_key}}\n{{#if nothing}}models: []\n{{/if}}", "/models", "name");
        assert!(validate_profile(&profile(vec![t])).is_ok());
    }

    /// Where a template with a local form writes the validation local server,
    /// parsed: the rendered body and every companion with a path, merged into
    /// one document (TOML and JSON alike), under `project_scope` as given.
    fn local_docs(t: &ClientProfileTemplate, project_scope: bool) -> serde_json::Value {
        let mut phs = validation_placeholders_for(t);
        phs.insert("forward_auth".into(), Value::Bool(false));
        phs.insert(crate::render::PROJECT_SCOPE.into(), Value::Bool(project_scope));
        let parse = |format: TemplateFormat, s: &str| -> serde_json::Value {
            match format {
                TemplateFormat::Json => serde_json::from_str(s).expect("json"),
                TemplateFormat::Toml => serde_json::to_value(s.parse::<toml::Table>().expect("toml")).unwrap(),
                TemplateFormat::Yaml => {
                    serde_json::to_value(yaml_serde::from_str::<yaml_serde::Value>(s).expect("yaml")).unwrap()
                }
                _ => serde_json::json!({}),
            }
        };
        let body = crate::render::render(&t.body, t.format, &phs).expect("renders");
        let mut merged = parse(t.format, &body);
        for c in crate::companions::companion_files(t, &phs).expect("companions render") {
            if c.path.is_some() || c.project_path.is_some() {
                let v = parse(c.format, &c.body);
                merged.as_object_mut().unwrap().extend(v.as_object().cloned().unwrap_or_default());
            }
        }
        merged
    }

    /// Each v1 client is written a local MCP server as its own reference names
    /// a stdio server — the keys, the argument list and the environment map —
    /// with every argument intact (one needing escapes included), an
    /// administrator's environment value as given and a developer's as the
    /// paste-here sentinel. One row per client and template: the pointer to
    /// its servers map and the entry expected there.
    #[test]
    fn every_local_form_writes_the_stdio_entry_its_client_reads() {
        let args = serde_json::json!(["-y", "@scope/pkg@1.0.0", "a \"quoted\" arg", "--port", "8080", "--python", "3.12"]);
        let env = serde_json::json!({
            "LOG_LEVEL": "info", "DEBUG": "true", "API_TOKEN": "<paste-your-localfs-api_token-here>",
        });
        let plain = serde_json::json!({"command": FIXTURE_LOCAL_COMMAND, "args": args, "env": env});
        let typed = serde_json::json!({"type": "stdio", "command": FIXTURE_LOCAL_COMMAND, "args": args, "env": env});
        let opencode = serde_json::json!({
            "type": "local",
            "command": [FIXTURE_LOCAL_COMMAND, "-y", "@scope/pkg@1.0.0", "a \"quoted\" arg", "--port", "8080", "--python", "3.12"],
            "environment": env,
            "codemode": false,
        });
        let continue_ = serde_json::json!({
            "name": "localfs", "type": "stdio", "command": FIXTURE_LOCAL_COMMAND, "args": args, "env": env,
        });
        let goose = serde_json::json!({
            "enabled": true, "type": "stdio", "name": "localfs", "cmd": FIXTURE_LOCAL_COMMAND, "args": args,
            "envs": env, "timeout": 300,
        });
        let vibe = serde_json::json!({
            "name": "localfs", "transport": "stdio", "command": FIXTURE_LOCAL_COMMAND, "args": args, "env": env,
        });
        // (client, template index, project scope, pointer to the servers map, entry)
        let rows: Vec<(&str, usize, bool, &str, &serde_json::Value)> = vec![
            ("claude-code", 0, true, "/mcpServers", &typed),
            ("claude-code", 1, true, "/mcpServers", &typed),
            ("claude-desktop", 0, false, "/mcpServers", &plain),
            ("cursor", 0, false, "/mcpServers", &typed),
            ("cursor", 1, false, "/mcpServers", &typed),
            ("cline", 2, false, "/mcpServers", &plain),
            ("codex", 0, false, "/mcp_servers", &plain),
            ("gemini-cli", 0, false, "/mcpServers", &plain),
            ("gemini-cli", 1, false, "/mcpServers", &plain),
            ("qwen-code", 0, false, "/mcpServers", &plain),
            ("opencode", 0, false, "/mcp/servers", &opencode),
            ("opencode", 1, false, "/mcp/servers", &opencode),
            ("opencode", 2, false, "/mcp/servers", &opencode),
            ("continue", 0, false, "/mcpServers", &continue_),
            ("continue", 1, false, "/mcpServers", &continue_),
            ("continue", 2, false, "/mcpServers", &continue_),
            ("crush", 0, false, "/mcp", &typed),
            ("crush", 1, false, "/mcp", &typed),
            ("crush", 2, false, "/mcp", &typed),
            ("goose", 0, false, "/extensions", &goose),
            ("vibe", 0, false, "/mcp_servers", &vibe),
        ];
        // A servers map is read by slug; an array of servers by its `name`.
        let entry = |servers: &serde_json::Value, slug: &str| -> Option<serde_json::Value> {
            match servers {
                serde_json::Value::Array(items) => items.iter().find(|s| s["name"] == slug).cloned(),
                other => other.get(slug).cloned(),
            }
        };
        for (id, index, project_scope, pointer, want) in &rows {
            let profile = seed(id);
            let t = &profile.templates[*index];
            assert!(!t.local_mcp.is_none(), "{id}[{index}] declares no local form");
            let doc = local_docs(t, *project_scope);
            let servers = doc.pointer(pointer).unwrap_or_else(|| panic!("{id}[{index}] has no {pointer}: {doc}"));
            assert_eq!(entry(servers, "localfs").as_ref(), Some(*want), "{id}[{index}]");
            // The gateway's servers are still written beside it, as before.
            for slug in ["fs", "web"] {
                assert!(entry(servers, slug).is_some(), "{id}[{index}] lost the gateway server {slug}: {servers}");
            }
            // A servers array is handled entry by entry beside the user's own.
            if servers.is_array() {
                assert_eq!(t.keyed_arrays.get(*pointer).map(String::as_str), Some("name"), "{id}[{index}]");
            }
            // With a local server alone the same command is written, and the
            // config still parses.
            let mut phs = validation_placeholders();
            phs.insert("forward_auth".into(), Value::Bool(false));
            phs.insert(crate::render::PROJECT_SCOPE.into(), Value::Bool(*project_scope));
            phs.insert("mcp_servers".into(), Value::List(vec![mcp_local_item("localfs")]));
            let body = crate::render::render(&t.body, t.format, &phs).expect("renders with a local server alone");
            let companions = crate::companions::companion_files(t, &phs).expect("companions render");
            assert!(
                body.contains(FIXTURE_LOCAL_COMMAND) || companions.iter().any(|c| c.body.contains(FIXTURE_LOCAL_COMMAND)),
                "{id}[{index}] writes no local server when it is the only one"
            );
        }
        // The table is the whole set: a template that declares a form and is
        // missing from it has no assertion of its entry.
        for (path, profile) in seed_profiles() {
            for (i, t) in profile.templates.iter().enumerate() {
                assert_eq!(
                    !t.local_mcp.is_none(),
                    rows.iter().any(|(id, index, ..)| *id == profile.id && *index == i),
                    "{}[{i}]: the local-form table and the seed disagree",
                    path.display()
                );
            }
        }
    }

    /// Claude Code is given a local server in a project's `.mcp.json` only:
    /// outside a project nothing it writes or prints carries it, and the MCP
    /// key its settings export is written for a gateway server alone.
    #[test]
    fn claude_code_writes_a_local_server_only_in_a_project() {
        let profile = seed("claude-code");
        for index in [0, 1] {
            let t = &profile.templates[index];
            assert_eq!(t.local_mcp, LocalMcpForm::Project);
            for local_only in [false, true] {
                let mut phs = validation_placeholders_for(t);
                phs.insert("forward_auth".into(), Value::Bool(false));
                if local_only {
                    phs.insert("mcp_servers".into(), Value::List(vec![mcp_local_item("localfs")]));
                }
                let body = crate::render::render(&t.body, t.format, &phs).expect("renders");
                let companions = crate::companions::companion_files(t, &phs).expect("companions render");
                assert!(!body.contains(FIXTURE_LOCAL_COMMAND), "{body}");
                for c in &companions {
                    assert!(!c.body.contains(FIXTURE_LOCAL_COMMAND) && !c.body.contains("localfs"), "{}", c.body);
                }
                // The key: beside a gateway server on the static-key template,
                // never for a local server alone.
                let writes_key = body.contains("STREAMSCOPE_MCP_KEY");
                assert_eq!(writes_key, index == 0 && !local_only, "template {index}, local only {local_only}: {body}");

                phs.insert(crate::render::PROJECT_SCOPE.into(), Value::Bool(true));
                let body = crate::render::render(&t.body, t.format, &phs).expect("renders");
                let settings: serde_json::Value = serde_json::from_str(&body).expect("json");
                assert!(
                    settings["enabledMcpjsonServers"].as_array().is_some_and(|a| a.iter().any(|s| s == "localfs")),
                    "the project settings enable the local server: {body}"
                );
            }
        }
    }

    /// Saving a template is refused when it renders invalid output for a
    /// local server alone, though it renders fine beside a gateway server: a
    /// separator written before every local item needs an item before it.
    #[test]
    fn a_template_that_breaks_with_a_local_server_alone_is_refused() {
        let leading_comma = "{\"mcpServers\": { {{#each mcp_servers}}{{#if local}}, \"{{slug}}\": {\"command\": \"{{command}}\"}{{else}}{{#unless @first}}, {{/unless}}\"{{slug}}\": {\"url\": \"{{url}}\"}{{/if}}{{/each}} } }";
        let sound = "{\"mcpServers\": { {{#each mcp_servers}}\"{{slug}}\": {{#if local}}{\"command\": \"{{command}}\"}{{else}}{\"url\": \"{{url}}\"}{{/if}}{{#unless @last}}, {{/unless}}{{/each}} } }";
        let make = |body: &str| {
            let mut t = template(TemplateKind::Mcp, body);
            t.format = TemplateFormat::Json;
            t.local_mcp = LocalMcpForm::Config;
            profile(vec![t])
        };
        // Beside the two gateway servers the body is valid JSON...
        let mut phs = validation_placeholders_for(&make(leading_comma).templates[0]);
        phs.insert("forward_auth".into(), Value::Bool(false));
        crate::render::render(leading_comma, TemplateFormat::Json, &phs).expect("valid beside gateway servers");
        // ...and alone it is not: the save is refused as a render failure.
        assert!(matches!(validate_profile(&make(leading_comma)), Err(ProfileInvalid::Render { .. })));
        validate_profile(&make(sound)).expect("valid with a local server alone");
    }

    /// A YAML template that writes a local server's argument or value bare is
    /// refused — the fixture's `8080` and `true` would reach the client as a
    /// number and a boolean — and the message names the helper. The same
    /// template writing them with `{{quoted …}}` is accepted.
    #[test]
    fn a_yaml_template_that_retypes_a_local_value_is_refused() {
        let body = |arg: &str, value: &str| {
            format!(
                "servers:\n{{{{#each mcp_servers}}}}  - name: {{{{quoted slug}}}}\n{{{{#if local}}}}    command: {{{{quoted command}}}}\n    args:\n{{{{#each args}}}}      - {arg}\n{{{{/each}}}}    env:\n{{{{#each env}}}}      {{{{name}}}}: {value}\n{{{{/each}}}}{{{{else}}}}    url: {{{{quoted url}}}}\n{{{{/if}}}}{{{{/each}}}}"
            )
        };
        let make = |body: String| {
            let mut t = template(TemplateKind::Mcp, &body);
            t.format = TemplateFormat::Yaml;
            t.local_mcp = LocalMcpForm::Config;
            profile(vec![t])
        };
        validate_profile(&make(body("{{quoted value}}", "{{quoted value}}"))).expect("strings stay strings");
        let err = validate_profile(&make(body("{{value}}", "{{quoted value}}"))).unwrap_err();
        assert!(matches!(err, ProfileInvalid::LocalMcpValueRetyped { what: "argument", .. }), "{err}");
        assert!(err.to_string().contains("{{quoted value}}"), "{err}");
        let err = validate_profile(&make(body("{{quoted value}}", "{{value}}"))).unwrap_err();
        assert!(matches!(err, ProfileInvalid::LocalMcpValueRetyped { what: "environment value", .. }), "{err}");
    }

    /// A declared local form is a checked claim: a template that declares one
    /// and writes no local server is refused, as is a project-only one that
    /// writes it outside a project; the same body under the right declaration
    /// is accepted.
    #[test]
    fn a_local_form_declaration_must_match_what_the_template_writes() {
        let with_form = "{\"mcpServers\": { {{#each mcp_servers}}\"{{slug}}\": {{#if local}}{\"command\": \"{{command}}\"}{{else}}{\"url\": \"{{url}}\"}{{/if}}{{#unless @last}}, {{/unless}}{{/each}} } }";
        let without = "{\"mcpServers\": { {{#each mcp_servers}}\"{{slug}}\": {\"url\": \"{{url}}\"}{{#unless @last}}, {{/unless}}{{/each}} } }";
        let make = |body: &str, form: LocalMcpForm| {
            let mut t = template(TemplateKind::Mcp, body);
            t.format = TemplateFormat::Json;
            t.local_mcp = form;
            profile(vec![t])
        };
        validate_profile(&make(with_form, LocalMcpForm::Config)).expect("writes what it declares");
        validate_profile(&make(without, LocalMcpForm::None)).expect("declares nothing, is handed nothing");
        assert!(matches!(
            validate_profile(&make(without, LocalMcpForm::Config)),
            Err(ProfileInvalid::LocalMcpUnwritten { form: "config", .. })
        ));
        assert!(matches!(
            validate_profile(&make(without, LocalMcpForm::Project)),
            Err(ProfileInvalid::LocalMcpUnwritten { form: "project", .. })
        ));
        assert!(matches!(
            validate_profile(&make(with_form, LocalMcpForm::Project)),
            Err(ProfileInvalid::LocalMcpOutsideProject { .. })
        ));
    }
}
