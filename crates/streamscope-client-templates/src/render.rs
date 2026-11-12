//! Render engine for client-config snippets (web quickstart + CLI provisioning).
//!
//! Substitutes Handlebars placeholders (`{{ident}}`) in a `ClientProfileTemplate`
//! body, processing `{{#if}}` / `{{#each}}` / `{{#unless}}` block helpers and
//! `@last` / `@first` / `@index` block variables, applying per-format escaping
//! (JSON / YAML / TOML / shell / text) so values land safely inside the
//! surrounding config syntax. Triple-stash `{{{ident}}}` bypasses the escape
//! for placeholders the caller has already rendered in the target format.
//!
//! Threat model: the rendered body never contains a freshly-minted plaintext
//! API key. `{{api_key}}` and every MCP server's header values always resolve
//! to literal placeholder strings (`<paste-your-api-key-here>`, or a
//! client-sent header's `<paste-your-<slug>-<header>-here>`). The plaintext is shipped separately in
//! `MintedSecrets` and substituted into the final payload by the consumer —
//! the web UI at clipboard-copy time (never written to the DOM), the CLI at
//! file-write time.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use handlebars::{handlebars_helper, no_escape, Handlebars, JsonRender};
use serde_json::Value as JsonValue;

use crate::types::TemplateFormat;

/// Sentinel that always maps to the gateway-issued plaintext we minted for the
/// user. The consumer splices `MintedSecrets.api_key` into this string when
/// producing the final payload.
///
/// Two distinct placement modes share this sentinel:
///   - non-BYOK templates: lives in the `Authorization` header — the `sk-*`
///     plaintext is the bearer the client sends.
///   - BYOK templates: lives in the `base_url` (`/fwd/<sentinel>/v1`) — the
///     `vk-*` plaintext identifies the caller; the header carries the user's
///     own upstream key via the separate [`UPSTREAM_API_KEY_PLACEHOLDER`].
///
/// In both modes the substitution target is "the plaintext we minted", which
/// keeps the consumer's substitution logic trivially correct without a
/// mode-aware branch.
pub const API_KEY_PLACEHOLDER: &str = "<paste-your-api-key-here>";

/// Sentinel for the user's own upstream LLM API key (the actual Anthropic /
/// OpenAI / etc. key). Only used by BYOK templates — left UNSUBSTITUTED in the
/// final payload so the user fills it in themselves. The gateway never sees
/// this value at render time; the BYOK proxy path receives it from the
/// client's `Authorization` header on each call and forwards it verbatim
/// upstream.
pub const UPSTREAM_API_KEY_PLACEHOLDER: &str = "<paste-your-upstream-api-key-here>";

/// Sentinel for a header an MCP server's client must send itself on every
/// request (a client-filled header input). Same no-substitute contract as
/// [`UPSTREAM_API_KEY_PLACEHOLDER`]: the consumer leaves it intact and the
/// user fills it in. Keyed by `slug` and header so a multi-server render tells
/// the user which blank belongs where.
pub fn mcp_client_header_placeholder(slug: &str, header: &str) -> String {
    format!("<paste-your-{slug}-{}-here>", header.to_ascii_lowercase())
}

/// One entry of an `mcp_servers[]` item's `headers` list: the header a
/// client config sends to the gateway for that server. A template writes the
/// list with `{{#each headers}}` inside `{{#each mcp_servers}}`, reading
/// `{{name}}` and `{{value}}`; the item's `headers` is a [`Value::List`] of
/// these.
pub fn mcp_header_item(name: &str, value: String) -> BTreeMap<String, Value> {
    let mut m = BTreeMap::new();
    m.insert("name".to_string(), Value::String(name.to_string()));
    m.insert("value".to_string(), Value::String(value));
    m
}

/// A local MCP server's whole launch as a person reads it, and as a shell
/// would read it back: each environment variable the administrator set as
/// `NAME=value`, then the command and its arguments. A variable with no value
/// (the developer's to fill) is not in it.
///
/// Pasted into a POSIX shell or zsh, the line splits into exactly those
/// parts, and its first word that is not one of the `NAME=value` pairs is the
/// command (locked by `a_local_command_line_splits_back_into_its_launch`).
/// So every part holding a character outside `[A-Za-z0-9_@%+:,./-]`, or
/// nothing, is single-quoted: a space, a quote, an operator, an expansion —
/// and `=`, which unquoted would make a command or an argument read as an
/// assignment (and, leading, as zsh's `=command` expansion), as would a
/// leading `~` or `#`. An environment pair is `NAME=` followed by its value
/// under the same rule. The ONE rendering: the admin and portal APIs return
/// it, and the CLI prints and records the same string. Nothing runs it.
pub fn local_command_line(command: &str, args: &[String], env: &[(String, Option<String>)]) -> String {
    fn quoted(part: &str) -> String {
        let safe = |c: char| c.is_ascii_alphanumeric() || "_@%+:,./-".contains(c);
        if !part.is_empty() && part.chars().all(safe) {
            part.to_string()
        } else {
            format!("'{}'", part.replace('\'', "'\\''"))
        }
    }
    env.iter()
        .filter_map(|(name, value)| value.as_ref().map(|v| format!("{name}={}", quoted(v))))
        .chain(std::iter::once(quoted(command)))
        .chain(args.iter().map(|a| quoted(a)))
        .collect::<Vec<_>>()
        .join(" ")
}

/// One `mcp_servers[]` item for a LOCAL MCP server: a server the developer's
/// machine starts. A template that declares a local form
/// ([`crate::types::LocalMcpForm`]) writes it as the client's stdio entry,
/// branching on `{{#if local}}` inside its `{{#each mcp_servers}}` loop:
/// `{{command}}`, `{{#each args}}{{value}}{{/each}}` and
/// `{{#each env}}{{name}}` / `{{value}}{{/each}}`.
///
/// An `env` entry with no value is the developer's to fill: it is written as
/// the same fill-in sentinel a client-sent header gets
/// ([`mcp_client_header_placeholder`]), which the consumer leaves intact and a
/// later write keeps the pasted value over. `headers` is an empty list and
/// there is no `url`, so a part of a template that skips local items reads
/// nothing from one. `command_line` is the whole launch as
/// [`local_command_line`] renders it — what the CLI prints and records.
pub fn mcp_local_server_item(
    slug: &str,
    name: &str,
    description: Option<&str>,
    command: &str,
    args: &[String],
    env: &[(String, Option<String>)],
) -> BTreeMap<String, Value> {
    let mut m: BTreeMap<String, Value> = BTreeMap::new();
    m.insert("slug".into(), Value::String(slug.to_string()));
    m.insert("name".into(), Value::String(name.to_string()));
    if let Some(d) = description {
        m.insert("description".into(), Value::String(d.to_string()));
    }
    m.insert("local".into(), Value::Bool(true));
    m.insert("command".into(), Value::String(command.to_string()));
    m.insert(
        "args".into(),
        Value::List(
            args.iter()
                .map(|a| BTreeMap::from([("value".to_string(), Value::String(a.clone()))]))
                .collect(),
        ),
    );
    m.insert(
        "env".into(),
        Value::List(
            env.iter()
                .map(|(name, value)| {
                    let value = value.clone().unwrap_or_else(|| mcp_client_header_placeholder(slug, name));
                    mcp_header_item(name, value)
                })
                .collect(),
        ),
    );
    m.insert("headers".into(), Value::List(Vec::new()));
    m.insert("transport_hint".into(), Value::String("stdio".into()));
    m.insert("command_line".into(), Value::String(local_command_line(command, args, env)));
    m
}

/// Boolean placeholder that is `true` only when the CLI writes a template at
/// its `project_filename` (`provision --local` / `--dir`). The server never
/// sets it — its render, the web quickstart's and the CLI's parity check all
/// produce the global form — so a body gates project-only content on
/// `{{#if project_scope}}` (e.g. pinning a client to the provisioned provider
/// in a project, which on the global file would hide the user's own).
pub const PROJECT_SCOPE: &str = "project_scope";

/// One value in the placeholder map. Booleans render as JSON-style literals
/// (`true`/`false`); strings are format-escaped per the target format;
/// numbers render verbatim. `None` means "this placeholder is unset for this
/// render call" — `{{ident}}` then expands to the empty string and `{{#if
/// ident}}` evaluates falsey. `List` is iterated by `{{#each ident}} …
/// {{/each}}`; inside the block the per-item map becomes the new scope —
/// unqualified `{{model_alias}}` resolves to the current item's value, and
/// outer-scope placeholders are accessed via `{{../api_key}}` (Handlebars
/// does NOT auto-walk parent scope for unqualified names).
///
/// Serialized form is a tagged union (`{"t": "string", "v": "…"}`) so the
/// provisioning bundle can ship a typed placeholder map over the wire and the
/// CLI re-renders with values identical to the server's.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "t", content = "v", rename_all = "snake_case")]
pub enum Value {
    String(String),
    Bool(bool),
    Int(i64),
    #[cfg_attr(feature = "openapi", schema(no_recursion))]
    List(Vec<BTreeMap<String, Value>>),
    None,
}

impl From<String> for Value {
    fn from(s: String) -> Self { Value::String(s) }
}
impl From<&str> for Value {
    fn from(s: &str) -> Self { Value::String(s.to_string()) }
}
impl From<bool> for Value {
    fn from(b: bool) -> Self { Value::Bool(b) }
}
impl From<i64> for Value {
    fn from(n: i64) -> Self { Value::Int(n) }
}
impl From<i32> for Value {
    fn from(n: i32) -> Self { Value::Int(n as i64) }
}
impl<T: Into<Value>> From<Option<T>> for Value {
    fn from(o: Option<T>) -> Self {
        match o {
            Some(v) => v.into(),
            None => Value::None,
        }
    }
}

fn value_to_json(v: &Value) -> JsonValue {
    match v {
        Value::String(s) => JsonValue::String(s.clone()),
        Value::Bool(b) => JsonValue::Bool(*b),
        Value::Int(n) => JsonValue::Number((*n).into()),
        Value::List(items) => JsonValue::Array(
            items
                .iter()
                .map(|item| {
                    JsonValue::Object(
                        item.iter()
                            .map(|(k, v)| (k.clone(), value_to_json(v)))
                            .collect(),
                    )
                })
                .collect(),
        ),
        Value::None => JsonValue::Null,
    }
}

fn placeholders_to_json(phs: &BTreeMap<String, Value>) -> JsonValue {
    JsonValue::Object(
        phs.iter()
            .map(|(k, v)| (k.clone(), value_to_json(v)))
            .collect(),
    )
}

#[derive(Debug, thiserror::Error)]
pub enum RenderError {
    #[error("template body parses as invalid {format:?}: {message}")]
    InvalidOutput { format: TemplateFormat, message: String },
    #[error("template render failed: {0}")]
    Template(String),
}

// `{{concat "openai/" model_alias}}` joins its arguments into ONE value, which
// the format's escape then sees whole. A placeholder written after literal text
// (`model: openai/{{model_alias}}`) is escaped alone: in YAML a value that needs
// quoting (`qwen3:8b`, a `<…>` sentinel) becomes `openai/"qwen3:8b"`, a scalar
// that keeps the quotes. Build any value with a fixed prefix or suffix with it.
handlebars_helper!(concat: |*args| args.iter().map(|v| v.render()).collect::<String>());

/// The name of the YAML string helper: `{{quoted value}}`.
pub const YAML_STRING_HELPER: &str = "quoted";

/// `{{quoted value}}` — YAML only. Writes its argument as a double-quoted
/// scalar, always: the position is a STRING by contract, whatever the text
/// looks like. `{{value}}` cannot know that — the escaper is handed text, not
/// a type, and leaves `8080` or `true` bare so a typed integer or boolean
/// keeps its type. A value that is text someone chose — a local MCP server's
/// command, each of its arguments and environment values, a server's slug, a
/// header's value — is written with this helper, so `--port 8080` stays the
/// string `"8080"` (locked by `a_string_comes_back_from_each_format_as_the_same_string`).
/// It writes the quotes itself: never put it inside quotes.
struct QuotedHelper;

impl handlebars::HelperDef for QuotedHelper {
    fn call<'reg: 'rc, 'rc>(
        &self,
        h: &handlebars::Helper<'rc>,
        _: &'reg Handlebars<'reg>,
        _: &'rc handlebars::Context,
        _: &mut handlebars::RenderContext<'reg, 'rc>,
        out: &mut dyn handlebars::Output,
    ) -> handlebars::HelperResult {
        let value = h
            .param(0)
            .ok_or_else(|| handlebars::RenderErrorReason::ParamNotFoundForIndex(YAML_STRING_HELPER, 0))?
            .value();
        // Written as it is: the helper's output does not pass the escaper.
        out.write(&yaml_double_quoted(&value.render()))?;
        Ok(())
    }
}

fn make_engine(escape: fn(&str) -> String) -> Handlebars<'static> {
    let mut h = Handlebars::new();
    h.register_escape_fn(escape);
    h.register_helper("concat", Box::new(concat));
    h
}

static JSON_ENGINE: LazyLock<Handlebars<'static>> = LazyLock::new(|| make_engine(json_escape));
static YAML_ENGINE: LazyLock<Handlebars<'static>> = LazyLock::new(|| {
    let mut h = make_engine(yaml_escape);
    h.register_helper(YAML_STRING_HELPER, Box::new(QuotedHelper));
    h
});
static TOML_ENGINE: LazyLock<Handlebars<'static>> = LazyLock::new(|| make_engine(toml_escape));
static SHELL_ENGINE: LazyLock<Handlebars<'static>> = LazyLock::new(|| make_engine(shell_escape));
static TEXT_ENGINE: LazyLock<Handlebars<'static>> = LazyLock::new(|| make_engine(no_escape));

fn engine_for(format: TemplateFormat) -> &'static Handlebars<'static> {
    match format {
        TemplateFormat::Json => &JSON_ENGINE,
        TemplateFormat::Yaml => &YAML_ENGINE,
        TemplateFormat::Toml => &TOML_ENGINE,
        TemplateFormat::Shell => &SHELL_ENGINE,
        TemplateFormat::Text => &TEXT_ENGINE,
    }
}

/// Render a template body with Handlebars substitution + per-format escape,
/// then syntactically validate the output against the declared format.
pub fn render(
    body: &str,
    format: TemplateFormat,
    placeholders: &BTreeMap<String, Value>,
) -> Result<String, RenderError> {
    let rendered = render_unvalidated(body, format, placeholders)?;
    validate(&rendered, format)?;
    Ok(rendered)
}

fn render_unvalidated(
    body: &str,
    format: TemplateFormat,
    placeholders: &BTreeMap<String, Value>,
) -> Result<String, RenderError> {
    let ctx = placeholders_to_json(placeholders);
    engine_for(format)
        .render_template(body, &ctx)
        .map_err(|e| RenderError::Template(e.to_string()))
}

/// [`render`] for a body that may render to nothing: `None` when the output is
/// whitespace only, else the validated output.
pub(crate) fn render_unless_empty(
    body: &str,
    format: TemplateFormat,
    placeholders: &BTreeMap<String, Value>,
) -> Result<Option<String>, RenderError> {
    let rendered = render_unvalidated(body, format, placeholders)?;
    if rendered.trim().is_empty() {
        return Ok(None);
    }
    validate(&rendered, format)?;
    Ok(Some(rendered))
}

/// JSON inner-string escape — caller is responsible for the surrounding
/// quotes (templates already wrap `{{ident}}` in `"…"`).
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// YAML scalar escape, for a value spliced where a scalar stands on its own
/// (`key: {{value}}`, `- {{value}}`, `[{{value}}]`).
///
/// The text of a typed integer or boolean stays bare, so the parser reads its
/// type. Any other text is written bare only when it is plainly a word —
/// ASCII letters, digits, `_ . / -` and single inner spaces, starting with a
/// letter, `_` or `/`, and not one of YAML's own words — and double-quoted
/// otherwise, so it comes back the same string.
///
/// NOT claimed: a STRING that reads as an integer or a boolean (`8080`,
/// `true`) — handed text, not a type, this escaper cannot tell it from a typed
/// one and leaves it bare; a position that is a string by contract uses
/// `{{quoted value}}` ([`YAML_STRING_HELPER`]). Nor a value spliced inside a
/// scalar the template already quoted, or after literal text
/// (`model: openai/{{alias}}` — build it with `concat`).
fn yaml_escape(s: &str) -> String {
    if s == "true" || s == "false" || s.parse::<i64>().is_ok() {
        return s.to_string();
    }
    let word = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '/' | '-' | ' ');
    let reserved = ["null", "true", "false", "yes", "no", "on", "off", "y", "n"];
    let plain = s.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_' || c == '/')
        && s.chars().all(word)
        && !s.ends_with(' ')
        && !s.contains("  ")
        && !s.contains(" -")
        && !reserved.iter().any(|r| s.eq_ignore_ascii_case(r));
    if plain {
        return s.to_string();
    }
    yaml_double_quoted(s)
}

/// `s` as a YAML double-quoted scalar: it reads back as exactly `s`.
fn yaml_double_quoted(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // What a YAML reader takes for a line break, or refuses unescaped.
            '\u{85}' => out.push_str("\\N"),
            '\u{2028}' => out.push_str("\\L"),
            '\u{2029}' => out.push_str("\\P"),
            '\u{FEFF}' | '\u{FFFE}' | '\u{FFFF}' => out.push_str(&format!("\\u{:04X}", c as u32)),
            c if (c as u32) < 0x20 || (0x7F..0xA0).contains(&(c as u32)) => {
                out.push_str(&format!("\\x{:02X}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// TOML basic-string inner escape (caller wraps in `"…"`).
fn toml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c == '\u{7F}' => {
                out.push_str(&format!("\\u{:04X}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// Shell escape that's safe inside *any* surrounding context — bare token,
/// single-quoted, or (most relevantly) splice-substitution into a
/// double-quoted string. Returns the value verbatim when every character
/// is in the safe set (alphanumeric + a small allow-list common in URLs,
/// keys, and model aliases). Otherwise wraps with POSIX single-quoting.
fn shell_escape(s: &str) -> String {
    let safe = !s.is_empty()
        && s.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    '_' | '-' | '.' | '/' | ':' | '=' | ',' | '@'
                        | '+' | '%' | '#' | '?' | '&' | '<' | '>'
                )
        });
    if safe {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// Best-effort syntactic validation of the rendered body. JSON / TOML get
/// parsed; YAML is parsed via `yaml_serde`; shell is left alone (we trust
/// our own templates and admin-edited shell snippets are inherently free
/// form). `Text` skips validation entirely.
fn validate(s: &str, format: TemplateFormat) -> Result<(), RenderError> {
    match format {
        TemplateFormat::Json => serde_json::from_str::<serde_json::Value>(s)
            .map(|_| ())
            .map_err(|e| RenderError::InvalidOutput { format, message: e.to_string() }),
        TemplateFormat::Yaml => yaml_serde::from_str::<yaml_serde::Value>(s)
            .map(|_| ())
            .map_err(|e| RenderError::InvalidOutput { format, message: e.to_string() }),
        TemplateFormat::Toml => s
            .parse::<toml::Table>()
            .map(|_| ())
            .map_err(|e| RenderError::InvalidOutput { format, message: e.to_string() }),
        TemplateFormat::Shell | TemplateFormat::Text => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    fn ph<const N: usize>(entries: [(&str, Value); N]) -> BTreeMap<String, Value> {
        entries.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
    }

    /// A value built with `concat` reaches the client as exactly the joined
    /// text, whatever the alias holds — the YAML escape quotes the WHOLE scalar.
    /// The same text after a literal prefix keeps the escape's quotes inside the
    /// value (the positive control: the shape `concat` exists to replace).
    #[test]
    fn a_concat_value_is_one_scalar_whatever_its_parts_hold() {
        for alias in ["mock-model", "qwen3:8b", "<your-model-name>", "a\"b", "x #y", "null", "-lead", "a\\b", "42"] {
            let phs = ph([("model_alias", alias.into())]);
            let out = render("model: {{concat \"openai/\" model_alias}}\n", TemplateFormat::Yaml, &phs).unwrap();
            let v: yaml_serde::Value = yaml_serde::from_str(&out).unwrap();
            assert_eq!(v["model"].as_str(), Some(format!("openai/{alias}").as_str()), "{alias}: {out}");

            // The JSON escape sees the joined value too (inside its quotes).
            let out = render("{\"model\": \"{{concat \"openai/\" model_alias}}\"}", TemplateFormat::Json, &phs).unwrap();
            let v: serde_json::Value = serde_json::from_str(&out).unwrap();
            assert_eq!(v["model"].as_str(), Some(format!("openai/{alias}").as_str()), "{alias}: {out}");
        }
        let phs = ph([("model_alias", "qwen3:8b".into())]);
        let out = render("model: openai/{{model_alias}}\n", TemplateFormat::Yaml, &phs).unwrap();
        let v: yaml_serde::Value = yaml_serde::from_str(&out).unwrap();
        assert_eq!(v["model"].as_str(), Some("openai/\"qwen3:8b\""), "{out}");
    }

    #[test]
    fn json_substitution_round_trip() {
        let body = r#"{ "key": "{{api_key}}", "model": "{{model}}" }"#;
        let phs = ph([
            ("api_key", "<paste-your-api-key-here>".into()),
            ("model", "claude-sonnet-4-5".into()),
        ]);
        let out = render(body, TemplateFormat::Json, &phs).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["key"], "<paste-your-api-key-here>");
        assert_eq!(v["model"], "claude-sonnet-4-5");
    }

    #[test]
    fn json_escapes_quotes_in_value() {
        let body = r#"{ "name": "{{name}}" }"#;
        let phs = ph([("name", "he said \"hi\"".into())]);
        let out = render(body, TemplateFormat::Json, &phs).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["name"], "he said \"hi\"");
    }

    #[test]
    fn yaml_conditional_block_drops_cleanly() {
        let body = "models:\n  - name: x\n{{#if mcp}}\nmcpServers:\n  - name: y\n{{/if}}\n";
        let off = render(body, TemplateFormat::Yaml, &ph([("mcp", false.into())])).unwrap();
        assert!(!off.contains("mcpServers"), "block should be removed; got:\n{off}");
        yaml_serde::from_str::<yaml_serde::Value>(&off).expect("parses");

        let on = render(body, TemplateFormat::Yaml, &ph([("mcp", true.into())])).unwrap();
        assert!(on.contains("mcpServers"));
        yaml_serde::from_str::<yaml_serde::Value>(&on).expect("parses");
    }

    #[test]
    fn json_conditional_inline() {
        let body = r#"{"a": 1{{#if extra}}, "b": 2{{/if}}}"#;
        let off = render(body, TemplateFormat::Json, &ph([("extra", false.into())])).unwrap();
        let v: serde_json::Value = serde_json::from_str(&off).unwrap();
        assert_eq!(v["b"], serde_json::Value::Null);
        let on = render(body, TemplateFormat::Json, &ph([("extra", true.into())])).unwrap();
        let v: serde_json::Value = serde_json::from_str(&on).unwrap();
        assert_eq!(v["b"], 2);
    }

    #[test]
    fn toml_substitution() {
        let body = "model = \"{{model}}\"\n[provider]\nbase_url = \"{{base_url}}\"\n";
        let phs = ph([
            ("model", "claude-sonnet-4-5".into()),
            ("base_url", "https://gw.acme.io/v1".into()),
        ]);
        let out = render(body, TemplateFormat::Toml, &phs).unwrap();
        let v: toml::Value = toml::from_str(&out).unwrap();
        assert_eq!(v["model"].as_str(), Some("claude-sonnet-4-5"));
        assert_eq!(v["provider"]["base_url"].as_str(), Some("https://gw.acme.io/v1"));
    }

    #[test]
    fn shell_escapes_single_quote() {
        let body = "echo {{name}}";
        let out = render(body, TemplateFormat::Shell, &ph([("name", "Bob's key".into())])).unwrap();
        assert_eq!(out, "echo 'Bob'\\''s key'");
    }

    #[test]
    fn unknown_ident_renders_empty() {
        // Handlebars default (non-strict): missing keys render as empty string.
        let body = "x = {{unknown}}";
        let out = render(body, TemplateFormat::Text, &BTreeMap::new()).unwrap();
        assert_eq!(out, "x = ");
    }

    #[test]
    fn unbalanced_block_errors() {
        let body = "{{#if x}} no close";
        let err = render(body, TemplateFormat::Text, &ph([("x", true.into())])).unwrap_err();
        assert_matches!(err, RenderError::Template(_));
    }

    #[test]
    fn validate_rejects_broken_json() {
        let body = r#"{ "k": {{n}} broken "#;
        let phs = ph([("n", 1i32.into())]);
        let err = render(body, TemplateFormat::Json, &phs).unwrap_err();
        assert_matches!(err, RenderError::InvalidOutput { .. });
    }

    #[test]
    fn yaml_escape_keeps_simple_values_bare_and_quotes_dangerous_ones() {
        assert_eq!(yaml_escape("claude-sonnet-4-5"), "claude-sonnet-4-5");
        assert_eq!(yaml_escape("two words"), "two words");
        assert_eq!(yaml_escape("https://gw.acme.io/v1"), "\"https://gw.acme.io/v1\"");
        // The text of a typed boolean or integer stays bare, so the YAML
        // parser reads its type.
        assert_eq!(yaml_escape("true"), "true");
        assert_eq!(yaml_escape("42"), "42");
        // Everything YAML would read as something else is quoted.
        for s in ["null", "Null", "NULL", "yes", "No", "ON", "~", "True", "FALSE", "3.12", "1e5", "0x1F", ".5",
                  "2026-11-11", "-lead", "?q", ":c", "#c", "&a", "*a", "!t", "|", ">", "%d", "@a", "{a}", "[x]",
                  "a: b", "a #b", "", " lead", "trail ", "a  b", "a - b", "é"] {
            assert_eq!(yaml_escape(s), format!("\"{s}\""), "{s:?}");
        }
    }

    /// A typed value keeps its type through `{{value}}`; a position that is a
    /// string by contract is written with `{{quoted value}}` and comes back a
    /// string whatever it reads as. The same string through `{{value}}` reads
    /// as a number or a boolean — the control that shows why the helper exists.
    #[test]
    fn yaml_keeps_a_typed_value_typed_and_a_quoted_string_a_string() {
        let phs = ph([
            ("port", "8080".into()),
            ("flag", "true".into()),
            ("version", "3.12".into()),
            ("window", 200_000i64.into()),
            ("vision", true.into()),
        ]);
        let out = render(
            "port: {{quoted port}}\nflag: {{quoted flag}}\nversion: {{quoted version}}\nwindow: {{window}}\nvision: {{vision}}\nargs:\n  - {{quoted port}}\nbare_port: {{port}}\nbare_flag: {{flag}}\n",
            TemplateFormat::Yaml,
            &phs,
        )
        .unwrap();
        let v: yaml_serde::Value = yaml_serde::from_str(&out).unwrap();
        assert_eq!(v["port"].as_str(), Some("8080"), "{out}");
        assert_eq!(v["flag"].as_str(), Some("true"), "{out}");
        assert_eq!(v["version"].as_str(), Some("3.12"), "{out}");
        assert_eq!(v["args"][0].as_str(), Some("8080"), "{out}");
        assert_eq!(v["window"].as_i64(), Some(200_000), "{out}");
        assert_eq!(v["vision"].as_bool(), Some(true), "{out}");
        assert_eq!(v["bare_port"].as_i64(), Some(8080), "{out}");
        assert_eq!(v["bare_flag"].as_bool(), Some(true), "{out}");
        // The helper is YAML's: another format has its own quotes.
        assert_matches!(
            render("{\"port\": {{quoted port}}}", TemplateFormat::Json, &phs).unwrap_err(),
            RenderError::Template(_)
        );
    }

    mod escaper_properties {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// Whatever a string holds — short of a control character — it
            /// comes back from the format's own parser as the same string,
            /// written the way the seeds write a local MCP entry: through
            /// `{{quoted …}}` in YAML (a mapping value, a mapping key, a block
            /// list item, a flow list item), inside a basic string in TOML,
            /// inside a string in JSON. In YAML the bare `{{value}}` path
            /// holds the same for every string but one that reads as an
            /// integer or a boolean, which it leaves typed.
            ///
            /// NOT a property, deliberately: that bare path for a string that
            /// reads as an integer or a boolean (use the helper); a value
            /// spliced inside a scalar the template already quoted in YAML,
            /// or after literal text (`concat` builds those); the shell and
            /// text formats, which have no parser to hold them to; a string
            /// holding a control character.
            #[test]
            fn a_string_comes_back_from_each_format_as_the_same_string(s in any_text(24)) {
                let phs = ph([("v", Value::String(s.clone()))]);

                let yaml = render(
                    "k: {{quoted v}}\nl:\n  - {{quoted v}}\nf: [{{quoted v}}]\nm:\n  {{quoted v}}: x\n",
                    TemplateFormat::Yaml,
                    &phs,
                )
                .unwrap();
                let v: yaml_serde::Value = yaml_serde::from_str(&yaml).unwrap();
                prop_assert_eq!(v["k"].as_str(), Some(s.as_str()), "{:?}", yaml);
                prop_assert_eq!(v["l"][0].as_str(), Some(s.as_str()), "{:?}", yaml);
                prop_assert_eq!(v["f"][0].as_str(), Some(s.as_str()), "{:?}", yaml);
                let key = v["m"].as_mapping().and_then(|m| m.keys().next()).and_then(|k| k.as_str());
                prop_assert_eq!(key, Some(s.as_str()), "{:?}", yaml);

                if !(s == "true" || s == "false" || s.parse::<i64>().is_ok()) {
                    let bare = render("k: {{v}}\nl:\n  - {{v}}\nf: [{{v}}]\n", TemplateFormat::Yaml, &phs).unwrap();
                    let v: yaml_serde::Value = yaml_serde::from_str(&bare).unwrap();
                    prop_assert_eq!(v["k"].as_str(), Some(s.as_str()), "{:?}", bare);
                    prop_assert_eq!(v["l"][0].as_str(), Some(s.as_str()), "{:?}", bare);
                    prop_assert_eq!(v["f"][0].as_str(), Some(s.as_str()), "{:?}", bare);
                }

                let toml_text = render("k = \"{{v}}\"\na = [\"{{v}}\"]\n", TemplateFormat::Toml, &phs).unwrap();
                let t: toml::Table = toml_text.parse().unwrap();
                prop_assert_eq!(t["k"].as_str(), Some(s.as_str()), "{:?}", toml_text);
                prop_assert_eq!(t["a"][0].as_str(), Some(s.as_str()), "{:?}", toml_text);

                let json = render("{\"k\": \"{{v}}\", \"a\": [\"{{v}}\"]}", TemplateFormat::Json, &phs).unwrap();
                let j: serde_json::Value = serde_json::from_str(&json).unwrap();
                prop_assert_eq!(j["k"].as_str(), Some(s.as_str()), "{:?}", json);
                prop_assert_eq!(j["a"][0].as_str(), Some(s.as_str()), "{:?}", json);
            }

            /// A rendered launch splits back, as a POSIX shell splits words,
            /// into exactly its parts: one `NAME=value` word per variable the
            /// administrator set, then the command, then each argument — and
            /// the command is the first word a shell would not take for an
            /// assignment. Not claimed: what the words do once run.
            #[test]
            fn a_local_command_line_splits_back_into_its_launch(
                command in any_text(12).prop_filter("a command is not empty", |c| !c.is_empty()),
                args in prop::collection::vec(any_text(12), 0..4),
                env in prop::collection::vec(("[A-Za-z_][A-Za-z0-9_]{0,6}", prop::option::of(any_text(12))), 0..3),
            ) {
                let line = local_command_line(&command, &args, &env);
                let words = shlex::split(&line).expect("the line is well-formed shell");
                let mut want: Vec<String> = env
                    .iter()
                    .filter_map(|(name, value)| value.as_ref().map(|v| format!("{name}={v}")))
                    .collect();
                let assignments = want.len();
                want.push(command.clone());
                want.extend(args.iter().cloned());
                prop_assert_eq!(&words, &want, "{}", line);

                // As the shell reads the RAW line: a word is an assignment
                // only while it starts with an unquoted `NAME=`. The first
                // word that does not is the command.
                let raw: Vec<&str> = raw_words(&line);
                prop_assert_eq!(raw.len(), want.len(), "{}", line);
                let is_assignment = |w: &str| {
                    w.split_once('=').is_some_and(|(name, _)| {
                        !name.is_empty()
                            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                            && !name.starts_with(|c: char| c.is_ascii_digit())
                    })
                };
                prop_assert_eq!(raw.iter().position(|w| !is_assignment(w)), Some(assignments), "{}", line);
                for word in &raw[assignments..] {
                    prop_assert!(!is_assignment(word), "{} in {}", word, line);
                    // Nothing zsh or a POSIX shell expands at the start of a word.
                    prop_assert!(!word.starts_with(['=', '~', '#']), "{} in {}", word, line);
                }
            }
        }

        /// Text with no control character, weighted toward what breaks an
        /// escaper: any Unicode; printable ASCII; short strings of digits and
        /// of YAML and shell punctuation; and the words a format reads as
        /// something other than a string.
        fn any_text(max: usize) -> impl Strategy<Value = String> {
            prop_oneof![
                proptest::string::string_regex(&format!("[^\\p{{Cc}}]{{0,{max}}}")).expect("a regex"),
                proptest::string::string_regex(&format!("[ -~]{{0,{max}}}")).expect("a regex"),
                proptest::string::string_regex("[0-9eE.+-]{0,6}").expect("a regex"),
                proptest::string::string_regex("[a-z0-9 :#~=&*!|>%@`'\"\\\\{}\\[\\],?$-]{0,8}").expect("a regex"),
                prop::sample::select(vec![
                    "true", "false", "True", "TRUE", "null", "Null", "~", "yes", "no", "on", "off", "8080", "-1",
                    "3.12", "1e5", "0x1F", ".inf", "{a}", "[x]", "- a", "? a", ": a", "# a", "&a", "*a", "!a", "|", ">",
                    "%a", "@a", "", " ", "a ", " a", "a: b", "a #b", "=a", "~/a", "a=b", "--x=y",
                ])
                .prop_map(str::to_string),
            ]
        }

        /// The words of a rendered line as written, quotes kept: split on the
        /// spaces outside single quotes.
        fn raw_words(line: &str) -> Vec<&str> {
            let mut words = Vec::new();
            let (mut start, mut quoted, mut escaped) = (0, false, false);
            for (i, c) in line.char_indices() {
                match c {
                    // Outside quotes a backslash takes the next character
                    // literally (the `'\''` that writes a quote).
                    _ if escaped => escaped = false,
                    '\\' if !quoted => escaped = true,
                    '\'' => quoted = !quoted,
                    ' ' if !quoted => {
                        words.push(&line[start..i]);
                        start = i + 1;
                    }
                    _ => {}
                }
            }
            words.push(&line[start..]);
            words
        }
    }

    #[test]
    fn triple_stash_bypasses_escape_for_pre_rendered_fragments() {
        let body = r#"{ "headers": { {{{mcp_auth_header}}} } }"#;
        let phs = ph([(
            "mcp_auth_header",
            "\"Authorization\": \"Bearer <paste-your-web-mcp-key-here>\"".into(),
        )]);
        let out = render(body, TemplateFormat::Json, &phs).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            v["headers"]["Authorization"],
            "Bearer <paste-your-web-mcp-key-here>"
        );
    }

    #[test]
    fn each_block_iterates_yaml_models() {
        let body = "models:\n{{#each routes}}  - name: {{model_alias}}\n    apiBase: {{base_url}}\n{{/each}}";
        let mut item1: BTreeMap<String, Value> = BTreeMap::new();
        item1.insert("model_alias".to_string(), Value::String("claude-sonnet".into()));
        item1.insert("base_url".to_string(), Value::String("https://gw/v1".into()));
        let mut item2: BTreeMap<String, Value> = BTreeMap::new();
        item2.insert("model_alias".to_string(), Value::String("claude-opus".into()));
        item2.insert("base_url".to_string(), Value::String("https://gw/v1".into()));
        let phs = ph([("routes", Value::List(vec![item1, item2]))]);
        let out = render(body, TemplateFormat::Yaml, &phs).unwrap();
        let parsed: yaml_serde::Value = yaml_serde::from_str(&out).unwrap();
        let arr = parsed["models"].as_sequence().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["name"].as_str(), Some("claude-sonnet"));
        assert_eq!(arr[1]["name"].as_str(), Some("claude-opus"));
    }

    #[test]
    fn each_block_at_last_drops_trailing_separator() {
        // The Crush + opencode templates rely on @last to write JSON arrays
        // without trailing commas. Verify the output parses as JSON.
        let body = r#"{"items": [{{#each routes}}{"id": "{{id}}"}{{#unless @last}},{{/unless}}{{/each}}]}"#;
        let mut a: BTreeMap<String, Value> = BTreeMap::new();
        a.insert("id".to_string(), "a".into());
        let mut b: BTreeMap<String, Value> = BTreeMap::new();
        b.insert("id".to_string(), "b".into());
        let phs = ph([("routes", Value::List(vec![a, b]))]);
        let out = render(body, TemplateFormat::Json, &phs).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["items"][0]["id"], "a");
        assert_eq!(v["items"][1]["id"], "b");
    }

    #[test]
    fn each_block_empty_list_drops_block() {
        let body = "models:\n{{#each routes}}  - {{x}}\n{{/each}}done";
        let phs = ph([("routes", Value::List(vec![]))]);
        let out = render(body, TemplateFormat::Text, &phs).unwrap();
        assert!(out.contains("done"));
    }

    #[test]
    fn capability_bool_renders_as_json_literal() {
        let body = r#"{"v": {{vision}}}"#;
        let on = render(body, TemplateFormat::Json, &ph([("vision", true.into())])).unwrap();
        assert_eq!(serde_json::from_str::<serde_json::Value>(&on).unwrap()["v"], true);
        let off = render(body, TemplateFormat::Json, &ph([("vision", false.into())])).unwrap();
        assert_eq!(serde_json::from_str::<serde_json::Value>(&off).unwrap()["v"], false);
    }

    #[test]
    fn each_block_requires_explicit_parent_ref_for_outer_scope() {
        // Handlebars does NOT walk parent scope for unqualified names inside
        // an `{{#each}}` block — the per-item context is the only scope a
        // bare `{{name}}` is resolved against. Templates that need the
        // parent's value (e.g. continue.json referencing the top-level
        // `api_key` inside its per-model loop) must use `{{../name}}`.
        let body_unqualified = r#"{{#each routes}}{{model_alias}}={{api_key}};{{/each}}"#;
        let body_parent_ref = r#"{{#each routes}}{{model_alias}}={{../api_key}};{{/each}}"#;
        let mut item: BTreeMap<String, Value> = BTreeMap::new();
        item.insert("model_alias".to_string(), "claude".into());
        let phs = ph([
            ("routes", Value::List(vec![item])),
            ("api_key", "<paste-your-api-key-here>".into()),
        ]);
        // Unqualified lookup returns empty — per-item scope has no api_key.
        let out = render(body_unqualified, TemplateFormat::Text, &phs).unwrap();
        assert_eq!(out, "claude=;");
        // Explicit `../` walks parent and finds the value.
        let out = render(body_parent_ref, TemplateFormat::Text, &phs).unwrap();
        assert_eq!(out, "claude=<paste-your-api-key-here>;");
    }

    #[test]
    fn value_serde_round_trips_tagged_union() {
        let mut item: BTreeMap<String, Value> = BTreeMap::new();
        item.insert("slug".to_string(), "web".into());
        let phs = ph([
            ("api_key", "<paste-your-api-key-here>".into()),
            ("vision", true.into()),
            ("context_window", Value::Int(200_000)),
            ("mcp_servers", Value::List(vec![item])),
            ("unset", Value::None),
        ]);
        let wire = serde_json::to_string(&phs).unwrap();
        let back: BTreeMap<String, Value> = serde_json::from_str(&wire).unwrap();
        // Round-tripped map renders identically to the original.
        let body = "{{api_key}}|{{vision}}|{{context_window}}|{{#each mcp_servers}}{{slug}}{{/each}}|{{#if unset}}x{{/if}}";
        let a = render(body, TemplateFormat::Text, &phs).unwrap();
        let b = render(body, TemplateFormat::Text, &back).unwrap();
        assert_eq!(a, b);
        assert_eq!(a, "<paste-your-api-key-here>|true|200000|web|");
    }

    /// The per-server header list renders inside the per-server loop in every
    /// format, each value escaped for its format, the gateway key sentinel and
    /// a client-header sentinel both intact.
    #[test]
    fn an_mcp_server_header_list_renders_nested_in_every_format() {
        let server = |slug: &str| {
            let mut m = BTreeMap::new();
            m.insert("slug".to_string(), Value::String(slug.into()));
            m.insert(
                "headers".to_string(),
                Value::List(vec![
                    super::mcp_header_item("Authorization", format!("Bearer {API_KEY_PLACEHOLDER}")),
                    super::mcp_header_item("X-Jira-Token", super::mcp_client_header_placeholder(slug, "X-Jira-Token")),
                ]),
            );
            m
        };
        let phs = ph([("mcp_servers", Value::List(vec![server("jira"), server("wiki")]))]);
        let bodies = [
            (
                TemplateFormat::Json,
                r#"{"s": { {{#each mcp_servers}}"{{slug}}": { {{#each headers}}"{{name}}": "{{value}}"{{#unless @last}}, {{/unless}}{{/each}} }{{#unless @last}}, {{/unless}}{{/each}} } }"#,
            ),
            (
                TemplateFormat::Yaml,
                "s:\n{{#each mcp_servers}}  {{slug}}:\n{{#each headers}}    {{name}}: {{value}}\n{{/each}}{{/each}}",
            ),
            (
                TemplateFormat::Toml,
                "{{#each mcp_servers}}[s.{{slug}}.headers]\n{{#each headers}}\"{{name}}\" = \"{{value}}\"\n{{/each}}{{/each}}",
            ),
            (
                TemplateFormat::Shell,
                "{{#each mcp_servers}}{{#each headers}}echo {{value}}\n{{/each}}{{/each}}",
            ),
            (TemplateFormat::Text, "{{#each mcp_servers}}{{#each headers}}{{name}}={{value}};{{/each}}{{/each}}"),
        ];
        for (format, body) in bodies {
            let out = render(body, format, &phs).unwrap_or_else(|e| panic!("{format:?}: {e}"));
            for slug in ["jira", "wiki"] {
                assert!(out.contains(&format!("<paste-your-{slug}-x-jira-token-here>")), "{format:?}:\n{out}");
            }
            assert_eq!(out.matches(API_KEY_PLACEHOLDER).count(), 2, "{format:?}:\n{out}");
        }
    }
    /// The one command-line rendering: admin-set environment first, a variable
    /// left to the developer absent, and every part a shell would split,
    /// expand or read as an assignment single-quoted — on each side of the
    /// safe set.
    #[test]
    fn a_local_command_line_is_the_whole_launch_and_shell_safe() {
        let args = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let env = |e: &[(&str, Option<&str>)]| -> Vec<(String, Option<String>)> {
            e.iter().map(|(n, v)| (n.to_string(), v.map(str::to_string))).collect()
        };
        assert_eq!(local_command_line("npx", &args(&["-y", "@scope/pkg@1.0.0"]), &[]), "npx -y @scope/pkg@1.0.0");
        assert_eq!(
            local_command_line(
                "npx",
                &args(&["-y", "pkg@1.0.0"]),
                &env(&[("LOG_LEVEL", Some("info")), ("API_TOKEN", None), ("NOTE", Some("two words")), ("EQ", Some("a=b"))]),
            ),
            "LOG_LEVEL=info NOTE='two words' EQ='a=b' npx -y pkg@1.0.0"
        );
        // Every safe character stays bare; each character outside the set quotes its part.
        assert_eq!(local_command_line("a_b@c%d+e:g,h.i/j-k", &[], &[]), "a_b@c%d+e:g,h.i/j-k");
        for unsafe_part in ["", "a b", "a;b", "$HOME", "`id`", "a|b", "a&b", "a>b", "a*b", "~", "~/x", "a\\b", "a\"b", "é",
                            "a\tb", "#x", "(x)", "!x", "a?b", "{a,b}", "a=b", "=ls", "--port=8080", "pkg==1.0.0"] {
            assert_eq!(local_command_line("cmd", &args(&[unsafe_part]), &[]), format!("cmd '{unsafe_part}'"), "{unsafe_part:?}");
            // The command is quoted by the same rule: `FOO=bar` as a command
            // never reads as an assignment.
            assert_eq!(local_command_line(unsafe_part, &[], &[]), format!("'{unsafe_part}'"), "{unsafe_part:?}");
        }
        assert_eq!(local_command_line("cmd", &args(&["it's"]), &[]), "cmd 'it'\\''s'");
        assert_eq!(local_command_line("/opt/my tool/run", &[], &env(&[("K", Some("$(id)"))])), "K='$(id)' '/opt/my tool/run'");
    }

}
