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
//! API key. `{{api_key}}` and the per-server MCP key fields always resolve to
//! literal placeholder strings (`<paste-your-api-key-here>` /
//! `<paste-your-<slug>-mcp-key-here>`). The plaintext is shipped separately in
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

/// Per-MCP-server sentinel for the user's own upstream MCP bearer in BYOT
/// templates. Same no-substitute contract as [`UPSTREAM_API_KEY_PLACEHOLDER`]
/// — the consumer leaves it intact and the user fills it in. Keyed by `slug`
/// so a multi-server BYOT render tells the user which server each blank
/// belongs to.
pub fn upstream_mcp_bearer_placeholder(slug: &str) -> String {
    format!("<paste-your-{slug}-upstream-bearer-here>")
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

fn make_engine(escape: fn(&str) -> String) -> Handlebars<'static> {
    let mut h = Handlebars::new();
    h.register_escape_fn(escape);
    h.register_helper("concat", Box::new(concat));
    h
}

static JSON_ENGINE: LazyLock<Handlebars<'static>> = LazyLock::new(|| make_engine(json_escape));
static YAML_ENGINE: LazyLock<Handlebars<'static>> = LazyLock::new(|| make_engine(yaml_escape));
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

/// YAML scalar escape. Returns either a bare scalar (when the content is
/// simple — no special chars, no whitespace at the edges, not a YAML tag) or
/// a double-quoted scalar with `\` and `"` escaped. Templates that splice
/// values into pre-quoted positions (`apiKey: "{{api_key}}"`) get correct
/// behaviour either way; templates that splice into bare positions
/// (`apiKey: {{api_key}}`) get safe quoting on hostile input.
fn yaml_escape(s: &str) -> String {
    // Booleans / integers from Handlebars come through here as their string
    // representation. Don't quote those — leave them bare so the YAML parser
    // sees them as the right scalar type.
    if s == "true" || s == "false" || s.parse::<i64>().is_ok() {
        return s.to_string();
    }
    let needs_quoting = s.is_empty()
        || s.chars().any(|c| matches!(c, ':' | '#' | '\'' | '"' | '&' | '*' | '?' | '|' | '<' | '>' | '=' | '!' | '%' | '@' | '\\' | '\n' | '\r' | '\t'))
        || s.starts_with('-')
        || s.starts_with(' ')
        || s.ends_with(' ')
        || matches!(s, "null" | "yes" | "no" | "on" | "off" | "~");
    if !needs_quoting {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
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
            c if (c as u32) < 0x20 => {
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
        assert_eq!(yaml_escape("https://gw.acme.io/v1"), "\"https://gw.acme.io/v1\"");
        // Bare bool/int tokens emitted by handlebars stay unquoted so the
        // YAML parser reads them as the right scalar type.
        assert_eq!(yaml_escape("true"), "true");
        assert_eq!(yaml_escape("42"), "42");
        // YAML reserved words still get quoted to force string scalar.
        assert_eq!(yaml_escape("null"), "\"null\"");
        assert_eq!(yaml_escape("yes"), "\"yes\"");
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
}
