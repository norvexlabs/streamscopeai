//! Companion files a client needs alongside its config template.
//!
//! Some tools read their credential from a file the profile's single template
//! cannot express: Gemini CLI and Mistral Vibe take it from an auto-loaded
//! `.env`, Goose from `secrets.yaml` beside its `config.yaml`. Aider reads
//! its models' window from `.aider.model.metadata.json` beside its config. A companion with
//! no path is a step the user runs instead (Claude Code's `claude mcp add-json`
//! commands: it keeps its MCP servers in a file holding its own state). The
//! companion is therefore part of the config, not an extra — a render that
//! omits it hands the user a config with no credential, or no server, in it.
//!
//! INVARIANT: this is the ONLY place a companion becomes a file. The web
//! quickstart renders these into the page and the CLI writes them to disk from
//! this same function, so the two surfaces cannot drift. A companion body
//! carries the api-key SENTINEL exactly like a template body — the consumer's
//! single splice pass turns it into the plaintext.
//!
//! Companions are DATA, declared per template in `seeds/client_profiles/*.json`
//! and editable per tenant, so a cloned or admin-authored profile carries its
//! own. There is no kind gate here because there is nothing left to decide: a
//! companion hangs off ONE template, so an MCP-only render can only see
//! companions its own template declared, and the LLM placeholders are not in
//! that render's map at all. That an MCP-only template declares no credential
//! companion is a checked property of the data (`fixture::validate_profile`),
//! not a branch in this function.

use std::collections::BTreeMap;

use crate::render::{render, render_unless_empty, Value, PROJECT_SCOPE};
use crate::types::{ClientProfileTemplate, TemplateFormat};
use crate::RenderError;

/// A rendered companion: same splice contract as the template body, its own
/// path and format. The output form of a
/// [`crate::types::CompanionTemplate`] — a `body` in hand has been through the
/// engine exactly when it is this type.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CompanionFile {
    /// Destination path, `~/`-anchored. The CLI writes here; the quickstart
    /// shows it as the snippet's filename. `None` with no `project_path`: a
    /// snippet to run, shown and never written.
    pub path: Option<String>,
    /// The declared project-scope path; read through
    /// [`crate::types::companion_project_path`].
    #[serde(default)]
    pub project_path: Option<String>,
    pub format: TemplateFormat,
    /// User-facing title for the snippet header.
    pub title: String,
    /// Why this file exists, rendered above the snippet.
    pub instructions: String,
    /// Contents with the api-key sentinel intact.
    pub body: String,
}

/// Render a template's declared companions against this render's placeholder
/// map. Left out of the render:
/// * a companion with no `path` but a `project_path` outside a project scope
///   (`project_scope` unset) — it is a project's file only;
/// * one whose body renders to whitespace only, unless it is a shell or text
///   FILE, which the CLI may still add lines of its own to (the private-CA
///   lines of a `.env`) — that render has nothing to put in it (Claude Code's
///   MCP servers with none selected).
///
/// Errors rather than dropping a companion that renders to invalid output: a
/// silently-omitted credential file is exactly the failure this module exists
/// to prevent. Save-time validation refuses a profile whose companions render
/// invalid output against the validation placeholders; this is the backstop
/// at render time, against the live ones.
pub fn companion_files(
    template: &ClientProfileTemplate,
    placeholders: &BTreeMap<String, Value>,
) -> Result<Vec<CompanionFile>, RenderError> {
    let mut out = Vec::with_capacity(template.companions.len());
    let project_scope = matches!(placeholders.get(PROJECT_SCOPE), Some(Value::Bool(true)));
    for c in &template.companions {
        if c.path.is_none() && c.project_path.is_some() && !project_scope {
            continue;
        }
        let is_file = c.path.is_some() || c.project_path.is_some();
        let keep_empty = is_file && matches!(c.format, TemplateFormat::Shell | TemplateFormat::Text);
        let body = if keep_empty {
            render(&c.body, c.format, placeholders)?
        } else {
            match render_unless_empty(&c.body, c.format, placeholders)? {
                Some(body) => body,
                None => continue,
            }
        };
        out.push(CompanionFile {
            path: c.path.clone(),
            project_path: c.project_path.clone(),
            format: c.format,
            title: c.title.clone(),
            // Instructions are prose, rendered unescaped and unvalidated —
            // the same treatment a template's own instructions get.
            instructions: render(&c.instructions, TemplateFormat::Text, placeholders)?,
            body,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::API_KEY_PLACEHOLDER;
    use crate::types::{CompanionTemplate, KeyDelivery, McpAuthMode, TemplateKind};

    fn companion(path: &str, format: TemplateFormat, body: &str) -> CompanionTemplate {
        CompanionTemplate {
            path: Some(path.into()),
            project_path: None,
            format,
            title: "t".into(),
            instructions: String::new(),
            body: body.into(),
        }
    }

    fn template(companions: Vec<CompanionTemplate>) -> ClientProfileTemplate {
        ClientProfileTemplate {
            kind: TemplateKind::Combined,
            protocol: None,
            route_tag: None,
            filename: None,
            project_filename: None,
            format: TemplateFormat::Yaml,
            title: "t".into(),
            instructions: None,
            mcp_auth_mode: McpAuthMode::default(),
            key_delivery: KeyDelivery::default(),
            companions,
            keyed_arrays: Default::default(),
            body: String::new(),
        }
    }

    fn placeholders() -> BTreeMap<String, Value> {
        BTreeMap::from([(
            "api_key".to_string(),
            Value::String(API_KEY_PLACEHOLDER.to_string()),
        )])
    }

    #[test]
    fn a_template_declaring_none_renders_none() {
        assert!(companion_files(&template(Vec::new()), &placeholders())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn companions_render_in_declaration_order() {
        let t = template(vec![
            companion("~/a.env", TemplateFormat::Shell, "A={{api_key}}\n"),
            companion("~/b.env", TemplateFormat::Shell, "B={{api_key}}\n"),
        ]);
        let out = companion_files(&t, &placeholders()).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].path.as_deref(), Some("~/a.env"));
        assert_eq!(out[1].path.as_deref(), Some("~/b.env"));
        assert_eq!(out[0].body, format!("A={API_KEY_PLACEHOLDER}\n"));
    }

    #[test]
    fn a_companion_that_renders_invalid_output_errors_rather_than_vanishing() {
        // Unbalanced YAML mapping: the post-render parse must reject it, and
        // the error must reach the caller instead of the file disappearing.
        let t = template(vec![companion(
            "~/broken.yaml",
            TemplateFormat::Yaml,
            "a: b\n  c: d\n",
        )]);
        let err = companion_files(&t, &placeholders()).unwrap_err();
        assert!(matches!(err, RenderError::InvalidOutput { .. }), "got {err:?}");
    }

    /// A body that renders to whitespace only is no file for that render —
    /// and the same companion is kept, and its JSON still checked, as soon as
    /// it has something to say.
    #[test]
    fn a_companion_that_renders_empty_is_left_out() {
        let body = "{{#if servers}}{\"servers\": {{servers}}}\n{{/if}}";
        let t = template(vec![companion("~/.tool.json", TemplateFormat::Json, body)]);
        assert!(companion_files(&t, &placeholders()).unwrap().is_empty());

        let mut phs = placeholders();
        phs.insert("servers".into(), Value::Int(2));
        let out = companion_files(&t, &phs).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].body, "{\"servers\": 2}\n");

        let broken = template(vec![companion("~/.tool.json", TemplateFormat::Json, "{{#if servers}}{{/if}}{")]);
        assert!(companion_files(&broken, &phs).is_err(), "a non-empty body is still validated");

        // An empty `.env` is still a file: the CLI may add lines of its own.
        let env = template(vec![companion("~/.tool/.env", TemplateFormat::Shell, "{{#if servers}}A=1\n{{/if}}")]);
        assert_eq!(companion_files(&env, &placeholders()).unwrap().len(), 1);
        // An empty snippet is nothing to run.
        let mut step = companion("~/unused", TemplateFormat::Text, "{{#if servers}}tool add {{servers}}\n{{/if}}");
        step.path = None;
        assert!(companion_files(&template(vec![step.clone()]), &placeholders()).unwrap().is_empty());
        let out = companion_files(&template(vec![step]), &phs).unwrap();
        assert_eq!((out[0].path.as_deref(), out[0].body.as_str()), (None, "tool add 2\n"));
    }

    /// A companion with no path but a project path is a project's file only:
    /// left out of a render outside a project scope.
    #[test]
    fn a_project_only_companion_renders_only_in_a_project() {
        let mut c = companion("~/unused", TemplateFormat::Shell, "A=1\n");
        c.path = None;
        c.project_path = Some(".tool.env".into());
        let t = template(vec![c]);
        assert!(companion_files(&t, &placeholders()).unwrap().is_empty());
        let mut phs = placeholders();
        phs.insert(PROJECT_SCOPE.into(), Value::Bool(true));
        let out = companion_files(&t, &phs).unwrap();
        assert_eq!((out[0].path.as_deref(), out[0].project_path.as_deref()), (None, Some(".tool.env")));
    }

    #[test]
    fn a_companion_body_carries_the_sentinel_not_a_plaintext_key() {
        let t = template(vec![companion(
            "~/.config/tool/secrets.yaml",
            TemplateFormat::Yaml,
            "OPENAI_API_KEY: {{api_key}}\n",
        )]);
        let out = companion_files(&t, &placeholders()).unwrap();
        // yaml_escape quotes any value containing `<`/`>`, so the sentinel
        // lands as a quoted scalar — the consumer splices inside the quotes.
        assert_eq!(out[0].body, format!("OPENAI_API_KEY: \"{API_KEY_PLACEHOLDER}\"\n"));
    }
}
