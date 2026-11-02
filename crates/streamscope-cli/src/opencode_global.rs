//! What OpenCode's USER config does to a provisioned OpenCode client.
//!
//! OpenCode 2 lets two user-level settings outrank any project config: a
//! `provider.use` policy (policies are evaluated broadest config last, last
//! match wins, so a user-level `deny` cannot be lifted by a project `allow`;
//! a V1 `enabled_providers` / `disabled_providers` list loads as such a
//! policy), and a per-agent model (`agents.<id>.model`, V1 `agent.<id>.model`),
//! which beats the project's top-level `model`. Either one sends plain
//! `opencode` to another provider while the project file looks right.
//! In a project, `ssai run opencode` is unaffected: it points OpenCode's user
//! config dir at the project (`AgentProfile::config_dir_env`). Every
//! provisioned form pins the built-in agents itself.
//!
//! This module only reads and reports; it never writes the user's config.

use std::path::{Path, PathBuf};

use serde_json::Value;

/// The user config files OpenCode reads: in its user config dir
/// (`$OPENCODE_CONFIG_DIR`, else `$XDG_CONFIG_HOME/opencode`, else
/// `~/.config/opencode`), and in `~/.opencode`, which it always loads.
pub fn user_config_files() -> Vec<PathBuf> {
    let dirs = user_config_dir().into_iter().chain(always_loaded_dir());
    dirs.flat_map(|dir| ["opencode.json", "opencode.jsonc"].map(|n| dir.join(n)))
        .filter(|p| p.is_file())
        .collect()
}

/// `~/.opencode`, which OpenCode loads whatever `OPENCODE_CONFIG_DIR` says —
/// so a rule there also reaches `ssai run`.
fn always_loaded_dir() -> Option<PathBuf> {
    crate::state::expand_tilde("~/.opencode").ok()
}

/// The directory OpenCode reads its user config from: `$OPENCODE_CONFIG_DIR`,
/// else `$XDG_CONFIG_HOME/opencode`, else `~/.config/opencode`.
fn user_config_dir() -> Option<PathBuf> {
    std::env::var_os("OPENCODE_CONFIG_DIR")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("XDG_CONFIG_HOME")
                .filter(|v| !v.is_empty())
                .map(|x| PathBuf::from(x).join("opencode"))
        })
        .or_else(|| crate::state::expand_tilde("~/.config/opencode").ok())
}

/// The provider key a provisioned OpenCode config registers the gateway under:
/// the `<key>` of its first owned `/providers/<key>/…` path.
pub fn provider_key(owned_paths: &[&str]) -> Option<String> {
    owned_paths.iter().find_map(|p| {
        let rest = p.strip_prefix("/providers/")?;
        let key = rest.split('/').next()?;
        (!key.is_empty()).then(|| key.to_string())
    })
}

/// One thing the user's OpenCode config does to the provisioned one. `overrides`
/// is set when it takes the provisioned config's effect away (a provider rule
/// that denies the gateway, an agent pinned elsewhere) — what `status` reports
/// in place of `ok`; an unreadable file or a config dir OpenCode reads instead
/// is reported, not called an override.
pub struct Conflict {
    pub text: String,
    pub overrides: bool,
}

/// Warnings for `provider` from every user config file, each naming the file.
/// Empty when nothing outranks the provisioned config. `provisioned` is the
/// file the provisioning wrote: an agent it pins itself is not reported (a
/// project pin outranks a user-level one). When it IS the user config (a
/// global provisioning), its own statements are still checked — a deny the
/// user wrote there blocks the provider all the same.
pub fn conflicts(provider: &str, provisioned: Option<&Path>) -> Vec<Conflict> {
    let provisioned_config = provisioned.and_then(|p| read_jsonc(p).ok());
    let files = user_config_files();
    // A global provisioning wrote the home-directory config (the template's
    // `~/.config/opencode/` path) or one of the user config files: every user
    // config is then the user's own scope, not something outranking a project.
    let home_dir = crate::state::expand_tilde("~/.config/opencode").ok();
    let in_home_dir = provisioned.is_some_and(|p| home_dir.as_deref().is_some_and(|d| p.parent() == Some(d)));
    let global = in_home_dir || provisioned.is_some_and(|p| files.iter().any(|f| crate::state::same_file(p, f)));
    let mut out = Vec::new();
    // OpenCode reads its user config from where `$OPENCODE_CONFIG_DIR` /
    // `$XDG_CONFIG_HOME` point: a global provisioning written elsewhere is a
    // file it does not load.
    if in_home_dir
        && let Some(p) = provisioned
        && let Some(reads) = user_config_dir()
        && !p.parent().is_some_and(|d| crate::state::same_file(d, &reads))
    {
        out.push(Conflict {
            text: format!(
                "OpenCode reads its user config from {}, not {} — set OPENCODE_CONFIG_DIR / XDG_CONFIG_HOME \
                 accordingly, or copy the gateway entries there.",
                reads.display(),
                p.display()
            ),
            overrides: true,
        });
    }
    for file in files {
        let config = match read_jsonc(&file) {
            Ok(c) => c,
            Err(()) => {
                out.push(Conflict {
                    text: format!(
                        "OpenCode's user config {} is not valid JSON — OpenCode may refuse to start.",
                        file.display()
                    ),
                    overrides: false,
                });
                continue;
            }
        };
        let project_pins = match (&provisioned_config, global) {
            (_, true) => None,
            (Some(pc), false) => Some(pinned_agents(pc)),
            (None, false) => Some(Vec::new()),
        };
        out.extend(
            conflicts_in(
                &config,
                provider,
                &file.display().to_string(),
                project_pins.as_deref(),
                // `run` swaps out the user config dir, never `~/.opencode`.
            run_replaces_user_config(provisioned)
                && always_loaded_dir().is_none_or(|d| file.parent() != Some(d.as_path())),
            )
            .into_iter()
            .map(|text| Conflict { text, overrides: true }),
        );
    }
    out
}

/// Whether `ssai run` hands OpenCode the provisioned config in place of
/// the user's: only a project config in a directory of its own
/// (`.opencode/`) — the directory `run` sets as `OPENCODE_CONFIG_DIR`.
fn run_replaces_user_config(provisioned: Option<&Path>) -> bool {
    provisioned
        .and_then(Path::parent)
        .and_then(Path::file_name)
        .is_some_and(|n| n == ".opencode")
}

/// [`conflicts`] for a provisioned client record — empty for any client but
/// OpenCode, or one whose config registers no gateway provider.
pub fn for_managed(client: &crate::state::ManagedClient) -> Vec<Conflict> {
    if client.client_id != "opencode" {
        return Vec::new();
    }
    let Some(file) = client.files.first() else { return Vec::new() };
    let owned: Vec<&str> = file.owned.iter().map(|o| o.path.as_str()).collect();
    let Some(provider) = provider_key(&owned) else { return Vec::new() };
    let provisioned = crate::state::expand_tilde(&file.path).ok();
    conflicts(&provider, provisioned.as_deref())
}

fn read_jsonc(path: &Path) -> Result<Value, ()> {
    let text = std::fs::read_to_string(path).map_err(|_| ())?;
    crate::writer::json::parse_jsonc(&text).map_err(|_| ())
}

/// Every agent a config gives a model of its own.
fn pinned_agents(config: &Value) -> Vec<String> {
    ["agents", "agent"]
        .iter()
        .filter_map(|k| config.get(*k).and_then(Value::as_object))
        .flat_map(|m| m.iter().filter(|(_, a)| a.get("model").is_some()).map(|(id, _)| id.clone()))
        .collect()
}

/// The warnings one parsed user config produces for `provider`.
/// `project_pins` is `Some` for a project provisioning — the agents the
/// project config pins itself, not reported — and `None` for a global
/// provisioning, where `config` is the provisioned file or another user
/// config read beside it, and `ssai run` reads them too. `run_replaces` says whether `ssai run`
/// swaps the user config out for this project (see
/// [`run_replaces_user_config`]) — only then is `run` unaffected.
pub fn conflicts_in(
    config: &Value,
    provider: &str,
    file: &str,
    project_pins: Option<&[String]>,
    run_replaces: bool,
) -> Vec<String> {
    let outranks = match project_pins {
        Some(_) => "a user-level deny outranks this project",
        None => "a deny after the provisioned allow wins",
    };
    let run_note = if project_pins.is_some() && run_replaces {
        " (`ssai run opencode` is unaffected)"
    } else {
        ""
    };
    let mut out = Vec::new();
    if !provider_allowed(config, provider) {
        out.push(format!(
            "OpenCode's user config {file} denies provider `{provider}`, and {outranks} — plain \
             `opencode` will not use the gateway{run_note}. To allow it, add after the deny in that \
             file's experimental.policies: {{ \"action\": \"provider.use\", \"resource\": \
             \"{provider}\", \"effect\": \"allow\" }} — then run `opencode service restart`."
        ));
    }
    // Every provisioned form pins the built-in agents itself, so what is left
    // pinned elsewhere is an agent of the user's own.
    let pinned: Vec<String> = agents_pinned_elsewhere(config, provider)
        .into_iter()
        .filter(|a| project_pins.is_none_or(|pins| !pins.contains(a)))
        .collect();
    if !pinned.is_empty() {
        let over = if project_pins.is_some() { "this project's `model`" } else { "the provisioned `model`" };
        out.push(format!(
            "OpenCode's user config {file} pins agent(s) {} to another provider's model, which \
             outranks {over} — `opencode` runs them there{run_note}.",
            pinned.join(", ")
        ));
    }
    out
}

/// Whether `provider` survives the config's `provider.use` statements: V1
/// lists first (`enabled_providers` = deny `*` + allow each, then
/// `disabled_providers` = deny each), then `experimental.policies` in order;
/// the last matching statement wins, and no match allows.
pub fn provider_allowed(config: &Value, provider: &str) -> bool {
    let mut allowed = true;
    if let Some(list) = config.get("enabled_providers").and_then(Value::as_array) {
        allowed = list.iter().filter_map(Value::as_str).any(|p| p == provider);
    }
    if let Some(list) = config.get("disabled_providers").and_then(Value::as_array)
        && list.iter().filter_map(Value::as_str).any(|p| p == provider)
    {
        allowed = false;
    }
    let policies = config
        .get("experimental")
        .and_then(|e| e.get("policies"))
        .and_then(Value::as_array);
    for statement in policies.into_iter().flatten() {
        let action = statement.get("action").and_then(Value::as_str).unwrap_or_default();
        let resource = statement.get("resource").and_then(Value::as_str).unwrap_or_default();
        if !glob_match(action, "provider.use") || !glob_match(resource, provider) {
            continue;
        }
        match statement.get("effect").and_then(Value::as_str) {
            Some("allow") => allowed = true,
            Some("deny") => allowed = false,
            _ => {}
        }
    }
    allowed
}

/// Agents whose user-level model names a provider other than `provider`,
/// sorted. Reads V2 `agents.<id>.model` (`{providerID, …}` or
/// `"provider/model"`) and V1 `agent.<id>.model` (`"provider/model"`).
pub fn agents_pinned_elsewhere(config: &Value, provider: &str) -> Vec<String> {
    let mut out = Vec::new();
    for key in ["agents", "agent"] {
        let Some(agents) = config.get(key).and_then(Value::as_object) else { continue };
        for (id, agent) in agents {
            let model_provider = match agent.get("model") {
                Some(Value::Object(m)) => m.get("providerID").and_then(Value::as_str).map(str::to_string),
                Some(Value::String(s)) => s.split_once('/').map(|(p, _)| p.to_string()),
                _ => None,
            };
            if model_provider.is_some_and(|p| p != provider) && !out.contains(id) {
                out.push(id.clone());
            }
        }
    }
    out.sort();
    out
}

/// `*` matches any run of characters; everything else is literal.
fn glob_match(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == text;
    }
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if !text.starts_with(first) || text.len() < first.len() + last.len() || !text.ends_with(last) {
        return false;
    }
    let mut rest = &text[first.len()..text.len() - last.len()];
    for mid in &parts[1..parts.len() - 1] {
        match rest.find(mid) {
            Some(i) => rest = &rest[i + mid.len()..],
            None => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const P: &str = "streamscope_default_vllm-a100";

    fn pol(effect: &str, resource: &str) -> Value {
        json!({ "action": "provider.use", "resource": resource, "effect": effect })
    }

    #[test]
    fn no_statement_allows() {
        assert!(provider_allowed(&json!({}), P));
        assert!(provider_allowed(&json!({ "experimental": { "policies": [] } }), P));
    }

    #[test]
    fn deny_all_then_allow_another_denies_ours() {
        let c = json!({ "experimental": { "policies": [pol("deny", "*"), pol("allow", "ai-code-labo-int")] } });
        assert!(!provider_allowed(&c, P));
        assert!(provider_allowed(&c, "ai-code-labo-int"));
    }

    #[test]
    fn a_later_allow_of_ours_lifts_the_deny_and_a_later_deny_takes_it_back() {
        let lifted = json!({ "experimental": { "policies": [pol("deny", "*"), pol("allow", P)] } });
        assert!(provider_allowed(&lifted, P));
        let retaken =
            json!({ "experimental": { "policies": [pol("deny", "*"), pol("allow", P), pol("deny", "streamscope_*")] } });
        assert!(!provider_allowed(&retaken, P));
    }

    #[test]
    fn other_actions_do_not_decide_provider_use() {
        let c = json!({ "experimental": { "policies": [
            { "action": "websearch", "resource": "*", "effect": "deny" }
        ] } });
        assert!(provider_allowed(&c, P));
        let any_action = json!({ "experimental": { "policies": [{ "action": "*", "resource": "*", "effect": "deny" }] } });
        assert!(!provider_allowed(&any_action, P));
    }

    #[test]
    fn v1_lists_load_as_policies() {
        assert!(!provider_allowed(&json!({ "enabled_providers": ["ai-code-labo-int"] }), P));
        assert!(provider_allowed(&json!({ "enabled_providers": ["ai-code-labo-int", P] }), P));
        assert!(!provider_allowed(&json!({ "disabled_providers": [P] }), P));
        // A V2 allow after the V1 list lifts it.
        let mixed = json!({ "enabled_providers": ["x"], "experimental": { "policies": [pol("allow", P)] } });
        assert!(provider_allowed(&mixed, P));
    }

    #[test]
    fn agents_pinned_to_another_provider_are_listed_ours_are_not() {
        let c = json!({
            "agents": {
                "build": { "model": { "providerID": "ai-code-labo-int", "model": "Q" } },
                "plan": { "model": { "providerID": P, "model": "Q" } },
                "title": { "model": "ai-code-labo-int/Q" },
                "explore": {}
            },
            "agent": { "summary": { "model": "other/x" }, "build": { "model": "other/x" } }
        });
        assert_eq!(agents_pinned_elsewhere(&c, P), vec!["build", "summary", "title"]);
        assert!(agents_pinned_elsewhere(&json!({}), P).is_empty());
    }

    #[test]
    fn conflicts_in_reports_both_kinds_and_nothing_for_a_clean_config() {
        let c = json!({
            "experimental": { "policies": [pol("deny", "*"), pol("allow", "ai-code-labo-int")] },
            "agents": { "build": { "model": { "providerID": "ai-code-labo-int", "model": "Q" } } }
        });
        let w = conflicts_in(&c, P, "g.json", Some(&[]), true);
        assert_eq!(w.len(), 2, "{w:?}");
        assert!(w[0].contains("denies provider") && w[0].contains(P));
        assert!(w[1].contains("build"));
        assert!(conflicts_in(&json!({ "share": "disabled" }), P, "g.json", Some(&[]), true).is_empty());
        // An agent the project pins itself is not reported; the deny still is.
        let w = conflicts_in(&c, P, "g.json", Some(&["build".to_string()]), true);
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("denies provider"));
        // The provisioned file itself (a global provisioning): `run` reads that
        // same file, so no warning may claim it is unaffected. An agent still
        // pinned elsewhere there is one the provisioning does not pin.
        let w = conflicts_in(&c, P, "g.json", None, false);
        assert_eq!(w.len(), 2, "{w:?}");
        assert!(w[0].contains("denies provider"), "{w:?}");
        assert!(w[1].contains("build") && w[1].contains("the provisioned `model`"), "{w:?}");
        assert!(w.iter().all(|m| !m.contains("is unaffected") && !m.contains("this project")), "{w:?}");
        let pinned_here = json!({ "agents": { "build": { "model": { "providerID": P, "model": "Q" } } } });
        assert!(conflicts_in(&pinned_here, P, "g.json", None, false).is_empty());
        let project = conflicts_in(&c, P, "g.json", Some(&[]), true);
        assert!(project.iter().all(|m| m.contains("is unaffected")), "{project:?}");
        // A project config `run` does not swap in (a root-level one): no promise.
        let root_level = conflicts_in(&c, P, "g.json", Some(&[]), false);
        assert!(root_level.iter().all(|m| !m.contains("is unaffected")), "{root_level:?}");
    }

    /// A global provisioning merged over a home config that pins the built-in
    /// agents elsewhere repoints those pins and keeps everything else the user
    /// set on them; only an agent of the user's own is still reported.
    #[test]
    fn a_global_provisioning_repoints_the_built_in_agents_and_reports_the_users_own() {
        let user = json!({
            "agents": {
                "build": { "model": { "providerID": "other", "model": "x" }, "prompt": "mine" },
                "title": { "model": "other/x" },
                "reviewer": { "model": { "providerID": "other", "model": "x" } }
            },
            "agent": { "plan": { "model": "other/x" } }
        });
        let pin = json!({ "model": { "providerID": P, "model": "Q" } });
        let ours = json!({ "model": format!("{P}/Q"), "agents": { "build": pin, "title": pin } });
        let out = crate::writer::merge(
            streamscope_client_templates::TemplateFormat::Json,
            Some(&user.to_string()),
            &ours.to_string(),
            &[],
            &Default::default(),
        )
        .unwrap();
        let merged: Value = serde_json::from_str(&out.contents).unwrap();
        assert_eq!(merged["agents"]["build"]["model"], pin["model"]);
        assert_eq!(merged["agents"]["build"]["prompt"], "mine");
        assert_eq!(merged["agents"]["title"]["model"], pin["model"]);
        // A pin under the V1 `agent` key is not rewritten, so it is reported.
        assert_eq!(agents_pinned_elsewhere(&merged, P), vec!["plan", "reviewer"]);
        let w = conflicts_in(&merged, P, "g.json", None, false);
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("plan, reviewer") && !w[0].contains("build"), "{w:?}");
    }

    #[test]
    fn provider_key_is_read_from_owned_paths() {
        assert_eq!(
            provider_key(&["/model", "/providers/ss_t_p/settings/apiKey", "/providers/other/name"]).as_deref(),
            Some("ss_t_p")
        );
        assert_eq!(provider_key(&["/model", "/mcp/servers/web/url"]), None);
    }

    #[test]
    fn glob_matches_literal_prefix_suffix_and_infix() {
        assert!(glob_match("*", ""));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("abc", "abc"));
        assert!(!glob_match("abc", "abcd"));
        assert!(glob_match("ab*", "abcd"));
        assert!(!glob_match("ab*", "a"));
        assert!(glob_match("*cd", "abcd"));
        assert!(glob_match("a*c*e", "abcde"));
        assert!(!glob_match("a*c*e", "abde"));
        assert!(!glob_match("ab*ba", "aba"), "the prefix and suffix may not overlap");
    }
}
