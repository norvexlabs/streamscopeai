//! What OpenCode's other configs do to a provisioned OpenCode client.
//!
//! OpenCode 2 reads a chain of config documents ([`load_order`]). The earliest
//! loaded with a `provider.use` statement matching a provider decides it, so a
//! user-level `deny` cannot be lifted by a project `allow`, and a repository's
//! root `opencode.json` outranks its `.opencode/` (a V1 `enabled_providers` /
//! `disabled_providers` list loads as such a policy). A per-agent model
//! (`agents.<id>.model`, V1 `agent.<id>.model`) beats a top-level `model`, and
//! settings go the other way from policies: the latest-loaded document wins.
//! Either one sends plain `opencode` to another provider while the provisioned
//! file looks right. In a project, `ssai run opencode` points OpenCode's user
//! config dir at the project (`AgentProfile::config_dir_env`), which changes the
//! chain, so each launch is decided on its own. Every provisioned form pins the
//! built-in agents itself, and denies OpenCode's own hosted provider.
//!
//! This module only reads and reports; it never writes a config.

use std::path::{Path, PathBuf};

use serde_json::Value;

/// OpenCode's own hosted provider. With no credential it serves its zero-cost
/// models under a public key, so they are offered beside the gateway's and a
/// request to one never reaches the gateway. Every provisioned form denies it.
const HOSTED_PROVIDER: &str = "opencode";

/// The file names OpenCode reads in a config directory, in the order it loads them.
const CONFIG_NAMES: [&str; 2] = ["opencode.json", "opencode.jsonc"];

/// A config file OpenCode loads, with its contents.
type Document = (PathBuf, Value);

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

/// One thing another OpenCode config does to the provisioned one. `overrides`
/// is set when it takes the provisioned config's effect away (a provider rule
/// that denies the gateway or allows the hosted provider, an agent pinned
/// elsewhere) — what `status` reports in place of `ok`; an unreadable file is
/// reported, not called an override.
pub struct Conflict {
    pub text: String,
    pub overrides: bool,
}

/// Warnings for `provider` from every config document OpenCode loads, each
/// naming its file. Empty when nothing outranks the provisioned config.
/// `provisioned` is the file the provisioning wrote: an agent it pins itself is
/// not reported from a document loaded before it, which it outranks. When it IS the user
/// config (a global provisioning), its own statements are still checked — a deny
/// the user wrote there blocks the provider all the same.
pub fn conflicts(provider: &str, provisioned: Option<&Path>) -> Vec<Conflict> {
    let provisioned_config = provisioned.and_then(|p| read_jsonc(p).ok());
    let user_dir = user_config_dir();
    // A global provisioning wrote the home-directory config (the template's
    // `~/.config/opencode/` path) or a file in the user config dir: every other
    // config is then the user's own scope, not something outranking a project.
    let home_dir = crate::state::expand_tilde("~/.config/opencode").ok();
    let in_home_dir = provisioned.is_some_and(|p| home_dir.as_deref().is_some_and(|d| p.parent() == Some(d)));
    // A project's `.opencode` is the user config dir inside an `ssai run`, and stays a project.
    let in_user_dir = provisioned.filter(|p| !run_replaces_user_config(p)).and_then(Path::parent).is_some_and(|d| {
        user_dir.as_deref().is_some_and(|u| crate::state::same_file(d, u))
    });
    let global = in_home_dir || in_user_dir;
    // A global provisioning's launch directory is unknown: read it as one under home.
    let start = if global {
        crate::state::expand_tilde("~").ok()
    } else {
        provisioned.and_then(project_root).map(Path::to_path_buf)
    };
    let plain_order = user_dir.as_deref().map(|d| load_order(d, start.as_deref())).unwrap_or_default();
    let run_order = provisioned
        .filter(|p| run_replaces_user_config(p))
        .and_then(Path::parent)
        .map(|d| load_order(d, start.as_deref()));
    let plain = read_documents(&plain_order);
    let run = run_order.as_deref().map(read_documents);

    let mut out = Vec::new();
    // OpenCode reads its user config from where `$OPENCODE_CONFIG_DIR` /
    // `$XDG_CONFIG_HOME` point: a global provisioning written elsewhere is a
    // file it does not load.
    if in_home_dir
        && let Some(p) = provisioned
        && let Some(reads) = user_dir.as_deref()
        && !p.parent().is_some_and(|d| crate::state::same_file(d, reads))
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
    let mut seen: Vec<&Path> = Vec::new();
    for file in plain_order.iter().chain(run_order.iter().flatten()) {
        if seen.contains(&file.as_path()) || !file.is_file() {
            continue;
        }
        seen.push(file);
        let Ok(config) = read_jsonc(file) else {
            out.push(Conflict {
                text: format!("OpenCode's config {} is not valid JSON — OpenCode may refuse to start.", file.display()),
                overrides: false,
            });
            continue;
        };
        if !global && provisioned.is_some_and(|p| crate::state::same_file(p, file)) {
            continue;
        }
        // A pin matters to the launches that load its file, each with its own rules.
        let pinned = |documents: &[Document]| pinned_under(&config, provider, documents, file);
        let name = file.display().to_string();
        out.extend(
            pins_warnings(&name, !global, pinned(&plain), run.as_deref().map(pinned))
                .into_iter()
                .map(|text| Conflict { text, overrides: true }),
        );
    }
    let hosted = provisioned_config.as_ref().is_some_and(states_hosted_deny).then(|| hosted_allowed(&plain, run.as_deref()));
    out.extend(
        gateway_denied(&plain, run.as_deref(), provider)
            .into_iter()
            .chain(hosted.into_iter().flatten())
            .map(|text| Conflict { text, overrides: true }),
    );
    out
}

/// Whether `ssai run` hands OpenCode the provisioned config in place of
/// the user's: only a project config in a directory of its own
/// (`.opencode/`) — the directory `run` sets as `OPENCODE_CONFIG_DIR`.
fn run_replaces_user_config(provisioned: &Path) -> bool {
    provisioned.parent().and_then(Path::file_name).is_some_and(|n| n == ".opencode")
}

/// The directory a project's provisioned config belongs to: the one holding its
/// `.opencode/`, or the one holding the file itself.
fn project_root(provisioned: &Path) -> Option<&Path> {
    let dir = provisioned.parent()?;
    if dir.file_name().is_some_and(|n| n == ".opencode") { dir.parent() } else { Some(dir) }
}

/// The config files OpenCode loads, in its load order, with `user_dir` as its
/// user config dir and `start` as its working directory: the user config dir,
/// then each directory's own files from the filesystem root down to `start`,
/// then each directory's `.opencode/` in the same order. The user config dir is
/// not read a second time through the walk, and `~/.opencode` is loaded only
/// from a directory under home. A machine-wide managed policy and a config
/// passed in the environment are not read here, nor a config below `start`,
/// which only a launch from that directory loads. A top-level `model` in a later
/// document, and an agent defined in a Markdown file, are not judged either.
fn load_order(user_dir: &Path, start: Option<&Path>) -> Vec<PathBuf> {
    let in_dir = |dir: &Path| CONFIG_NAMES.map(|name| dir.join(name));
    let mut walked: Vec<&Path> = start.map(|s| s.ancestors().collect()).unwrap_or_default();
    walked.reverse();
    let is_user_dir = |dir: &Path| crate::state::same_file(dir, user_dir);
    let own = walked.iter().filter(|d| !is_user_dir(d)).flat_map(|d| in_dir(d));
    let dot_dirs = walked.iter().map(|d| d.join(".opencode")).filter(|d| !is_user_dir(d));
    in_dir(user_dir).into_iter().chain(own).chain(dot_dirs.flat_map(|d| in_dir(&d))).collect()
}

/// The files of `order` that exist and parse, with their contents. A file that
/// does not parse is skipped here; [`conflicts`] reports it on its own.
fn read_documents(order: &[PathBuf]) -> Vec<Document> {
    order.iter().filter_map(|path| Some((path.clone(), read_jsonc(path).ok()?))).collect()
}

/// What OpenCode decides for `provider` over `documents` in load order, and the
/// file that decided: the earliest-loaded document with a matching statement,
/// where that document's last match wins. `None` when nothing matches, which
/// allows.
fn decide<'a>(documents: &'a [Document], provider: &str) -> Option<(bool, &'a Path)> {
    documents.iter().find_map(|(path, config)| Some((last_decision(config, provider)?, path.as_path())))
}

/// Whether `documents` leave `provider` usable.
fn decided_allowed(documents: &[Document], provider: &str) -> bool {
    decide(documents, provider).is_none_or(|(allowed, _)| allowed)
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

/// The agents `config`, the document at `file`, takes off `provider` under the
/// launch loading `documents`: nothing if that launch does not load it. An agent
/// a later-loaded document also pins is left out, since the latest-loaded pin
/// wins, and a pin to a provider that launch denies runs on the default model.
fn pinned_under(config: &Value, provider: &str, documents: &[Document], file: &Path) -> Vec<String> {
    let Some(at) = documents.iter().position(|(p, _)| crate::state::same_file(p, file)) else {
        return Vec::new();
    };
    let later: Vec<String> = documents[at + 1..].iter().flat_map(|(_, later)| pinned_agents(later)).collect();
    agents_pinned_elsewhere(config, provider, &|pinned| decided_allowed(documents, pinned))
        .into_iter()
        .filter(|agent| !later.contains(agent))
        .collect()
}

/// The warnings for a file's pins under each launch, `run` being `Some` when
/// `ssai run opencode` loads other documents than plain `opencode`.
fn pins_warnings(file: &str, project: bool, plain: Vec<String>, run: Option<Vec<String>>) -> Vec<String> {
    let over = if project { "this project's config" } else { "the provisioned config" };
    let warning = |agents: &[String], launches: &str, note: &str| {
        format!(
            "OpenCode's config {file} pins agent(s) {} to another provider's model, which outranks {over} — \
             under {launches} they run there{note}.",
            agents.join(", ")
        )
    };
    let Some(run) = run else {
        return if plain.is_empty() { Vec::new() } else { vec![warning(&plain, "`opencode`", "")] };
    };
    if plain == run {
        return if plain.is_empty() {
            Vec::new()
        } else {
            vec![warning(&plain, "plain `opencode` and `ssai run opencode`", "")]
        };
    }
    let mut out = Vec::new();
    if !plain.is_empty() {
        let note = if run.is_empty() { " (`ssai run opencode` is unaffected)" } else { "" };
        out.push(warning(&plain, "plain `opencode`", note));
    }
    if !run.is_empty() {
        out.push(warning(&run, "`ssai run opencode`", ""));
    }
    out
}

/// Whether a provisioned config carries the hosted-provider deny. An admin can
/// edit it out of the client profile, and then a user's allow takes nothing away.
fn states_hosted_deny(provisioned: &Value) -> bool {
    let policies = provisioned.get("experimental").and_then(|e| e.get("policies")).and_then(Value::as_array);
    policies.into_iter().flatten().any(|statement| {
        let field = |k: &str| statement.get(k).and_then(Value::as_str);
        field("action") == Some("provider.use")
            && field("resource") == Some(HOSTED_PROVIDER)
            && field("effect") == Some("deny")
    })
}

/// The warnings for a document that decides to allow the hosted provider, which
/// takes the provisioned deny away.
fn hosted_allowed(plain: &[Document], run: Option<&[Document]>) -> Vec<String> {
    launch_warnings(plain, run, HOSTED_PROVIDER, true, &|file, launches, note| {
        format!(
            "OpenCode's config {file} allows its own hosted provider `{HOSTED_PROVIDER}`, and no config outranking \
             that file denies it — its models are on offer under {launches}, and a request to one bypasses the \
             gateway{note}. To hide it, remove that statement or end that file's experimental.policies with: \
             {{ \"action\": \"provider.use\", \"resource\": \"{HOSTED_PROVIDER}\", \"effect\": \"deny\" }}."
        )
    })
}

/// The warnings for a document that decides to deny the gateway's provider.
fn gateway_denied(plain: &[Document], run: Option<&[Document]>, provider: &str) -> Vec<String> {
    launch_warnings(plain, run, provider, false, &|file, launches, note| {
        format!(
            "OpenCode's config {file} denies provider `{provider}`, and no config outranking that file allows it — \
             {launches} will not use the gateway{note}. To allow it, add after the deny in that file's \
             experimental.policies: {{ \"action\": \"provider.use\", \"resource\": \"{provider}\", \
             \"effect\": \"allow\" }} — then run `opencode service restart`."
        )
    })
}

/// One warning per file whose decision for `provider` is `effect`. `plain` is
/// what plain `opencode` loads and `run` what `ssai run opencode` loads when it
/// replaces the user config; each launch is decided on its own, since a file can
/// decide under one and not the other. `warning` gets the file, the launches it
/// reaches, and a note for a launch it leaves alone.
fn launch_warnings(
    plain: &[Document],
    run: Option<&[Document]>,
    provider: &str,
    effect: bool,
    warning: &dyn Fn(String, &str, &str) -> String,
) -> Vec<String> {
    let decided_by = |documents| decide(documents, provider).and_then(|(d, file)| (d == effect).then_some(file));
    let by_plain = decided_by(plain);
    let by_run = run.and_then(decided_by);
    let shown = |file: &Path| file.display().to_string();
    let mut out = Vec::new();
    if let Some(file) = by_plain {
        out.push(match (run, by_run) {
            (None, _) => warning(shown(file), "`opencode`", ""),
            (Some(_), None) => warning(shown(file), "plain `opencode`", " (`ssai run opencode` is unaffected)"),
            (Some(_), Some(other)) if other == file => {
                warning(shown(file), "plain `opencode` and `ssai run opencode`", "")
            }
            (Some(_), Some(_)) => warning(shown(file), "plain `opencode`", ""),
        });
    }
    if let Some(file) = by_run.filter(|file| by_plain != Some(*file)) {
        out.push(warning(shown(file), "`ssai run opencode`", ""));
    }
    out
}

/// What the config's last statement matching `provider` decides, `None` when
/// none matches: V1 lists first (`enabled_providers` = deny `*` + allow each,
/// then `disabled_providers` = deny each), then `experimental.policies` in
/// order.
fn last_decision(config: &Value, provider: &str) -> Option<bool> {
    let mut decision = None;
    if let Some(list) = config.get("enabled_providers").and_then(Value::as_array) {
        decision = Some(list.iter().filter_map(Value::as_str).any(|p| p == provider));
    }
    if let Some(list) = config.get("disabled_providers").and_then(Value::as_array)
        && list.iter().filter_map(Value::as_str).any(|p| p == provider)
    {
        decision = Some(false);
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
            Some("allow") => decision = Some(true),
            Some("deny") => decision = Some(false),
            _ => {}
        }
    }
    decision
}

/// Agents whose model in this config names a usable provider other than `provider`,
/// sorted. A pin to a provider `allowed` refuses is left out: OpenCode runs that
/// agent on the default model instead. Reads V2 `agents.<id>.model`
/// (`{providerID, …}` or `"provider/model"`) and V1 `agent.<id>.model`
/// (`"provider/model"`).
fn agents_pinned_elsewhere(config: &Value, provider: &str, allowed: &dyn Fn(&str) -> bool) -> Vec<String> {
    let mut out = Vec::new();
    for key in ["agents", "agent"] {
        let Some(agents) = config.get(key).and_then(Value::as_object) else { continue };
        for (id, agent) in agents {
            let model_provider = match agent.get("model") {
                Some(Value::Object(m)) => m.get("providerID").and_then(Value::as_str).map(str::to_string),
                Some(Value::String(s)) => s.split_once('/').map(|(p, _)| p.to_string()),
                _ => None,
            };
            if model_provider.is_some_and(|p| p != provider && allowed(&p)) && !out.contains(id) {
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

    fn any(_: &str) -> bool {
        true
    }

    fn provider_allowed(config: &Value, provider: &str) -> bool {
        last_decision(config, provider).unwrap_or(true)
    }

    fn docs(files: &[(&str, Value)]) -> Vec<Document> {
        files.iter().map(|(path, config)| (PathBuf::from(path), config.clone())).collect()
    }

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
        assert_eq!(agents_pinned_elsewhere(&c, P, &any), vec!["build", "summary", "title"]);
        assert!(agents_pinned_elsewhere(&json!({}), P, &any).is_empty());
    }

    fn pin(agent: &str, provider: &str) -> Value {
        json!({ "agents": { agent: { "model": { "providerID": provider, "model": "x" } } } })
    }

    fn agents(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| n.to_string()).collect()
    }

    /// Policies go to the earliest-loaded document, pins to the latest: the
    /// project's pin wins under plain `opencode`, which loads it last, and loses
    /// to a root file's under `ssai run`, which loads it first.
    #[test]
    fn a_pin_is_left_out_only_where_a_later_document_pins_that_agent() {
        let root_pin = pin("build", "other");
        let ours = pin("build", P);
        let root = Path::new("root.json");
        let plain = docs(&[("root.json", root_pin.clone()), ("dot.json", ours.clone())]);
        let run = docs(&[("dot.json", ours.clone()), ("root.json", root_pin.clone())]);
        assert!(pinned_under(&root_pin, P, &plain, root).is_empty());
        assert_eq!(pinned_under(&root_pin, P, &run, root), agents(&["build"]));
        // An agent nothing later pins is the file's under both.
        let own = pin("reviewer", "other");
        let beside = docs(&[("root.json", own.clone()), ("dot.json", ours)]);
        assert_eq!(pinned_under(&own, P, &beside, root), agents(&["reviewer"]));
        // A launch that does not load the file never sees the pin.
        assert!(pinned_under(&root_pin, P, &docs(&[("dot.json", json!({}))]), root).is_empty());
    }

    #[test]
    fn a_pin_counts_under_each_launch_by_its_own_rules() {
        let deny = json!({ "experimental": { "policies": [pol("deny", "other")] } });
        let own = pin("reviewer", "other");
        let file = Path::new("root.json");
        let plain = docs(&[("home.json", deny), ("root.json", own.clone())]);
        let run = docs(&[("root.json", own.clone())]);
        assert!(pinned_under(&own, P, &plain, file).is_empty());
        assert_eq!(pinned_under(&own, P, &run, file), agents(&["reviewer"]));
    }

    #[test]
    fn the_pin_warning_names_the_launches_it_reaches() {
        let build = agents(&["build"]);
        let w = pins_warnings("g.json", true, build.clone(), Some(Vec::new()));
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("build") && w[0].contains("this project's config"), "{w:?}");
        assert!(w[0].contains("under plain `opencode` they") && w[0].contains("is unaffected"), "{w:?}");
        let w = pins_warnings("g.json", true, Vec::new(), Some(build.clone()));
        assert!(w[0].contains("under `ssai run opencode` they") && !w[0].contains("is unaffected"), "{w:?}");
        let w = pins_warnings("g.json", true, build.clone(), Some(build.clone()));
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("under plain `opencode` and `ssai run opencode` they"), "{w:?}");
        let w = pins_warnings("g.json", true, build.clone(), Some(agents(&["plan"])));
        assert_eq!(w.len(), 2, "{w:?}");
        assert!(w[0].contains("build") && !w[0].contains("is unaffected") && w[1].contains("plan"), "{w:?}");
        // A global provisioning: one launch.
        let w = pins_warnings("g.json", false, build, None);
        assert!(w[0].contains("under `opencode` they") && w[0].contains("the provisioned config"), "{w:?}");
        assert!(pins_warnings("g.json", true, Vec::new(), Some(Vec::new())).is_empty());
        assert!(pins_warnings("g.json", false, Vec::new(), None).is_empty());
    }

    /// The document that decides is named, whichever launch it reaches, and a
    /// document it outranks is not.
    #[test]
    fn a_deny_of_the_gateway_is_reported_from_the_document_that_decides() {
        let deny_all = json!({ "experimental": { "policies": [pol("deny", "*"), pol("allow", "other")] } });
        let allow = json!({ "experimental": { "policies": [pol("allow", P)] } });
        let silent = json!({ "share": "disabled" });
        let plain = docs(&[("home.json", deny_all.clone()), ("dot.json", silent.clone())]);
        let run = docs(&[("dot.json", silent.clone())]);
        let w = gateway_denied(&plain, Some(&run), P);
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("home.json") && w[0].contains(P) && w[0].contains("plain `opencode` will not use"), "{w:?}");
        assert!(w[0].contains("`ssai run opencode` is unaffected"), "{w:?}");
        // A repository's root file, which `run` loads too.
        let both = docs(&[("root.json", deny_all.clone())]);
        let w = gateway_denied(&both, Some(&both), P);
        assert!(w[0].contains("plain `opencode` and `ssai run opencode` will not use"), "{w:?}");
        assert!(!w[0].contains("is unaffected"), "{w:?}");
        // A global provisioning: one launch, and an earlier allow outranks a deny after it.
        assert!(gateway_denied(&docs(&[("g.json", deny_all.clone())]), None, P)[0].contains("— `opencode` will not use"));
        assert!(gateway_denied(&docs(&[("a.json", allow), ("b.json", deny_all)]), None, P).is_empty());
        assert!(gateway_denied(&docs(&[("a.json", silent)]), None, P).is_empty());
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
        assert_eq!(agents_pinned_elsewhere(&merged, P, &any), vec!["plan", "reviewer"]);
        let w = pins_warnings("g.json", false, agents_pinned_elsewhere(&merged, P, &any), None);
        assert!(w[0].contains("plan, reviewer") && !w[0].contains("build"), "{w:?}");
    }

    /// Only a statement that matches and allows is reported: a config saying
    /// nothing about the provider leaves the provisioned deny standing.
    #[test]
    fn a_config_allowing_the_hosted_provider_is_reported() {
        let deny = ("p/.opencode/opencode.json", json!({ "experimental": { "policies": [pol("deny", "opencode")] } }));
        for allowing in [
            json!({ "experimental": { "policies": [pol("allow", "opencode")] } }),
            json!({ "experimental": { "policies": [pol("allow", "*")] } }),
            json!({ "experimental": { "policies": [pol("deny", "opencode"), pol("allow", "open*")] } }),
            json!({ "enabled_providers": ["opencode", P] }),
        ] {
            let plain = docs(&[("g.json", allowing.clone()), deny.clone()]);
            let alone = hosted_allowed(&plain, None);
            assert_eq!(alone.len(), 1, "{alone:?}");
            assert!(alone[0].contains("g.json") && alone[0].contains("on offer under `opencode`,"), "{alone:?}");
            let run = docs(&[deny.clone(), ("g.json", allowing)]);
            let w = hosted_allowed(&plain, Some(&run));
            assert_eq!(w.len(), 1, "{w:?}");
            assert!(w[0].contains("g.json") && w[0].contains("on offer under plain `opencode`,"), "{w:?}");
            assert!(w[0].contains("`ssai run opencode` is unaffected"), "{w:?}");
        }
        for silent in [
            json!({}),
            json!({ "experimental": { "policies": [pol("allow", P)] } }),
            json!({ "experimental": { "policies": [pol("allow", P), pol("deny", "opencode")] } }),
            json!({ "experimental": { "policies": [pol("allow", "opencode"), pol("deny", "opencode")] } }),
            json!({ "experimental": { "policies": [pol("deny", "*"), pol("allow", P)] } }),
            json!({ "enabled_providers": [P] }),
            json!({ "enabled_providers": ["opencode"], "disabled_providers": ["opencode"] }),
        ] {
            assert_eq!(hosted_allowed(&docs(&[("g.json", silent.clone()), deny.clone()]), None), Vec::<String>::new(), "{silent}");
        }
    }

    /// Each launch is decided on its own, and the warning says which it reaches.
    #[test]
    fn the_hosted_warning_names_the_launches_each_file_reaches() {
        let allow = json!({ "experimental": { "policies": [pol("allow", "opencode")] } });
        let deny = json!({ "experimental": { "policies": [pol("deny", "opencode")] } });
        // A statement after the deny in the provisioned file itself, with nothing above it.
        let plain = docs(&[("dot.json", allow.clone())]);
        let w = hosted_allowed(&plain, Some(&plain));
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("under plain `opencode` and `ssai run opencode`,"), "{w:?}");
        // A home deny hides it from plain `opencode`; `run` leaves that home out.
        let w = hosted_allowed(&docs(&[("home.json", deny), ("dot.json", allow.clone())]), Some(&plain));
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("dot.json") && w[0].contains("on offer under `ssai run opencode`,"), "{w:?}");
        // Two different files, one per launch: both are named.
        let w = hosted_allowed(&docs(&[("home.json", allow.clone()), ("dot.json", allow)]), Some(&plain));
        assert_eq!(w.len(), 2, "{w:?}");
        assert!(w[0].contains("home.json") && w[0].contains("on offer under plain `opencode`,"), "{w:?}");
        assert!(!w[0].contains("is unaffected"), "{w:?}");
        assert!(w[1].contains("dot.json") && w[1].contains("on offer under `ssai run opencode`,"), "{w:?}");
    }

    /// The order the real binary was measured to apply: the user config dir
    /// outranks a repository's root file, which outranks its `.opencode/`, an
    /// ancestor outranks the directory below it, and `.json` outranks `.jsonc`.
    #[test]
    fn the_load_order_is_the_user_dir_then_each_directorys_files_then_its_dot_dir() {
        let order = load_order(Path::new("/h/.config/opencode"), Some(Path::new("/h/p")));
        let expected: Vec<PathBuf> = [
            "/h/.config/opencode/opencode.json",
            "/h/.config/opencode/opencode.jsonc",
            "/opencode.json",
            "/opencode.jsonc",
            "/h/opencode.json",
            "/h/opencode.jsonc",
            "/h/p/opencode.json",
            "/h/p/opencode.jsonc",
            "/.opencode/opencode.json",
            "/.opencode/opencode.jsonc",
            "/h/.opencode/opencode.json",
            "/h/.opencode/opencode.jsonc",
            "/h/p/.opencode/opencode.json",
            "/h/p/.opencode/opencode.jsonc",
        ]
        .map(PathBuf::from)
        .to_vec();
        assert_eq!(order, expected);
        // `ssai run` makes the project's `.opencode` the user config dir: it comes
        // first, and only once.
        let run = load_order(Path::new("/h/p/.opencode"), Some(Path::new("/h/p")));
        assert_eq!(run[0], Path::new("/h/p/.opencode/opencode.json"));
        assert_eq!(run.iter().filter(|p| p.starts_with("/h/p/.opencode")).count(), 2, "{run:?}");
        assert_eq!(load_order(Path::new("/u"), None).len(), 2);
        // A project outside the home directory never reaches `~/.opencode`.
        let outside = load_order(Path::new("/h/.config/opencode"), Some(Path::new("/srv/p")));
        assert!(!outside.iter().any(|p| p.starts_with("/h/.opencode")), "{outside:?}");
    }

    #[test]
    fn the_earliest_loaded_document_with_a_match_decides() {
        let allow = json!({ "experimental": { "policies": [pol("allow", "x")] } });
        let deny = json!({ "experimental": { "policies": [pol("deny", "x")] } });
        let silent = json!({ "experimental": { "policies": [pol("deny", "other")] } });
        let decided = |files: &[(&str, Value)]| {
            let documents = docs(files);
            decide(&documents, "x").map(|(allowed, file)| (allowed, file.display().to_string()))
        };
        assert_eq!(decided(&[("a", deny.clone()), ("b", allow.clone())]), Some((false, "a".into())));
        assert_eq!(decided(&[("a", allow), ("b", deny)]), Some((true, "a".into())));
        assert_eq!(decided(&[("a", silent.clone())]), None);
        assert_eq!(decided(&[]), None);
        let later = json!({ "experimental": { "policies": [pol("deny", "x"), pol("allow", "x")] } });
        assert_eq!(decided(&[("a", silent), ("b", later)]), Some((true, "b".into())));
    }

    #[test]
    fn a_project_root_is_above_its_dot_dir_or_beside_its_file() {
        assert_eq!(project_root(Path::new("/p/.opencode/opencode.json")), Some(Path::new("/p")));
        assert_eq!(project_root(Path::new("/p/opencode.json")), Some(Path::new("/p")));
    }

    /// OpenCode runs an agent pinned to a denied provider on the default model,
    /// so the pin takes nothing away from the provisioned config.
    #[test]
    fn a_pin_to_a_denied_provider_is_not_reported() {
        let c = json!({ "agents": {
            "reviewer": { "model": { "providerID": "denied", "model": "x" } },
            "writer": { "model": "usable/x" }
        } });
        let allowed = |p: &str| p != "denied";
        assert_eq!(agents_pinned_elsewhere(&c, P, &allowed), vec!["writer"]);
        // With its provider usable, the same pin is reported.
        assert_eq!(agents_pinned_elsewhere(&c, P, &any), vec!["reviewer", "writer"]);
    }

    /// The warning says a deny was taken away, so it needs a deny: an admin's
    /// profile without one leaves nothing to report.
    #[test]
    fn only_a_provisioned_deny_of_the_hosted_provider_counts() {
        assert!(states_hosted_deny(&json!({ "experimental": { "policies": [pol("deny", "opencode")] } })));
        for not_the_deny in [
            json!({}),
            json!({ "experimental": { "policies": [pol("allow", "opencode")] } }),
            json!({ "experimental": { "policies": [pol("deny", "*")] } }),
            json!({ "experimental": { "policies": [
                { "action": "tool.use", "resource": "opencode", "effect": "deny" }
            ] } }),
        ] {
            assert!(!states_hosted_deny(&not_the_deny), "{not_the_deny}");
        }
    }

    /// The render states the deny before the allow: the merge puts a missing
    /// entry right before the next rendered one the file holds, so an allow
    /// rendered first would land ahead of a user's `deny *` after an old deny.
    #[test]
    fn a_merge_keeps_the_gateway_allow_after_a_users_deny_of_everything() {
        let keyed = [("/experimental/policies".to_string(), "action+resource".to_string())].into();
        let rendered = json!({ "experimental": { "policies": [pol("deny", "opencode"), pol("allow", P)] } });
        for existing in [
            json!({ "experimental": { "policies": [pol("deny", "*"), pol("allow", "mine")] } }),
            json!({ "experimental": { "policies": [pol("deny", "opencode"), pol("deny", "*"), pol("allow", "mine")] } }),
            // A home config an earlier provisioning wrote: the deny joins ahead of the allow it holds.
            json!({ "experimental": { "policies": [pol("deny", "*"), pol("allow", "mine"), pol("allow", P)] } }),
        ] {
            let out = crate::writer::merge(
                streamscope_client_templates::TemplateFormat::Json,
                Some(&existing.to_string()),
                &rendered.to_string(),
                &[],
                &keyed,
            )
            .unwrap();
            let merged: Value = serde_json::from_str(&out.contents).unwrap();
            assert!(provider_allowed(&merged, P), "{merged}");
            assert!(provider_allowed(&merged, "mine"), "{merged}");
            assert_eq!(last_decision(&merged, HOSTED_PROVIDER), Some(false), "{merged}");
        }
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
