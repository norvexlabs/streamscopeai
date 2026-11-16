//! What OpenCode's other configs do to a provisioned OpenCode client.
//!
//! OpenCode 2 reads a chain of config documents ([`load_order`]). The earliest
//! loaded with a `provider.use` statement matching a provider decides it, so a
//! user-level `deny` cannot be lifted by a project `allow`, and a repository's
//! root `opencode.json` outranks its `.opencode/` (a V1 `enabled_providers` /
//! `disabled_providers` list, `experimental.policies` and the top-level
//! `policies` load as such statements, in that order). Settings go the other
//! way: the latest-loaded document wins. A per-agent model
//! (`agents.<id>.model`, V1 `agent.<id>.model`, a Markdown agent's `model`)
//! beats the default `model`, which every agent without one of its own runs
//! on. Each sends plain `opencode` to another provider while the provisioned
//! file looks right. In a project, `ssai run opencode` points OpenCode's user
//! config dir at the project's config dir
//! ([`crate::sandbox::profiles::project_config_dir`]), which changes the
//! chain, so each launch is decided on its own. `provision` and `status`
//! judge a global client as launched from home, its launch directory being
//! unknown to them; every `ssai run` judges the one launch it starts
//! ([`at_launch`]), from where it starts — under `--sandbox docker` inside the
//! container, whose home is a volume the host does not read. Every provisioned form pins the built-in agents itself,
//! and denies OpenCode's own hosted provider.
//!
//! This module only reads and reports; it never writes a config.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

/// OpenCode's own hosted provider. With no credential it serves its zero-cost
/// models under a public key, so they are offered beside the gateway's and a
/// request to one never reaches the gateway. Every provisioned form denies it.
const HOSTED_PROVIDER: &str = "opencode";

/// The file names OpenCode reads in a config directory, in the order it loads them.
const CONFIG_NAMES: [&str; 2] = ["opencode.json", "opencode.jsonc"];

/// The folders of a config dir holding Markdown agents, in the order OpenCode
/// scans them: each group's files sorted together, the first group searched at
/// any depth, the second only at its top.
const AGENT_FOLDERS: [(&[&str], bool); 2] = [(&["agent", "agents"], true), (&["mode", "modes"], false)];

/// How deep an agent folder is searched: a bound on a symlink loop.
const AGENT_DEPTH: usize = 8;

/// Folders an agent search never enters, as OpenCode's scan does not.
const AGENT_SKIPPED: [&str; 5] = ["node_modules", ".git", ".venv", "venv", "__pycache__"];

/// How many entries one config dir's agent search reads at most: the
/// container's init reads a home the agent writes, and a folder holding
/// thousands of files must not keep the run from starting.
const AGENT_ENTRIES: usize = 1_000;

/// The largest config document read: a bigger one is read as missing.
const MAX_CONFIG_BYTES: u64 = 1 << 20;

/// The launch every warning names when there is only one: plain `opencode`.
const PLAIN: &str = "`opencode`";

/// A config document OpenCode loads: a config file, or a Markdown agent named
/// `agent`, read as `{ "agents": { <agent>: <its front matter> } }`.
#[derive(Debug, Clone, PartialEq)]
struct Source {
    path: PathBuf,
    agent: Option<String>,
    /// A config dir whose agent search stopped at [`AGENT_ENTRIES`]: `path`
    /// is the dir, and the agents past the cut are not judged.
    cut: bool,
}

/// A config document OpenCode loads, with its contents.
type Document = (PathBuf, Value);

/// What each launch loads: `plain` (named `single` when it is the only one) and,
/// when `ssai run opencode` loads other documents, `run`.
struct Launches<'a> {
    plain: &'a [Document],
    run: Option<&'a [Document]>,
    single: &'a str,
}

/// The directory OpenCode reads its user config from, in an environment `var`
/// reads: `$OPENCODE_CONFIG_DIR`, else `$XDG_CONFIG_HOME/opencode`, else
/// `<home>/.config/opencode`; a relative value is taken from `cwd`, where
/// OpenCode starts.
pub fn config_dir_in(var: &dyn Fn(&str) -> Option<String>, home: &Path, cwd: &Path) -> PathBuf {
    let var = |k: &str| var(k).filter(|v| !v.is_empty()).map(|v| cwd.join(v));
    var("OPENCODE_CONFIG_DIR")
        .or_else(|| var("XDG_CONFIG_HOME").map(|x| x.join("opencode")))
        .unwrap_or_else(|| home.join(".config").join("opencode"))
}

/// Where [`conflicts`] judges from: the home directory, the working directory
/// and the environment.
struct Host<'a> {
    home: PathBuf,
    cwd: PathBuf,
    var: &'a dyn Fn(&str) -> Option<String>,
}

/// The directory plain `opencode` reads its user config from on `host`
/// ([`config_dir_in`]). An `$OPENCODE_CONFIG_DIR` naming `run_dir` is the one
/// `ssai run` set — this is a shell inside the run — so it is passed over.
fn user_config_dir(host: &Host, run_dir: Option<&Path>) -> PathBuf {
    let var = |k: &str| {
        (host.var)(k)
            .filter(|v| !(k == "OPENCODE_CONFIG_DIR" && run_dir.is_some_and(|r| crate::state::same_file(&host.cwd.join(v), r))))
    };
    config_dir_in(&var, &host.home, &host.cwd)
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
/// elsewhere, a default model elsewhere) — what `status` reports in place of
/// `ok`; an unreadable file is reported, not called an override.
pub struct Conflict {
    pub text: String,
    pub overrides: bool,
}

/// Warnings for `provider` from every config document OpenCode loads, each
/// naming its file. Empty when nothing outranks the provisioned config.
/// `provisioned` is the file the provisioning wrote, `project` the canonical
/// root of the project whose record it is (`None` for a global provisioning).
/// In a project an agent the provisioned file pins itself is not reported from
/// a document loaded before it, which it outranks; a global provisioning's own
/// statements are still checked — a deny the user wrote there blocks the
/// provider all the same. A global provisioning's launch directory is unknown:
/// it is read as one under home.
pub fn conflicts(provider: &str, provisioned: Option<&Path>, project: Option<&Path>) -> Vec<Conflict> {
    let Ok(home) = crate::state::home_dir() else { return Vec::new() };
    let cwd = std::env::current_dir().unwrap_or_else(|_| home.clone());
    let var = |k: &str| std::env::var(k).ok();
    conflicts_in(&Host { home, cwd, var: &var }, provider, provisioned, project)
}

/// [`conflicts`] on `host`.
fn conflicts_in(host: &Host, provider: &str, recorded: Option<&Path>, project: Option<&Path>) -> Vec<Conflict> {
    let provisioned = recorded.map(canonical);
    let provisioned = provisioned.as_deref();
    let global = project.is_none();
    // The recorded path, as `ssai run` reads it: a linked config's own folder
    // is not the one the run hands OpenCode.
    let run_dir = recorded
        .zip(project)
        .and_then(|(p, root)| crate::sandbox::profiles::project_config_dir(p, root));
    let user_dir = user_config_dir(host, run_dir.as_deref());
    let start = project.unwrap_or(&host.home);
    let plain_order = load_order(&user_dir, Some(start));
    let run_order = run_dir.as_deref().map(|d| load_order(d, Some(start)));
    let plain = read_documents(&plain_order);
    let run = run_order.as_deref().map(read_documents);
    let launches = Launches { plain: &plain, run: run.as_deref(), single: PLAIN };

    let mut out = Vec::new();
    // OpenCode reads its user config from where `$OPENCODE_CONFIG_DIR` /
    // `$XDG_CONFIG_HOME` point: a global provisioning recorded in another
    // folder is a file it does not load. The recorded path's folder, not the
    // resolved file's: a config linked from a dotfiles repository is still
    // written in the config folder.
    if global
        && let Some(p) = recorded
        && let Some(dir) = p.parent()
        && !crate::state::same_file(dir, &user_dir)
    {
        out.push(Conflict {
            text: format!(
                "OpenCode reads its user config from {}, not {} — set OPENCODE_CONFIG_DIR / XDG_CONFIG_HOME \
                 accordingly, or copy the gateway entries there.",
                user_dir.display(),
                p.display()
            ),
            overrides: true,
        });
    }
    let over = if global { "the provisioned config" } else { "this project's config" };
    let order: Vec<&Source> = plain_order.iter().chain(run_order.iter().flatten()).collect();
    out.extend(judge(&order, provider, provisioned, global, over, &launches));
    out
}

/// [`conflicts`] for the one launch `ssai run` starts, judged where it reads
/// what the client will load: by `ssai run` itself ([`at_launch_here`]), or,
/// under `--sandbox docker`, by `ssai __opencode-check`, which the container's
/// init starts as the agent. `user_dir` is the config dir the client's
/// environment names, `cwd` where it starts, `provisioned` the provisioned
/// config's place there, `global` whether it is a global provisioning, whose
/// own pins are judged too.
pub fn at_launch(provider: &str, provisioned: &Path, global: bool, user_dir: &Path, cwd: &Path) -> Vec<String> {
    let provisioned = &canonical(provisioned);
    let order = load_order(user_dir, Some(cwd));
    let documents = read_documents(&order);
    let launches = Launches { plain: &documents, run: None, single: "this run" };
    let mut out = Vec::new();
    if !order.iter().any(|s| s.path.is_file() && canonical(&s.path) == *provisioned) {
        out.push(format!(
            "OpenCode does not load the provisioned config {} in this run: it reads its user config from {} \
             and starts in {} — this run may not use the gateway.",
            provisioned.display(),
            user_dir.display(),
            cwd.display()
        ));
    }
    let order: Vec<&Source> = order.iter().collect();
    out.extend(judge(&order, provider, Some(provisioned), global, "the provisioned config", &launches).into_iter().map(|c| c.text));
    out
}

/// [`at_launch`] for a client `ssai run` starts here, as this user, in `cwd`:
/// `env` holds the variables the run sets over this process's own.
pub fn at_launch_here(launch: &crate::sandbox::OpencodeLaunch, env: &[(String, String)], cwd: &Path) -> Vec<String> {
    let Ok(home) = crate::state::home_dir() else { return Vec::new() };
    let var = |k: &str| env.iter().rev().find(|(n, _)| n == k).map(|(_, v)| v.clone()).or_else(|| std::env::var(k).ok());
    let user_dir = config_dir_in(&var, &home, cwd);
    at_launch(&launch.provider, &launch.config, launch.global, &user_dir, cwd)
}

/// The warnings for the documents `order` loads under `launches`: each file's
/// own (once per resolved file; a project's provisioned file's pins are not
/// reported, a global provisioning's are), then what the chain decides.
fn judge(order: &[&Source], provider: &str, provisioned: Option<&Path>, global: bool, over: &str, launches: &Launches) -> Vec<Conflict> {
    let mut out = Vec::new();
    let mut seen: Vec<PathBuf> = Vec::new();
    for source in order {
        if source.cut {
            let dir = canonical(&source.path);
            if seen.contains(&dir) {
                continue;
            }
            seen.push(dir);
            out.push(Conflict {
                text: format!(
                    "OpenCode's agent folders in {} hold more than {AGENT_ENTRIES} entries, so the agents past them \
                     are not checked here.",
                    source.path.display()
                ),
                overrides: false,
            });
            continue;
        }
        if !source.path.is_file() {
            continue;
        }
        let file = canonical(&source.path);
        if seen.contains(&file) {
            continue;
        }
        let skip = provisioned.filter(|_| !global) == Some(file.as_path());
        out.extend(source_conflicts(source, &file, skip, provider, over, launches));
        seen.push(file);
    }
    let provisioned_config = provisioned.and_then(|p| parsed(launches, p).cloned().or_else(|| read_config(p, None).ok()));
    out.extend(launch_conflicts(provider, provisioned, provisioned_config.as_ref(), launches));
    out
}

/// The contents `launches` read for the resolved file `file`.
fn parsed<'a>(launches: &Launches<'a>, file: &Path) -> Option<&'a Value> {
    launches.plain.iter().chain(launches.run.into_iter().flatten()).find(|(p, _)| p == file).map(|(_, c)| c)
}

/// What one loaded document, at resolved path `file`, does on its own: a
/// config file that does not parse, or agents it pins to another provider
/// under each launch (none when `skip`: the provisioned file, in a project).
fn source_conflicts(source: &Source, file: &Path, skip: bool, provider: &str, over: &str, launches: &Launches) -> Vec<Conflict> {
    let shown = source.path.display();
    let Some(config) = parsed(launches, file) else {
        let too_big = std::fs::metadata(&source.path).is_ok_and(|m| m.len() > MAX_CONFIG_BYTES);
        let unreadable = open_unblocked(&source.path).is_err();
        let text = if too_big {
            format!("OpenCode's config {shown} is larger than 1 MiB, so what it decides is not checked here.")
        } else if unreadable {
            format!("OpenCode's config {shown} cannot be read here, so what it decides is not checked.")
        } else {
            format!("OpenCode's config {shown} is not valid JSON — OpenCode may refuse to start.")
        };
        return vec![Conflict { text, overrides: false }];
    };
    if skip {
        return Vec::new();
    }
    // A pin matters to the launches that load its file, each with its own rules.
    let pinned = |documents: &[Document]| pinned_under(config, provider, documents, file);
    pins_warnings(&shown.to_string(), over, launches.single, pinned(launches.plain), launches.run.map(pinned))
        .into_iter()
        .map(|text| Conflict { text, overrides: true })
        .collect()
}

/// What the chain decides as a whole: a deny of the gateway, an allow of the
/// hosted provider the provisioned config denies, a default model elsewhere.
fn launch_conflicts(provider: &str, provisioned: Option<&Path>, provisioned_config: Option<&Value>, launches: &Launches) -> Vec<Conflict> {
    let hosted = provisioned_config.is_some_and(states_hosted_deny).then(|| hosted_allowed(launches));
    gateway_denied(launches, provider)
        .into_iter()
        .chain(hosted.into_iter().flatten())
        .chain(default_model_elsewhere(launches, provider, provisioned))
        .map(|text| Conflict { text, overrides: true })
        .collect()
}

/// The config documents OpenCode loads, in its load order, with `user_dir` as
/// its user config dir and `start` as its working directory: the user config
/// dir, then each directory's own files from the filesystem root down to
/// `start`, then each directory's `.opencode/` in the same order; a config dir
/// (the user's, a `.opencode/`) adds its Markdown agents right after its files.
/// The user config dir is not read a second time through the walk, and
/// `~/.opencode` is loaded only from a directory under home. A machine-wide
/// managed policy and a config passed in the environment are not read here,
/// nor a config below `start`, which only a launch from that directory loads.
fn load_order(user_dir: &Path, start: Option<&Path>) -> Vec<Source> {
    let files = |dir: &Path| CONFIG_NAMES.map(|name| Source { path: dir.join(name), agent: None, cut: false }).to_vec();
    let config_dir = |dir: &Path| {
        let mut out = files(dir);
        out.extend(markdown_agents(dir));
        out
    };
    let mut walked: Vec<&Path> = start.map(|s| s.ancestors().collect()).unwrap_or_default();
    walked.reverse();
    let is_user_dir = |dir: &Path| crate::state::same_file(dir, user_dir);
    let own = walked.iter().filter(|d| !is_user_dir(d)).flat_map(|d| files(d));
    let dot_dirs = walked.iter().map(|d| d.join(".opencode")).filter(|d| !is_user_dir(d));
    config_dir(user_dir).into_iter().chain(own).chain(dot_dirs.flat_map(|d| config_dir(&d))).collect()
}

/// The Markdown agents of config dir `dir`, in OpenCode's order, each named by
/// its path under its folder without `.md` (`agents/review/deep.md` is
/// `review/deep`).
fn markdown_agents(dir: &Path) -> Vec<Source> {
    let mut out = Vec::new();
    let mut walk = Walk { budget: AGENT_ENTRIES, visited: Vec::new(), cut: false };
    for (folders, deep) in AGENT_FOLDERS {
        let mut found = Vec::new();
        for folder in folders {
            find_markdown(&dir.join(folder), if deep { AGENT_DEPTH } else { 0 }, &mut walk, &mut found);
        }
        found.sort_by_cached_key(|p| p.to_string_lossy().into_owned());
        out.extend(found.into_iter().filter_map(|path| {
            let mut parts = path.strip_prefix(dir).ok()?.components();
            parts.next();
            let name = parts.as_path().with_extension("").to_string_lossy().replace('\\', "/");
            Some(Source { path, agent: Some(name), cut: false })
        }));
    }
    if walk.cut {
        out.push(Source { path: dir.to_path_buf(), agent: None, cut: true });
    }
    out
}

/// What one agent search has left to read, and the folders it has read (by
/// resolved path: a link back to one is not read again).
struct Walk {
    budget: usize,
    visited: Vec<PathBuf>,
    /// An entry was left unread when the budget ran out.
    cut: bool,
}

/// Every `.md` file under `dir`, `depth` folders down, each folder read once.
fn find_markdown(dir: &Path, depth: usize, walk: &mut Walk, out: &mut Vec<PathBuf>) {
    let Ok(real) = dunce::canonicalize(dir) else { return };
    if walk.visited.contains(&real) {
        return;
    }
    walk.visited.push(real);
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        if walk.budget == 0 {
            walk.cut = true;
            return;
        }
        walk.budget -= 1;
        let path = entry.path();
        if path.is_dir() {
            let skipped = path.file_name().is_some_and(|n| AGENT_SKIPPED.iter().any(|s| n == *s));
            if depth > 0 && !skipped {
                find_markdown(&path, depth - 1, walk, out);
            }
        } else if path.extension().is_some_and(|e| e == "md") {
            out.push(path);
        }
    }
}

/// The sources of `order` that exist and parse, each at its resolved path,
/// with its contents. A file
/// that does not parse is skipped here; [`conflicts`] reports it on its own.
fn read_documents(order: &[Source]) -> Vec<Document> {
    order
        .iter()
        .filter_map(|s| Some((canonical(&s.path), read_config(&s.path, s.agent.as_deref()).ok()?)))
        .collect()
}

/// `path` resolved, so documents compare by `==` (one lookup per document,
/// never one per comparison); as it is when it does not resolve.
pub fn canonical(path: &Path) -> PathBuf {
    dunce::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// A source's contents: a config file parsed as JSONC; a Markdown agent as
/// `{ "agents": { <agent>: <its front matter> } }`, the front matter empty when
/// the file has none OpenCode reads (it skips such a file).
fn read_config(path: &Path, agent: Option<&str>) -> Result<Value, ()> {
    let Some(name) = agent else {
        let text = read_small(path).ok_or(())?;
        return crate::writer::json::parse_jsonc(&text).map_err(|_| ());
    };
    let front = read_small(path).and_then(|t| front_matter(&t)).unwrap_or_else(|| json!({}));
    Ok(json!({ "agents": { name: front } }))
}

/// A regular file's text, up to [`MAX_CONFIG_BYTES`]: never a FIFO or a device
/// (the container's init reads a home the agent writes, and must not block).
fn read_small(path: &Path) -> Option<String> {
    use std::io::Read;
    let file = open_unblocked(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() > MAX_CONFIG_BYTES {
        return None;
    }
    let mut text = String::new();
    file.take(MAX_CONFIG_BYTES).read_to_string(&mut text).ok()?;
    Some(text)
}

/// `path` opened for reading, never waiting: opening a FIFO for reading
/// blocks until a writer comes, and opening a terminal could make it the
/// reader's controlling one — neither with these flags.
fn open_unblocked(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NONBLOCK | libc::O_NOCTTY);
    options.open(path)
}

/// A Markdown file's YAML front matter (`---` lines around it, at the top), as
/// an object.
/// The block ends at the first `\n---`, as gray-matter (OpenCode's parser)
/// finds it; YAML that does not parse is read again as OpenCode retries it
/// ([`block_scalar_values`]).
fn front_matter(text: &str) -> Option<Value> {
    let rest = text.strip_prefix("---")?;
    let rest = rest.strip_prefix("\r\n").or_else(|| rest.strip_prefix('\n'))?;
    let end = rest.find("\n---")?;
    let yaml = rest[..end].strip_suffix('\r').unwrap_or(&rest[..end]);
    let parse = |y: &str| yaml_serde::from_str::<Value>(y).ok().filter(Value::is_object);
    parse(yaml).or_else(|| parse(&block_scalar_values(yaml)))
}

/// OpenCode's retry of front matter that does not parse (`ConfigMarkdown.sanitize`
/// in its core package): a top-level `key: value` line whose plain value holds a
/// `:` (or starts with `[`/`{` and goes on after its close) becomes a block
/// scalar, so other agents' unquoted values still load. Keep in step with it.
fn block_scalar_values(yaml: &str) -> String {
    let out: Vec<String> = yaml
        .split('\n')
        .map(|l| l.strip_suffix('\r').unwrap_or(l))
        .map(|line| {
            let keep = line.to_string();
            let trimmed = line.trim();
            if trimmed.starts_with('#') || trimmed.is_empty() || line.starts_with(char::is_whitespace) {
                return keep;
            }
            let Some((key, value)) = line.split_once(':') else { return keep };
            let key = key.trim_end();
            let is_key = key.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
            let value = value.trim();
            if !is_key || value.is_empty() || matches!(value, ">" | "|") || value.starts_with(['"', '\'']) {
                return keep;
            }
            // `[…] text` / `{…} text`: a flow collection with text after it.
            let tagged = value.starts_with(['[', '{'])
                && value.match_indices([']', '}']).any(|(i, _)| i > 0 && !value[i + 1..].trim_start().is_empty());
            if !value.contains(':') && !tagged {
                return keep;
            }
            format!("{key}: |-\n  {value}")
        })
        .collect();
    out.join("\n")
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

/// A provisioned OpenCode client's gateway provider key and its main config —
/// `None` for any other client, or one whose config registers no gateway provider.
pub fn gateway_of(client: &crate::state::ManagedClient) -> Option<(String, PathBuf)> {
    if client.client_id != "opencode" {
        return None;
    }
    let file = client.files.first()?;
    let owned: Vec<&str> = file.owned.iter().map(|o| o.path.as_str()).collect();
    Some((provider_key(&owned)?, crate::state::expand_tilde(&file.path).ok()?))
}

/// [`conflicts`] for a provisioned client record — empty for any client but
/// OpenCode, or one whose config registers no gateway provider. `project` is
/// the root of the project whose manifest holds the record, `None` for the
/// global one.
pub fn for_managed(client: &crate::state::ManagedClient, project: Option<&Path>) -> Vec<Conflict> {
    let Some((provider, provisioned)) = gateway_of(client) else { return Vec::new() };
    conflicts(&provider, Some(&provisioned), project.map(canonical).as_deref())
}

/// Every agent a config gives a model of its own.
fn pinned_agents(config: &Value) -> Vec<String> {
    ["agents", "agent"]
        .iter()
        .filter_map(|k| config.get(*k).and_then(Value::as_object))
        .flat_map(|m| m.iter().filter(|(_, a)| a.get("model").is_some()).map(|(id, _)| id.clone()))
        .collect()
}

/// The agents `config`, the document at `file` (resolved, as the documents' paths are), takes off `provider` under the
/// launch loading `documents`: nothing if that launch does not load it. An agent
/// a later-loaded document also pins is left out, since the latest-loaded pin
/// wins, and a pin to a provider that launch denies runs on the default model.
fn pinned_under(config: &Value, provider: &str, documents: &[Document], file: &Path) -> Vec<String> {
    let Some(at) = documents.iter().position(|(p, _)| p == file) else {
        return Vec::new();
    };
    let pinned = agents_pinned_elsewhere(config, provider, &|pinned| decided_allowed(documents, pinned));
    if pinned.is_empty() {
        return pinned;
    }
    let later: Vec<String> = documents[at + 1..].iter().flat_map(|(_, later)| pinned_agents(later)).collect();
    pinned.into_iter().filter(|agent| !later.contains(agent)).collect()
}

/// The warnings for a file's pins under each launch, `run` being `Some` when
/// `ssai run opencode` loads other documents than plain `opencode`; `single`
/// names the launch when there is only one, `over` the config they outrank.
fn pins_warnings(file: &str, over: &str, single: &str, plain: Vec<String>, run: Option<Vec<String>>) -> Vec<String> {
    let warning = |agents: &[String], launches: &str, note: &str| {
        format!(
            "OpenCode's config {file} pins agent(s) {} to another provider's model, which outranks {over} — \
             under {launches} they run there{note}.",
            agents.join(", ")
        )
    };
    let Some(run) = run else {
        return if plain.is_empty() { Vec::new() } else { vec![warning(&plain, single, "")] };
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
    policy_statements(provisioned).any(|statement| {
        let field = |k: &str| statement.get(k).and_then(Value::as_str);
        field("action") == Some("provider.use")
            && field("resource") == Some(HOSTED_PROVIDER)
            && field("effect") == Some("deny")
    })
}

/// The warnings for a document that decides to allow the hosted provider, which
/// takes the provisioned deny away.
fn hosted_allowed(launches: &Launches) -> Vec<String> {
    let decided_by = |documents: &[Document]| allowed_by(documents, HOSTED_PROVIDER, true);
    launch_warnings(launches, &decided_by, &|file, launches, note| {
        format!(
            "OpenCode's config {file} allows its own hosted provider `{HOSTED_PROVIDER}`, and no config outranking \
             that file denies it — its models are on offer under {launches}, and a request to one bypasses the \
             gateway{note}. To hide it, remove that statement or end that file's last list of provider rules (its \
             `policies` when it has one, else experimental.policies) with: \
             {{ \"action\": \"provider.use\", \"resource\": \"{HOSTED_PROVIDER}\", \"effect\": \"deny\" }}."
        )
    })
}

/// The warnings for a document that decides to deny the gateway's provider.
fn gateway_denied(launches: &Launches, provider: &str) -> Vec<String> {
    let decided_by = |documents: &[Document]| allowed_by(documents, provider, false);
    launch_warnings(launches, &decided_by, &|file, launches, note| {
        format!(
            "OpenCode's config {file} denies provider `{provider}`, and no config outranking that file allows it — \
             {launches} will not use the gateway{note}. To allow it, end that file's last list of provider \
             rules (its `policies` when it has one, else experimental.policies) with: {{ \"action\": \"provider.use\", \
             \"resource\": \"{provider}\", \"effect\": \"allow\" }} — then run `opencode service restart`."
        )
    })
}

/// The file whose decision for `provider` is `effect`, if one decides.
fn allowed_by(documents: &[Document], provider: &str, effect: bool) -> Option<PathBuf> {
    decide(documents, provider).and_then(|(d, file)| (d == effect).then(|| file.to_path_buf()))
}

/// The warnings for a default `model` on another usable provider set by a
/// document loaded after the provisioned one: every agent without a model of
/// its own runs there (the built-in agents keep the pins the provisioning gave
/// them).
fn default_model_elsewhere(launches: &Launches, provider: &str, provisioned: Option<&Path>) -> Vec<String> {
    let decided_by = |documents: &[Document]| {
        let (path, config) = documents.iter().rev().find(|(_, c)| c.get("model").is_some())?;
        let to = model_provider(config.get("model")?)?;
        let ours = provisioned == Some(path.as_path());
        (to != provider && !ours && decided_allowed(documents, &to)).then(|| path.clone())
    };
    launch_warnings(launches, &decided_by, &|file, launches, note| {
        format!(
            "OpenCode's config {file} sets the default `model` to another provider's, and no config loaded after \
             it sets one — under {launches} an agent with no model of its own (one you add without a `model`) \
             runs there{note}. Remove that `model`, or point it at provider `{provider}`."
        )
    })
}

/// One warning per file `decided_by` names for a launch. Each launch is
/// decided on its own, since a file can decide under one and not the other.
/// `warning` gets the file, the launches it reaches, and a note for a launch it
/// leaves alone.
fn launch_warnings(
    launches: &Launches,
    decided_by: &dyn Fn(&[Document]) -> Option<PathBuf>,
    warning: &dyn Fn(String, &str, &str) -> String,
) -> Vec<String> {
    let by_plain = decided_by(launches.plain);
    let by_run = launches.run.and_then(decided_by);
    let shown = |file: &Path| file.display().to_string();
    let mut out = Vec::new();
    if let Some(file) = &by_plain {
        out.push(match (launches.run, &by_run) {
            (None, _) => warning(shown(file), launches.single, ""),
            (Some(_), None) => warning(shown(file), "plain `opencode`", " (`ssai run opencode` is unaffected)"),
            (Some(_), Some(other)) if other == file => {
                warning(shown(file), "plain `opencode` and `ssai run opencode`", "")
            }
            (Some(_), Some(_)) => warning(shown(file), "plain `opencode`", ""),
        });
    }
    if let Some(file) = by_run.filter(|file| by_plain.as_ref() != Some(file)) {
        out.push(warning(shown(&file), "`ssai run opencode`", ""));
    }
    out
}

/// A document's policy statements in the order OpenCode reads them as one
/// sequence: `experimental.policies`, then the top-level `policies`.
fn policy_statements(config: &Value) -> impl Iterator<Item = &Value> {
    let experimental = config.get("experimental").and_then(|e| e.get("policies")).and_then(Value::as_array);
    let native = config.get("policies").and_then(Value::as_array);
    experimental.into_iter().flatten().chain(native.into_iter().flatten())
}

/// What the config's last statement matching `provider` decides, `None` when
/// none matches: V1 lists first (`enabled_providers` = deny `*` + allow each,
/// then `disabled_providers` = deny each), then `experimental.policies`, then
/// the top-level `policies`, each in order.
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
    for statement in policy_statements(config) {
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

/// The provider a model selection names: V2 `{providerID, …}` or
/// `"provider/model"`.
fn model_provider(model: &Value) -> Option<String> {
    match model {
        Value::Object(m) => m.get("providerID").and_then(Value::as_str).map(str::to_string),
        Value::String(s) => s.split_once('/').map(|(p, _)| p.to_string()),
        _ => None,
    }
}

/// Agents whose model in this config names a usable provider other than `provider`,
/// sorted. A pin to a provider `allowed` refuses is left out: OpenCode runs that
/// agent on the default model instead. Reads V2 `agents.<id>.model` and V1
/// `agent.<id>.model` ([`model_provider`]).
fn agents_pinned_elsewhere(config: &Value, provider: &str, allowed: &dyn Fn(&str) -> bool) -> Vec<String> {
    let mut out = Vec::new();
    for key in ["agents", "agent"] {
        let Some(agents) = config.get(key).and_then(Value::as_object) else { continue };
        for (id, agent) in agents {
            let model_provider = agent.get("model").and_then(model_provider);
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
        let w = pins_warnings("g.json", "this project's config", PLAIN, build.clone(), Some(Vec::new()));
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("build") && w[0].contains("this project's config"), "{w:?}");
        assert!(w[0].contains("under plain `opencode` they") && w[0].contains("is unaffected"), "{w:?}");
        let w = pins_warnings("g.json", "this project's config", PLAIN, Vec::new(), Some(build.clone()));
        assert!(w[0].contains("under `ssai run opencode` they") && !w[0].contains("is unaffected"), "{w:?}");
        let w = pins_warnings("g.json", "this project's config", PLAIN, build.clone(), Some(build.clone()));
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("under plain `opencode` and `ssai run opencode` they"), "{w:?}");
        let w = pins_warnings("g.json", "this project's config", PLAIN, build.clone(), Some(agents(&["plan"])));
        assert_eq!(w.len(), 2, "{w:?}");
        assert!(w[0].contains("build") && !w[0].contains("is unaffected") && w[1].contains("plan"), "{w:?}");
        // A global provisioning: one launch.
        let w = pins_warnings("g.json", "the provisioned config", PLAIN, build, None);
        assert!(w[0].contains("under `opencode` they") && w[0].contains("the provisioned config"), "{w:?}");
        assert!(pins_warnings("g.json", "this project's config", PLAIN, Vec::new(), Some(Vec::new())).is_empty());
        assert!(pins_warnings("g.json", "the provisioned config", PLAIN, Vec::new(), None).is_empty());
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
        let w = gateway_denied(&Launches { plain: &plain, run: Some(&run[..]), single: PLAIN }, P);
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("home.json") && w[0].contains(P) && w[0].contains("plain `opencode` will not use"), "{w:?}");
        assert!(w[0].contains("`ssai run opencode` is unaffected"), "{w:?}");
        // A repository's root file, which `run` loads too.
        let both = docs(&[("root.json", deny_all.clone())]);
        let w = gateway_denied(&Launches { plain: &both, run: Some(&both[..]), single: PLAIN }, P);
        assert!(w[0].contains("plain `opencode` and `ssai run opencode` will not use"), "{w:?}");
        assert!(!w[0].contains("is unaffected"), "{w:?}");
        // A global provisioning: one launch, and an earlier allow outranks a deny after it.
        assert!(gateway_denied(&Launches { plain: &docs(&[("g.json", deny_all.clone())]), run: None, single: PLAIN }, P)[0].contains("— `opencode` will not use"));
        assert!(gateway_denied(&Launches { plain: &docs(&[("a.json", allow), ("b.json", deny_all)]), run: None, single: PLAIN }, P).is_empty());
        assert!(gateway_denied(&Launches { plain: &docs(&[("a.json", silent)]), run: None, single: PLAIN }, P).is_empty());
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
        let w = pins_warnings("g.json", "the provisioned config", PLAIN, agents_pinned_elsewhere(&merged, P, &any), None);
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
            let alone = hosted_allowed(&Launches { plain: &plain, run: None, single: PLAIN });
            assert_eq!(alone.len(), 1, "{alone:?}");
            assert!(alone[0].contains("g.json") && alone[0].contains("on offer under `opencode`,"), "{alone:?}");
            let run = docs(&[deny.clone(), ("g.json", allowing)]);
            let w = hosted_allowed(&Launches { plain: &plain, run: Some(&run[..]), single: PLAIN });
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
            assert_eq!(hosted_allowed(&Launches { plain: &docs(&[("g.json", silent.clone()), deny.clone()]), run: None, single: PLAIN }), Vec::<String>::new(), "{silent}");
        }
    }

    /// Each launch is decided on its own, and the warning says which it reaches.
    #[test]
    fn the_hosted_warning_names_the_launches_each_file_reaches() {
        let allow = json!({ "experimental": { "policies": [pol("allow", "opencode")] } });
        let deny = json!({ "experimental": { "policies": [pol("deny", "opencode")] } });
        // A statement after the deny in the provisioned file itself, with nothing above it.
        let plain = docs(&[("dot.json", allow.clone())]);
        let w = hosted_allowed(&Launches { plain: &plain, run: Some(&plain[..]), single: PLAIN });
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("under plain `opencode` and `ssai run opencode`,"), "{w:?}");
        // A home deny hides it from plain `opencode`; `run` leaves that home out.
        let w = hosted_allowed(&Launches { plain: &docs(&[("home.json", deny), ("dot.json", allow.clone())]), run: Some(&plain[..]), single: PLAIN });
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("dot.json") && w[0].contains("on offer under `ssai run opencode`,"), "{w:?}");
        // Two different files, one per launch: both are named.
        let w = hosted_allowed(&Launches { plain: &docs(&[("home.json", allow.clone()), ("dot.json", allow)]), run: Some(&plain[..]), single: PLAIN });
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
        let paths = |order: Vec<Source>| order.into_iter().map(|s| s.path).collect::<Vec<_>>();
        let order = paths(load_order(Path::new("/h/.config/opencode"), Some(Path::new("/h/p"))));
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
        let run = paths(load_order(Path::new("/h/p/.opencode"), Some(Path::new("/h/p"))));
        assert_eq!(run[0], Path::new("/h/p/.opencode/opencode.json"));
        assert_eq!(run.iter().filter(|p| p.starts_with("/h/p/.opencode")).count(), 2, "{run:?}");
        assert_eq!(load_order(Path::new("/u"), None).len(), 2);
        // A project outside the home directory never reaches `~/.opencode`.
        let outside = paths(load_order(Path::new("/h/.config/opencode"), Some(Path::new("/srv/p"))));
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
        assert!(states_hosted_deny(&json!({ "policies": [pol("deny", "opencode")] })));
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

    /// The render states the deny before the allow, in both lists: the merge
    /// puts a missing entry right before the next rendered one the file holds,
    /// so an allow rendered first would land ahead of a user's `deny *` after an
    /// old deny; a `deny *` in either list is lifted.
    #[test]
    fn a_merge_keeps_the_gateway_allow_after_a_users_deny_of_everything() {
        let keyed = [
            ("/experimental/policies".to_string(), "action+resource".to_string()),
            ("/policies".to_string(), "action+resource".to_string()),
        ]
        .into();
        let ours = [pol("deny", "opencode"), pol("allow", P)];
        let rendered = json!({ "experimental": { "policies": ours }, "policies": ours });
        for existing in [
            // The top-level list, read after the experimental one, denying everything.
            json!({ "policies": [pol("deny", "*"), pol("allow", "mine")] }),
            json!({ "experimental": { "policies": [pol("allow", "mine")] }, "policies": [pol("deny", "*"), pol("allow", "mine")] }),
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

    /// A fresh directory for one test, canonical (macOS's temp dir is a symlink).
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ss-og-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dunce::canonicalize(&dir).unwrap()
    }

    fn write(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    /// The provisioned form's shape, as far as these checks read it.
    fn provisioned_form() -> String {
        json!({
            "model": format!("{P}/m"),
            "agents": { "build": { "model": { "providerID": P, "model": "m" } } },
            "experimental": { "policies": [pol("deny", "opencode")] }
        })
        .to_string()
    }

    /// OpenCode 2 merges the native top-level `policies` after
    /// `experimental.policies`, the later statement of a document winning.
    #[test]
    fn the_top_level_policies_decide_after_the_experimental_ones() {
        assert_eq!(last_decision(&json!({ "policies": [pol("deny", P)] }), P), Some(false));
        let both = json!({ "experimental": { "policies": [pol("deny", P)] }, "policies": [pol("allow", P)] });
        assert_eq!(last_decision(&both, P), Some(true));
        let back = json!({ "experimental": { "policies": [pol("allow", P)] }, "policies": [pol("deny", "*")] });
        assert_eq!(last_decision(&back, P), Some(false));
        assert_eq!(last_decision(&json!({ "policies": [pol("deny", "other")] }), P), None);
        let w = gateway_denied(&Launches { plain: &docs(&[("home.json", json!({ "policies": [pol("deny", P)] }))]), run: None, single: PLAIN }, P);
        assert!(w.len() == 1 && w[0].contains("home.json"), "{w:?}");
    }

    /// A config dir's Markdown agents load right after its files, in
    /// OpenCode's order, named by their path under their folder; a `mode/`
    /// is read at its top only.
    #[test]
    fn a_config_dirs_markdown_agents_load_after_its_files() {
        let dir = scratch("md-order");
        let user = dir.join("u");
        for rel in ["agents/b.md", "agent/review/deep.md", "agent/a.md", "agent/notes.txt", "mode/m.md", "mode/sub/x.md", "agent/node_modules/n.md"] {
            write(&user.join(rel), "---\nmodel: other/x\n---\nBody.\n");
        }
        let order = load_order(&user, None);
        let agents: Vec<(PathBuf, String)> = order
            .iter()
            .filter_map(|s| Some((s.path.strip_prefix(&user).ok()?.to_path_buf(), s.agent.clone()?)))
            .collect();
        let expected = [("agent/a.md", "a"), ("agent/review/deep.md", "review/deep"), ("agents/b.md", "b"), ("mode/m.md", "m")];
        assert_eq!(agents, expected.map(|(p, n)| (PathBuf::from(p), n.to_string())).to_vec());
        assert!(order[..2].iter().all(|s| s.agent.is_none()), "the dir's files come first: {order:?}");
        let documents = read_documents(&order);
        let (_, deep) = documents.iter().find(|(p, _)| p.ends_with("deep.md")).unwrap();
        assert_eq!(deep["agents"]["review/deep"]["model"], "other/x");
    }

    /// A folder linking back up to itself is read once, and the agents it
    /// holds are found.
    #[cfg(unix)]
    #[test]
    fn an_agent_folder_linking_to_itself_is_searched_within_a_bound() {
        let dir = scratch("md-loop");
        write(&dir.join("agents/a.md"), "---\nmodel: other/x\n---\n");
        for i in 0..4 {
            std::os::unix::fs::symlink(dir.join("agents"), dir.join(format!("agents/loop{i}"))).unwrap();
        }
        let found = markdown_agents(&dir);
        let names: Vec<_> = found.iter().filter_map(|s| s.agent.as_deref()).collect();
        assert_eq!(names, ["a"]);
        let provisioned = dir.join("p/.opencode/opencode.json");
        write(&provisioned, &provisioned_form());
        let w = at_launch(P, &provisioned, false, &dir, &dir.join("p"));
        assert!(w.len() == 1 && w[0].contains("agent(s) a"), "{w:#?}");
    }

    /// An agent search cut at its budget says so; one that read every entry,
    /// the budget's last included, does not.
    #[test]
    fn an_agent_search_cut_at_its_budget_is_named() {
        for (entries, cut) in [(AGENT_ENTRIES, false), (AGENT_ENTRIES + 1, true)] {
            let dir = scratch(&format!("md-budget-{entries}"));
            for i in 0..entries {
                write(&dir.join(format!("agents/a{i:04}.md")), "Prompt.\n");
            }
            let provisioned = dir.join("p/.opencode/opencode.json");
            write(&provisioned, &provisioned_form());
            let w = at_launch(P, &provisioned, false, &dir, &dir.join("p"));
            assert_eq!(w.iter().any(|t| t.contains("are not checked here")), cut, "{entries}: {w:#?}");
        }
        // A project's `.opencode`, in both launches' load orders, is named once.
        let root = scratch("md-budget-project");
        let provisioned = root.join(".opencode/opencode.json");
        write(&provisioned, &provisioned_form());
        for i in 0..=AGENT_ENTRIES {
            write(&root.join(format!(".opencode/agents/a{i:04}.md")), "Prompt.\n");
        }
        let w = judged(&provisioned, Some(&root));
        assert_eq!(w.iter().filter(|t| t.contains("are not checked here")).count(), 1, "{w:#?}");
    }

    /// A Markdown agent without front matter OpenCode reads pins nothing, and
    /// is never reported as a broken config.
    #[test]
    fn a_markdown_agent_without_front_matter_pins_nothing() {
        let dir = scratch("md-plain");
        for (name, text) in [("plain.md", "Just a prompt.\n"), ("broken.md", "---\nmodel: [unclosed\n---\n"), ("list.md", "---\n- a\n---\n")] {
            let path = dir.join(name);
            write(&path, text);
            assert_eq!(read_config(&path, Some("x")), Ok(json!({ "agents": { "x": {} } })), "{name}");
        }
        // An unquoted value with a colon: OpenCode retries it as a block scalar,
        // and the model pin beside it stands.
        let colon = dir.join("colon.md");
        write(&colon, "---\ndescription: Reviews code: carefully\nmodel: other/x\n---\nBody\n");
        assert_eq!(read_config(&colon, Some("x")).unwrap()["agents"]["x"]["model"], "other/x");
        let tagged = dir.join("tagged.md");
        write(&tagged, "---\ndescription: [Tag] a reviewer\nmodel: other/y\n---\n");
        assert_eq!(read_config(&tagged, Some("x")).unwrap()["agents"]["x"]["model"], "other/y");
        let windows = dir.join("crlf.md");
        write(&windows, "---\r\nmodel: other/x\r\n---\r\nBody\r\n");
        assert_eq!(read_config(&windows, Some("x")).unwrap()["agents"]["x"]["model"], "other/x");
    }

    /// [`conflicts_in`]'s texts on a host of the test's own: an empty
    /// environment, a home with no config, started in the project.
    fn judged(provisioned: &Path, project: Option<&Path>) -> Vec<String> {
        let home = scratch(&format!("home-{}", project.and_then(Path::file_name).map_or("global".into(), |n| n.to_string_lossy())));
        let cwd = project.map_or_else(|| home.clone(), Path::to_path_buf);
        conflicts_in(&Host { home, cwd, var: &|_| None }, P, Some(provisioned), project).into_iter().map(|c| c.text).collect()
    }

    /// A global provisioning in the home's config, read from another user
    /// config dir: named by the path it was written at, even when that file
    /// links into a dotfiles repository.
    #[test]
    fn a_global_config_opencode_does_not_read_is_named_by_its_recorded_path() {
        let home = scratch("recorded");
        let dotfiles = home.join("dotfiles/opencode.json");
        write(&dotfiles, &provisioned_form());
        let recorded = home.join(".config/opencode/opencode.json");
        std::fs::create_dir_all(recorded.parent().unwrap()).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&dotfiles, &recorded).unwrap();
        #[cfg(windows)]
        std::fs::copy(&dotfiles, &recorded).unwrap();
        let elsewhere = home.join("xdg");
        let judge = |xdg: Option<&Path>| -> Vec<String> {
            let xdg = xdg.map(|x| x.display().to_string());
            let var = move |k: &str| (k == "XDG_CONFIG_HOME").then(|| xdg.clone()).flatten();
            conflicts_in(&Host { home: home.clone(), cwd: home.clone(), var: &var }, P, Some(&recorded), None)
                .into_iter()
                .map(|c| c.text)
                .collect()
        };
        let w = judge(Some(&elsewhere));
        assert!(
            w.iter().any(|t| t.contains("reads its user config from") && t.contains(&recorded.display().to_string())),
            "{w:#?}"
        );
        assert!(!judge(None).iter().any(|t| t.contains("reads its user config from")));
        // The reverse: recorded under `$XDG_CONFIG_HOME`, judged without it.
        let xdg_file = elsewhere.join("opencode/opencode.json");
        write(&xdg_file, &provisioned_form());
        let none = |_: &str| None;
        let w: Vec<String> = conflicts_in(&Host { home: home.clone(), cwd: home.clone(), var: &none }, P, Some(&xdg_file), None)
            .into_iter()
            .map(|c| c.text)
            .collect();
        assert!(w.iter().any(|t| t.contains("reads its user config from")), "{w:#?}");
    }

    /// A project's `.opencode/agent/rev.md` pinned to another provider takes
    /// `rev` off the gateway under both launches; a repository root
    /// `opencode.json` setting the default model outranks the provisioned one
    /// under `ssai run`, which loads it after the project's config dir (its user
    /// config dir there), but not under plain `opencode`, which loads it before.
    #[test]
    fn a_markdown_pin_and_a_repository_default_model_are_reported() {
        let root = scratch("md-project");
        let provisioned = root.join(".opencode/opencode.json");
        write(&provisioned, &provisioned_form());
        write(&root.join(".opencode/agent/rev.md"), "---\ndescription: reviewer\nmodel: other/x\n---\nReview.\n");
        write(&root.join("opencode.json"), r#"{ "model": "other/x" }"#);
        let texts: Vec<String> = judged(&provisioned, Some(&root));
        let pin = texts.iter().find(|t| t.contains("rev.md")).unwrap_or_else(|| panic!("{texts:#?}"));
        assert!(pin.contains("agent(s) rev") && pin.contains("plain `opencode` and `ssai run opencode`"), "{pin}");
        let model = texts.iter().find(|t| t.contains("default `model`")).unwrap_or_else(|| panic!("{texts:#?}"));
        assert!(model.contains(&root.join("opencode.json").display().to_string()), "{model}");
        assert!(model.contains("under `ssai run opencode` an agent"), "{model}");
        // Without the root file's model nothing is said about the default.
        write(&root.join("opencode.json"), "{}");
        assert!(!judged(&provisioned, Some(&root)).iter().any(|t| t.contains("default `model`")));
    }

    /// The default model is the latest-loaded document's; one on the gateway,
    /// on a denied provider, or in the provisioned file itself takes nothing away.
    #[test]
    fn only_a_later_default_model_on_a_usable_provider_is_reported() {
        let ours = ("ours.json", json!({ "model": format!("{P}/m") }));
        let elsewhere = ("repo.json", json!({ "model": { "providerID": "other", "model": "x" } }));
        let report = |files: &[(&str, Value)]| {
            let documents = docs(files);
            default_model_elsewhere(&Launches { plain: &documents, run: None, single: PLAIN }, P, Some(Path::new("ours.json")))
        };
        let w = report(&[ours.clone(), elsewhere.clone()]);
        assert!(w.len() == 1 && w[0].contains("repo.json") && w[0].contains("under `opencode` an agent"), "{w:?}");
        assert!(report(&[elsewhere.clone(), ours.clone()]).is_empty());
        assert!(report(&[ours.clone(), ("repo.json", json!({ "model": format!("{P}/other") }))]).is_empty());
        let denied = ("home.json", json!({ "policies": [pol("deny", "other")] }));
        assert!(report(&[denied, ours.clone(), elsewhere.clone()]).is_empty());
        assert!(report(&[ours, ("repo.json", json!({ "share": "disabled" }))]).is_empty());
    }

    /// `ssai run` hands OpenCode the directory holding a project's config
    /// whatever it is named (an admin's template may not use `.opencode/`):
    /// that launch is judged with that directory as the user config dir.
    #[test]
    fn a_project_config_dir_of_any_name_is_the_run_launchs_user_dir() {
        let root = scratch("cfg-name");
        let provisioned = root.join("config/opencode.json");
        write(&provisioned, &provisioned_form());
        write(&root.join("config/opencode.jsonc"), &json!({ "policies": [pol("deny", P)] }).to_string());
        let texts: Vec<String> = judged(&provisioned, Some(&root));
        assert!(
            texts.iter().any(|t| t.contains(&root.join("config").join("opencode.jsonc").display().to_string())
                && t.contains("`ssai run opencode` will not use")),
            "{texts:#?}"
        );
    }

    /// A run judges the one launch it starts: what it loads, and a
    /// provisioned config OpenCode does not load there at all.
    #[test]
    fn a_run_judges_the_launch_it_starts() {
        let dir = scratch("container");
        let (home, work) = (dir.join("home"), dir.join("ws"));
        let user = home.join(".config/opencode");
        let provisioned = work.join(".opencode/opencode.json");
        write(&provisioned, &provisioned_form());
        write(&user.join("opencode.json"), &json!({ "policies": [pol("deny", P)] }).to_string());
        write(&user.join("agents/rev.md"), "---\nmodel: other/x\n---\n");
        let w = at_launch(P, &provisioned, false, &user, &work);
        assert_eq!(w.len(), 2, "{w:#?}");
        assert!(w.iter().any(|t| t.contains("rev.md") && t.contains("under this run they")), "{w:#?}");
        assert!(w.iter().any(|t| t.contains("denies provider") && t.contains("this run will not use")), "{w:#?}");
        // The run's own config dir: nothing above it.
        assert!(at_launch(P, &provisioned, false, &work.join(".opencode"), &work).is_empty());
        // A config the container never loads is named.
        let w = at_launch(P, &home.join("elsewhere/opencode.json"), false, &work.join(".opencode"), &work);
        assert!(w.len() == 1 && w[0].contains("does not load the provisioned config"), "{w:#?}");
    }

    /// `ssai run` judges its launch with the config dir it sets for the client
    /// (over this process's own), from the directory it starts in — a global
    /// client's started outside home included.
    #[test]
    fn a_run_here_judges_with_the_config_dir_it_sets() {
        let dir = scratch("here");
        let (user, work) = (dir.join("cfg"), dir.join("srv/p"));
        let provisioned = user.join("opencode.json");
        write(&provisioned, &provisioned_form());
        write(&dir.join("srv/opencode.json"), &json!({ "policies": [pol("deny", P)] }).to_string());
        let launch = crate::sandbox::OpencodeLaunch { provider: P.into(), config: provisioned.clone(), global: true };
        let env = [("OPENCODE_CONFIG_DIR".to_string(), user.display().to_string())];
        let w = at_launch_here(&launch, &env, &work);
        assert!(w.len() == 1 && w[0].contains("srv") && w[0].contains("denies provider"), "{w:#?}");
        // Started where that file is not loaded: nothing to say.
        assert!(at_launch_here(&launch, &env, &dir).is_empty());
    }

    /// A global provisioning's own file is the user's too: in the container,
    /// as on the host, a pin it still holds under the V1 `agent` key is named.
    #[test]
    fn the_container_judges_a_global_provisionings_own_pins() {
        let dir = scratch("container-global");
        let (home, work) = (dir.join("home"), dir.join("ws"));
        let user = home.join(".config/opencode");
        let provisioned = user.join("opencode.json");
        let mut form: Value = serde_json::from_str(&provisioned_form()).unwrap();
        form["agent"] = json!({ "plan": { "model": "other/x" } });
        write(&provisioned, &form.to_string());
        std::fs::create_dir_all(&work).unwrap();
        let w = at_launch(P, &provisioned, true, &user, &work);
        assert!(w.len() == 1 && w[0].contains("agent(s) plan"), "{w:#?}");
        assert!(at_launch(P, &provisioned, false, &user, &work).is_empty());
    }

    /// A config too big to read is said to be unchecked, never called invalid.
    #[test]
    fn a_config_too_big_to_read_is_named_as_unchecked() {
        let dir = scratch("too-big");
        let (user, work) = (dir.join("u"), dir.join("ws"));
        let provisioned = work.join(".opencode/opencode.json");
        write(&provisioned, &provisioned_form());
        write(&user.join("opencode.json"), &format!("{{\"x\": \"{}\"}}", "a".repeat(MAX_CONFIG_BYTES as usize)));
        let w = at_launch(P, &provisioned, false, &user, &work);
        assert!(w.len() == 1 && w[0].contains("larger than 1 MiB") && !w[0].contains("not valid JSON"), "{w:#?}");
        write(&user.join("opencode.json"), "{ not json");
        assert!(at_launch(P, &provisioned, false, &user, &work)[0].contains("not valid JSON"));
    }

    /// A config the reader may not open is said to be unchecked, never called
    /// invalid. Root reads any file, so this holds only for another user (the
    /// macOS and Windows runs of these tests).
    #[cfg(unix)]
    #[test]
    fn a_config_that_cannot_be_read_is_named_as_unchecked() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let dir = scratch("unreadable");
        let (user, work) = (dir.join("u"), dir.join("ws"));
        let provisioned = work.join(".opencode/opencode.json");
        write(&provisioned, &provisioned_form());
        let config = user.join("opencode.json");
        write(&config, "{}");
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o000)).unwrap();
        let w = at_launch(P, &provisioned, false, &user, &work);
        assert!(w.len() == 1 && w[0].contains("cannot be read here") && !w[0].contains("not valid JSON"), "{w:#?}");
    }

    /// The agent writes the home init reads: a FIFO where a config goes is
    /// read as missing, never waited on.
    #[cfg(unix)]
    #[test]
    fn a_fifo_in_place_of_a_config_is_never_waited_on() {
        let dir = scratch("fifo");
        let fifo = dir.join("opencode.json");
        let c = std::ffi::CString::new(fifo.to_string_lossy().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert_eq!(read_config(&fifo, None), Err(()));
        assert_eq!(read_config(&fifo, Some("x")), Ok(json!({ "agents": { "x": {} } })));
        let big = dir.join("big.json");
        std::fs::write(&big, vec![b' '; MAX_CONFIG_BYTES as usize + 1]).unwrap();
        assert_eq!(read_config(&big, None), Err(()));
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
