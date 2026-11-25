//! Compose-based Dev Containers in the docker tier: a `devcontainer.json`
//! naming `dockerComposeFile` and `service`. Pure — the caller reads the files.
//!
//! The primary `service` is the sandbox container itself. Only it is read
//! here, through a closed table of its keys onto what an `image` / `build`
//! devcontainer gives ([`Primary`]): a key outside the table is refused, as
//! one that would widen what the container reaches on the host. The other
//! services run in the sandbox's own engine (`"docker": true`), started by
//! init from the project's own files ([`ComposeRun`]). Their definitions are
//! not vetted: the engine inside is their boundary, as for any
//! `docker compose` the agent runs itself. What would start the primary
//! inside that engine is refused ([`side_services`]).
//!
//! Variables (`${VAR}`, `${VAR:-default}`, …) are filled from the project's
//! `.env` and the defaults only — never from the developer's environment,
//! which would carry a token into a build that runs before any guard.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use streamscope_client_templates::sandbox_image;
use yaml_serde::{Mapping, Value};

use super::config::{in_project, ImageSource};

/// The largest compose or `.env` file read (a compose file is a few KB).
const FILE_CAP: usize = 1 << 20;

/// The compose project the side services run as, inside the sandbox's engine
/// (one engine per project: the name never meets another project's).
pub const PROJECT_NAME: &str = "ssai-devcontainer";

/// What init starts: the side services, from the project's own files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComposeRun {
    /// The compose files on the host, in order (a later one overrides).
    pub files: Vec<PathBuf>,
    /// The compose project directory on the host: the first file's, against
    /// which every relative path of every file resolves.
    pub project_dir: PathBuf,
    /// The primary service: the sandbox container.
    pub service: String,
    /// The services init starts, in the order named (compose starts their
    /// dependencies with them).
    pub side: Vec<String>,
    /// The side service the primary shares a network with
    /// (`network_mode: service:<x>`), run on the sandbox's own network.
    pub host_mode: Option<String>,
    /// Every other service of the files that may name the primary: none with
    /// a `network_mode` of its own, which takes no host entry.
    pub callers: Vec<String>,
    /// Every service of the files but the primary: the names the agent
    /// reaches directly, never through the proxy.
    pub names: Vec<String>,
    /// The services the primary waits on to finish
    /// (`condition: service_completed_successfully`): ready only once exited 0.
    pub must_exit: Vec<String>,
}

/// The primary service as the sandbox reads it.
#[derive(Debug, Clone, PartialEq)]
pub struct Primary {
    pub source: ImageSource,
    /// `user`: the container's user (a `remoteUser` / `containerUser` wins).
    pub user: Option<String>,
    /// `env_file` then `environment`: the container's variables, a later
    /// entry winning.
    pub env: Vec<(String, String)>,
    /// One line per key read but not applied.
    pub notes: Vec<String>,
}

/// The primary's keys the sandbox applies.
const READ_KEYS: &[&str] = &["image", "build", "user", "environment", "env_file", "volumes", "network_mode", "depends_on"];

/// The primary's keys read but not applied, and what the user is told.
const IGNORED_KEYS: &[(&str, &str)] = &[
    ("command", "is not applied: the sandbox starts the agent itself"),
    ("entrypoint", "is not applied: the sandbox starts the agent itself"),
    ("working_dir", "is not applied: the agent starts in the project"),
    ("container_name", "is not applied"),
    ("hostname", "is not applied"),
    ("domainname", "is not applied"),
    ("labels", "is not applied"),
    ("restart", "is not applied: the sandbox ends with the agent"),
    ("tty", "is not applied"),
    ("stdin_open", "is not applied"),
    ("init", "is not applied: the sandbox runs its own init"),
    ("healthcheck", "is not applied"),
    ("stop_signal", "is not applied"),
    ("stop_grace_period", "is not applied"),
    ("logging", "is not applied"),
    ("pull_policy", "is not applied"),
    ("links", "is not applied: the side services are reached by name"),
    ("networks", "is not applied: the sandbox has no network of its own"),
    ("expose", "is not applied: the sandbox publishes no port"),
    ("ports", "is not applied: the sandbox publishes no port"),
    ("cap_add", "is not applied: the sandbox's container already has what an engine inside needs"),
    ("cap_drop", "is not applied"),
    ("security_opt", "is not applied: the sandbox sets the container's security options"),
    ("privileged", "is not applied: the sandbox's container is already privileged for its engine"),
    ("mem_limit", "is not applied: `memory` in sandbox.json sets the limit"),
    ("memswap_limit", "is not applied: `memory` in sandbox.json sets the limit"),
    ("cpus", "is not applied: `cpus` in sandbox.json sets the limit"),
    ("shm_size", "is not applied"),
    ("deploy", "is not applied"),
    ("profiles", "is not applied: the sandbox runs the service whatever its profiles"),
    ("tmpfs", "is not applied"),
    ("group_add", "is not applied: the agent has the groups its image gives it"),
];

/// The primary's keys refused by name, and why. Any key in neither table is
/// refused too.
const REFUSED_KEYS: &[(&str, &str)] = &[
    ("extends", "it reads the service from elsewhere — write it out in the compose file"),
    ("devices", "it passes host devices into the container"),
    ("pid", "it shares a process namespace"),
    ("ipc", "it shares an IPC namespace"),
    ("userns_mode", "the sandbox sets the user namespace"),
    ("cgroup_parent", "the sandbox sets the cgroup"),
    ("cgroup", "the sandbox sets the cgroup"),
    ("sysctls", "the sandbox sets the container's kernel parameters"),
    ("ulimits", "the sandbox sets the container's limits"),
    ("extra_hosts", "the sandbox resolves names itself"),
    ("dns", "the sandbox resolves names itself"),
    ("dns_search", "the sandbox resolves names itself"),
    ("dns_opt", "the sandbox resolves names itself"),
    ("secrets", "it mounts host files into the container"),
    ("configs", "it mounts host files into the container"),
    ("volumes_from", "it mounts another container's volumes"),
    ("platform", "the sandbox runs the host's platform"),
    ("runtime", "the sandbox picks the runtime"),
    ("gpus", "it passes host devices into the container"),
];

/// `build` keys applied, ignored (with a note) and refused (any other).
const BUILD_READ: &[&str] = &["context", "dockerfile", "target", "args"];
const BUILD_IGNORED: &[&str] = &["cache_from", "cache_to", "labels", "tags", "pull", "no_cache", "shm_size", "isolation"];

/// Files under a home folder the sandbox never hands the agent: a bind of one
/// is a convenience of the developer's machine, left out with a note.
const HOME_CONVENIENCES: &[(&str, &str)] = &[
    (".ssh", "the sandbox hands the agent no SSH key of yours"),
    (".gitconfig", "the sandbox hands the agent none of your git configuration"),
    (".aws", "the sandbox hands the agent no cloud credential of yours"),
];

/// Read the compose Dev Container `dc` (its parsed body `obj`) of the project
/// at `root`, mounted in the container at `workspace`.
pub fn read(
    root: &Path,
    dc: &Path,
    obj: &serde_json::Map<String, serde_json::Value>,
    workspace: &str,
    read: &dyn Fn(&Path) -> Result<String>,
) -> Result<(ComposeRun, Primary)> {
    let shown = dc.display();
    let dir = dc.parent().unwrap_or(Path::new("."));
    let rels: Vec<String> = match obj.get("dockerComposeFile") {
        Some(serde_json::Value::String(s)) => vec![s.clone()],
        Some(serde_json::Value::Array(a)) if !a.is_empty() && a.iter().all(serde_json::Value::is_string) => {
            a.iter().filter_map(serde_json::Value::as_str).map(str::to_string).collect()
        }
        _ => bail!("{shown}: `dockerComposeFile` must be a path or a non-empty array of paths"),
    };
    let service = match obj.get("service") {
        Some(serde_json::Value::String(s)) if !s.trim().is_empty() => s.trim().to_string(),
        _ => bail!("{shown}: `dockerComposeFile` needs `service`, the service the agent runs in"),
    };
    let run_services: Option<Vec<String>> = match obj.get("runServices") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::Array(a)) if a.iter().all(serde_json::Value::is_string) => {
            Some(a.iter().filter_map(serde_json::Value::as_str).map(str::to_string).collect())
        }
        Some(_) => bail!("{shown}: `runServices` must be an array of service names"),
    };
    let mut files = Vec::new();
    for rel in &rels {
        if rel.contains("${") {
            bail!("{shown}: `dockerComposeFile` may not hold a `${{…}}` variable");
        }
        files.push(in_project(root, dir, rel, "dockerComposeFile")?);
    }
    let project_dir = files[0].parent().unwrap_or(root).to_path_buf();
    let mut docs = Vec::new();
    for f in &files {
        let text = read(f).with_context(|| format!("read {}", f.display()))?;
        docs.push((f.clone(), parse(f, &text)?));
    }
    let vars = dotenv(&project_dir.join(".env"), read)?;
    let defs = definitions(&docs)?;
    let Some(primary_defs) = defs.get(&service) else {
        bail!("{shown}: `service` {service:?} is not a service of {}", rels.join(", "));
    };
    let merged = merge_primary(&service, primary_defs)?;
    let ctx = Ctx { root, project_dir: &project_dir, workspace, vars: &vars, read };
    let mut primary = primary(&service, &merged, &ctx)?;
    if let Some(action) = obj.get("shutdownAction").and_then(serde_json::Value::as_str)
        && action != "stopCompose"
    {
        primary.notes.push(format!("{shown}: `shutdownAction` {action:?} is not applied: the side services stop with the sandbox"));
    }
    let host_mode = network_target(&service, &merged, &ctx)?;
    let side = side_services(&service, &defs, run_services.as_deref(), host_mode.as_deref())?;
    let callers = defs
        .iter()
        .filter(|(name, d)| {
            **name != service
                && host_mode.as_deref() != Some(name.as_str())
                // One that `extends` another may inherit a `network_mode`; one
                // on another's network (or none, or the host's) takes no host
                // entry. `bridge` and `default` are an engine network like any.
                && !d.iter().any(|m| {
                    m.contains_key("extends")
                        || m.get("network_mode").is_some_and(|v| !matches!(v.as_str(), Some("bridge" | "default")))
                })
        })
        .map(|(name, _)| name.clone())
        .collect();
    // Only a name DNS asks as it is written is a service's: a dotted one
    // (`deb.debian.org`) would take a real host's name from the agent.
    let names = defs.keys().filter(|n| **n != service && local_name(n)).cloned().collect();
    let must_exit = primary_dependencies(primary_defs)
        .into_iter()
        .filter(|(n, (finish, _))| *finish && defs.contains_key(n))
        .map(|(n, _)| n)
        .collect();
    Ok((ComposeRun { files, project_dir, service, side, host_mode, callers, names, must_exit }, primary))
}

/// One compose file, its `<<:` merge keys applied. A file whose top level
/// `include`s another is refused: the services it brings in would not be
/// seen here.
fn parse(file: &Path, text: &str) -> Result<Value> {
    if text.len() > FILE_CAP {
        bail!("{} is larger than any compose file the sandbox reads ({} bytes)", file.display(), FILE_CAP);
    }
    let mut doc: Value = yaml_serde::from_str(text).with_context(|| format!("parse {}", file.display()))?;
    if doc.is_null() {
        doc = Value::Mapping(Mapping::new());
    }
    doc.apply_merge().with_context(|| format!("{}: a `<<:` merge", file.display()))?;
    let top = doc.as_mapping().with_context(|| format!("{}: not a mapping", file.display()))?;
    if top.contains_key("include") {
        bail!("{}: `include` is refused by the docker sandbox — list the files in `dockerComposeFile`", file.display());
    }
    match top.get("services") {
        None | Some(Value::Null) | Some(Value::Mapping(_)) => Ok(doc),
        Some(_) => bail!("{}: `services` must be a mapping", file.display()),
    }
}

/// Every service's definitions, one per file that has it, in file order.
fn definitions(docs: &[(PathBuf, Value)]) -> Result<BTreeMap<String, Vec<Mapping>>> {
    let mut out: BTreeMap<String, Vec<Mapping>> = BTreeMap::new();
    for (file, doc) in docs {
        let Some(Value::Mapping(services)) = doc.get("services") else { continue };
        for (name, def) in services {
            let name = name.as_str().with_context(|| format!("{}: a service name must be a string", file.display()))?;
            let def = match def {
                Value::Mapping(m) => m.clone(),
                Value::Null => Mapping::new(),
                _ => bail!("{}: service `{name}` must be a mapping", file.display()),
            };
            out.entry(name.to_string()).or_default().push(def);
        }
    }
    Ok(out)
}

/// The primary's definitions merged as compose merges them, for the keys the
/// sandbox applies: a scalar replaced, `environment`, `build` (and its
/// `args`) by key, `volumes` by target, `env_file` appended. Another key keeps
/// the last file's value.
fn merge_primary(service: &str, defs: &[Mapping]) -> Result<Mapping> {
    let mut out = Mapping::new();
    for def in defs {
        for (key, value) in def {
            let k = key.as_str().with_context(|| format!("service `{service}`: a key must be a string"))?;
            if READ_KEYS.contains(&k) && matches!(value, Value::Tagged(_)) {
                bail!("service `{service}`: `{k}` carries a YAML tag (`!reset`, `!override`), which the docker sandbox does not read");
            }
            let merged = match (k, out.get(k)) {
                ("environment", Some(old)) => Value::Mapping(merge_maps(&env_map(old, k)?, &env_map(value, k)?)),
                ("build", Some(old)) => Value::Mapping(merge_build(&build_map(old)?, &build_map(value)?)?),
                ("volumes", Some(old)) => Value::Sequence(merge_volumes(old, value)?),
                ("env_file", Some(old)) => Value::Sequence([seq_of(old), seq_of(value)].concat()),
                _ => value.clone(),
            };
            out.insert(Value::String(k.to_string()), merged);
        }
    }
    Ok(out)
}

fn merge_maps(old: &Mapping, new: &Mapping) -> Mapping {
    let mut out = old.clone();
    for (k, v) in new {
        out.insert(k.clone(), v.clone());
    }
    out
}

fn seq_of(v: &Value) -> Vec<Value> {
    match v {
        Value::Sequence(s) => s.clone(),
        Value::Null => Vec::new(),
        other => vec![other.clone()],
    }
}

/// `environment` or `args`, a list (`K=V`, `K`) or a mapping, as a mapping
/// (`K` alone: `null`, a value taken from the environment).
fn env_map(v: &Value, key: &str) -> Result<Mapping> {
    match v {
        Value::Mapping(m) => Ok(m.clone()),
        Value::Null => Ok(Mapping::new()),
        Value::Sequence(items) => {
            let mut out = Mapping::new();
            for item in items {
                let s = item.as_str().with_context(|| format!("`{key}` entries must be strings"))?;
                match s.split_once('=') {
                    Some((k, v)) => out.insert(Value::String(k.to_string()), Value::String(v.to_string())),
                    None => out.insert(Value::String(s.to_string()), Value::Null),
                };
            }
            Ok(out)
        }
        _ => bail!("`{key}` must be a list or a mapping"),
    }
}

fn build_map(v: &Value) -> Result<Mapping> {
    match v {
        Value::String(s) => {
            let mut m = Mapping::new();
            m.insert(Value::String("context".into()), Value::String(s.clone()));
            Ok(m)
        }
        Value::Mapping(m) => Ok(m.clone()),
        _ => bail!("`build` must be a path or a mapping"),
    }
}

fn merge_build(old: &Mapping, new: &Mapping) -> Result<Mapping> {
    let mut out = old.clone();
    for (k, v) in new {
        let merged = match (k.as_str(), old.get(k)) {
            (Some("args"), Some(o)) => Value::Mapping(merge_maps(&env_map(o, "build.args")?, &env_map(v, "build.args")?)),
            _ => v.clone(),
        };
        out.insert(k.clone(), merged);
    }
    Ok(out)
}

/// `volumes` merged by target: a later file's entry for a target replaces
/// the earlier one in its place.
fn merge_volumes(old: &Value, new: &Value) -> Result<Vec<Value>> {
    let mut out: Vec<(Option<String>, Value)> = Vec::new();
    for v in seq_of(old).into_iter().chain(seq_of(new)) {
        let target = volume(&v)?.target;
        match out.iter_mut().find(|(t, _)| t.is_some() && *t == target) {
            Some(slot) => slot.1 = v,
            None => out.push((target, v)),
        }
    }
    Ok(out.into_iter().map(|(_, v)| v).collect())
}

/// One `volumes` entry, short (`src:target[:mode]`, `target`) or long form.
#[derive(Debug, Clone, PartialEq)]
struct Volume {
    kind: VolumeKind,
    source: Option<String>,
    target: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum VolumeKind {
    Bind,
    Named,
    Anonymous,
    Other,
}

fn volume(v: &Value) -> Result<Volume> {
    match v {
        Value::String(s) => {
            let parts = split_volume(s);
            let (source, target) = match parts.as_slice() {
                [target] => (None, Some(target.clone())),
                [source, target, ..] => (Some(source.clone()), Some(target.clone())),
                [] => bail!("an empty `volumes` entry"),
            };
            let kind = match &source {
                None => VolumeKind::Anonymous,
                Some(s) if s.starts_with(['/', '.', '~', '$']) => VolumeKind::Bind,
                Some(_) => VolumeKind::Named,
            };
            Ok(Volume { kind, source, target })
        }
        Value::Mapping(m) => {
            let text = |k: &str| m.get(k).and_then(Value::as_str).map(str::to_string);
            let kind = match text("type").as_deref() {
                Some("bind") => VolumeKind::Bind,
                Some("volume") if text("source").is_some() => VolumeKind::Named,
                Some("volume") => VolumeKind::Anonymous,
                _ => VolumeKind::Other,
            };
            Ok(Volume { kind, source: text("source"), target: text("target") })
        }
        _ => bail!("a `volumes` entry must be a string or a mapping"),
    }
}

/// A short-form volume split at its `:`s, none inside a `${…}`.
fn split_volume(s: &str) -> Vec<String> {
    let (mut out, mut cur, mut depth) = (Vec::new(), String::new(), 0usize);
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '$' if chars.peek() == Some(&'{') => {
                depth += 1;
                cur.push(c);
                cur.push(chars.next().unwrap_or('{'));
            }
            '}' if depth > 0 => {
                depth -= 1;
                cur.push(c);
            }
            ':' if depth == 0 => out.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out
}

/// What reading the primary needs beside its definition.
struct Ctx<'a> {
    root: &'a Path,
    project_dir: &'a Path,
    workspace: &'a str,
    vars: &'a BTreeMap<String, String>,
    read: &'a dyn Fn(&Path) -> Result<String>,
}

impl Ctx<'_> {
    /// `text` with its variables filled from `.env` (`key` names it in an
    /// error). A result naming the developer's environment (`${localEnv:…}`,
    /// `${env:…}`) is refused: the Dev Container CLI, which builds an image
    /// with `features`, would expand it from this machine.
    fn fill(&self, text: &str, key: &str) -> Result<String> {
        let filled = interpolate(text, &|n| self.vars.get(n).cloned()).map_err(|e| e.context(key.to_string()))?;
        if super::config::names_local_env(&filled) {
            bail!("{key}: {filled:?} names your environment (`${{localEnv:…}}`), which the docker sandbox never reads");
        }
        Ok(filled)
    }
}

fn primary(service: &str, def: &Mapping, ctx: &Ctx) -> Result<Primary> {
    let shown = format!("service `{service}`");
    let mut notes = Vec::new();
    for key in def.keys().filter_map(Value::as_str) {
        if READ_KEYS.contains(&key) || key.starts_with("x-") {
            continue;
        }
        if let Some((_, what)) = IGNORED_KEYS.iter().find(|(k, _)| *k == key) {
            notes.push(format!("{shown}: `{key}` {what}"));
        } else if let Some((_, why)) = REFUSED_KEYS.iter().find(|(k, _)| *k == key) {
            bail!("{shown}: `{key}` is refused by the docker sandbox — {why}");
        } else {
            bail!("{shown}: `{key}` is not a key the docker sandbox knows — it is refused, since it may widen what the container reaches");
        }
    }
    let text = |key: &str| -> Result<Option<String>> {
        match def.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) if !s.trim().is_empty() => Ok(Some(ctx.fill(s.trim(), &format!("{shown}: `{key}`"))?)),
            Some(Value::Number(n)) => Ok(Some(n.to_string())),
            Some(_) => bail!("{shown}: `{key}` must be a non-empty string"),
        }
    };
    let source = match (text("image")?, def.get("build")) {
        (_, Some(build)) => build_source(build, ctx, &mut notes).with_context(|| format!("{shown}: `build`"))?,
        (Some(image), None) if sandbox_image::image_reference(&image) => ImageSource::Image(docker_reference(&image)),
        (Some(image), None) => bail!("{shown}: `image` must be an image reference, got {image:?}"),
        (None, None) => bail!("{shown}: set `image` or `build`"),
    };
    let user = text("user")?;
    let mut env = Vec::new();
    for entry in def.get("env_file").map(seq_of).unwrap_or_default() {
        let (path, required) = match &entry {
            Value::String(s) => (s.clone(), true),
            Value::Mapping(m) => (
                m.get("path").and_then(Value::as_str).context("an `env_file` entry needs `path`")?.to_string(),
                m.get("required").and_then(Value::as_bool).unwrap_or(true),
            ),
            _ => bail!("{shown}: an `env_file` entry must be a path or a mapping"),
        };
        let path = in_project(ctx.root, ctx.project_dir, &ctx.fill(&path, &format!("{shown}: `env_file`"))?, "env_file")?;
        match read_optional(&path, ctx.read)? {
            Some(text) => env.extend(parse_dotenv(&text)),
            None if required => bail!("{shown}: its `env_file` {} does not exist", path.display()),
            None => {}
        }
    }
    if let Some(v) = def.get("environment") {
        for (k, v) in env_map(v, "environment").with_context(|| shown.clone())? {
            let k = k.as_str().with_context(|| format!("{shown}: an `environment` name must be a string"))?.to_string();
            if k.is_empty() || k.contains(['=', '\0']) {
                bail!("{shown}: `environment` names a variable {k:?}, which no environment can hold");
            }
            let value = match &v {
                Value::Null => {
                    notes.push(format!("{shown}: `environment.{k}` takes its value from your environment, which the sandbox never reads — not set"));
                    continue;
                }
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                Value::Bool(b) => b.to_string(),
                _ => bail!("{shown}: `environment.{k}` must be a string"),
            };
            match interpolate(&value, &|n| ctx.vars.get(n).cloned()) {
                Ok(v) if v.contains('\0') => bail!("{shown}: `environment.{k}` holds a NUL character"),
                Ok(v) => env.push((k, v)),
                Err(e) if e.downcast_ref::<Unset>().is_some() => notes.push(format!(
                    "{shown}: `environment.{k}` names {}, set neither in the project's .env nor by a default — the sandbox never reads your environment: not set",
                    e.downcast_ref::<Unset>().map(|u| format!("${{{}}}", u.0)).unwrap_or_default()
                )),
                Err(e) => return Err(e.context(format!("{shown}: `environment.{k}`"))),
            }
        }
    }
    for v in def.get("volumes").map(seq_of).unwrap_or_default() {
        if let Some(note) = primary_volume(&shown, &v, ctx)? {
            notes.push(note);
        }
    }
    Ok(Primary { source, user, env, notes })
}

/// `build`, its paths confined to the project: the context against the
/// project directory, the Dockerfile against the context (as compose reads
/// them).
fn build_source(build: &Value, ctx: &Ctx, notes: &mut Vec<String>) -> Result<ImageSource> {
    let m = build_map(build)?;
    for key in m.keys().filter_map(Value::as_str) {
        if BUILD_IGNORED.contains(&key) {
            notes.push(format!("`build.{key}` is not applied"));
        } else if !BUILD_READ.contains(&key) {
            bail!("`{key}` is refused by the docker sandbox — the image is built from the project only, with no option of its own");
        }
    }
    let text = |key: &str| -> Result<Option<String>> {
        match m.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) if !s.trim().is_empty() => Ok(Some(ctx.fill(s.trim(), &format!("`{key}`"))?)),
            Some(_) => bail!("`{key}` must be a non-empty string"),
        }
    };
    let context = text("context")?.unwrap_or_else(|| ".".into());
    if context.contains("://") || context.starts_with("git@") {
        bail!("`context` {context:?} is not a folder of the project — the image is built from the project only");
    }
    let context = in_project(ctx.root, ctx.project_dir, &context, "context")?;
    let dockerfile = in_project(ctx.root, &context, &text("dockerfile")?.unwrap_or_else(|| "Dockerfile".into()), "dockerfile")?;
    let mut args = Vec::new();
    if let Some(v) = m.get("args") {
        for (k, v) in env_map(v, "build.args")? {
            let k = k.as_str().context("a `build.args` name must be a string")?.to_string();
            let value = match &v {
                Value::Null => {
                    notes.push(format!("`build.args.{k}` takes its value from your environment, which the sandbox never reads — not passed"));
                    continue;
                }
                Value::String(s) => ctx.fill(s, &format!("`args.{k}`"))?,
                Value::Number(n) => n.to_string(),
                Value::Bool(b) => b.to_string(),
                _ => bail!("`args.{k}` must be a string"),
            };
            args.push((k, value));
        }
    }
    Ok(ImageSource::Build { context, dockerfile, target: text("target")?, args })
}

/// One of the primary's `volumes`: the project's own bind (the workspace
/// mount, made by the sandbox), a home convenience or a named or anonymous
/// volume (a note), anything else refused.
fn primary_volume(shown: &str, v: &Value, ctx: &Ctx) -> Result<Option<String>> {
    let vol = volume(v).with_context(|| format!("{shown}: `volumes`"))?;
    let named = |what: &str| format!("{shown}: the {what} at {} is not kept: the sandbox keeps only the project and its own home", vol.target.as_deref().unwrap_or("?"));
    match vol.kind {
        VolumeKind::Named => return Ok(Some(named(&format!("volume `{}`", vol.source.as_deref().unwrap_or(""))))),
        VolumeKind::Anonymous => return Ok(Some(named("anonymous volume"))),
        VolumeKind::Other => bail!("{shown}: a `volumes` entry that is not a bind or a volume (tmpfs, a pipe) is refused by the docker sandbox"),
        VolumeKind::Bind => {}
    }
    let raw = vol.source.as_deref().context("a bind needs a source")?;
    if let Some(why) = home_convenience(raw) {
        return Ok(Some(format!("{shown}: the bind of {raw} is not mounted — {why}")));
    }
    if matches!(raw, "/var/run/docker.sock" | "/run/docker.sock") {
        return Ok(Some(format!("{shown}: the bind of {raw} is not mounted — the sandbox's own engine answers there")));
    }
    let filled = ctx.fill(raw, &format!("{shown}: `volumes`"))?;
    // A variable may fill a volume's name rather than a path: compose reads a
    // source as a path only when it starts as one.
    if !filled.starts_with(['/', '.', '~']) {
        return Ok(Some(named(&format!("volume `{filled}`"))));
    }
    let source = normalise(&ctx.project_dir.join(&filled));
    if !ctx.root.starts_with(&source) {
        bail!(
            "{shown}: the bind of {raw} is refused by the docker sandbox — of your machine it mounts only the project, \
             at the devcontainer's `workspaceFolder` (a folder inside the project is there already, under it)"
        );
    }
    // The project's own bind (or an ancestor's): the sandbox mounts the
    // project itself, alone, at `workspaceFolder`.
    let target = ctx.fill(vol.target.as_deref().context("a bind needs a target")?, &format!("{shown}: `volumes`"))?;
    let lands = Path::new(&target).join(ctx.root.strip_prefix(&source).unwrap_or(Path::new("")));
    let lands = normalise(&lands);
    if source != ctx.root && lands != Path::new(ctx.workspace) {
        bail!(
            "{shown}: the bind of {raw} is refused by the docker sandbox — a folder around the project is read as the \
             project's own mount only when it puts the project at the `workspaceFolder` {}, and it puts it at {}",
            ctx.workspace,
            lands.display()
        );
    }
    if source != ctx.root {
        return Ok(Some(format!(
            "{shown}: the bind of {raw} mounts only the project, at {} — the folders beside it are not in the sandbox",
            ctx.workspace
        )));
    }
    if lands != Path::new(ctx.workspace) {
        return Ok(Some(format!("{shown}: the project is mounted at the `workspaceFolder` {}, not at {}", ctx.workspace, lands.display())));
    }
    Ok(None)
}

/// Why a bind of `raw` (as written) is a home convenience the sandbox leaves
/// out: under `~`, `$HOME`, `${HOME}` or a home folder spelled out
/// (`/home/<user>`, `/Users/<user>`, `/root`).
fn home_convenience(raw: &str) -> Option<&'static str> {
    let rest = ["~/", "$HOME/", "${HOME}/"]
        .iter()
        .find_map(|p| raw.strip_prefix(p).map(str::to_string))
        .or_else(|| {
            let comps: Vec<&str> = raw.split('/').filter(|c| !c.is_empty()).collect();
            match comps.as_slice() {
                ["home" | "Users", _user, rest @ ..] if raw.starts_with('/') => Some(rest.join("/")),
                ["root", rest @ ..] if raw.starts_with('/') => Some(rest.join("/")),
                _ => None,
            }
        })?;
    let first = rest.split('/').find(|c| !c.is_empty())?;
    HOME_CONVENIENCES.iter().find(|(name, _)| *name == first).map(|(_, why)| *why)
}

/// The primary's `network_mode`: `service:<x>` names the side service run on
/// the sandbox's own network; the bridge default is the sandbox's anyway;
/// anything else is refused.
fn network_target(service: &str, def: &Mapping, ctx: &Ctx) -> Result<Option<String>> {
    let Some(v) = def.get("network_mode") else { return Ok(None) };
    let mode = ctx.fill(v.as_str().context("`network_mode` must be a string")?, "`network_mode`")?;
    match mode.strip_prefix("service:") {
        Some(x) if !x.is_empty() && x != service => Ok(Some(x.to_string())),
        Some(_) => bail!("service `{service}`: `network_mode` {mode:?} must name another service"),
        None if mode == "bridge" || mode == "default" => Ok(None),
        None => bail!("service `{service}`: `network_mode` {mode:?} is refused by the docker sandbox — only `service:<name>` is read"),
    }
}

/// What the primary's `depends_on` names, the last file's entry for each
/// name winning: the name, whether it must have finished
/// (`condition: service_completed_successfully`), and whether it is required
/// (`required: false`: compose skips it when no file defines it).
fn primary_dependencies(defs: &[Mapping]) -> BTreeMap<String, (bool, bool)> {
    let mut out = BTreeMap::new();
    for def in defs {
        match def.get("depends_on") {
            Some(Value::Mapping(m)) => {
                for (k, v) in m {
                    if let Some(k) = k.as_str() {
                        let finish = v.get("condition").and_then(Value::as_str) == Some("service_completed_successfully");
                        let required = v.get("required").and_then(Value::as_bool).unwrap_or(true);
                        out.insert(k.to_string(), (finish, required));
                    }
                }
            }
            Some(Value::Sequence(items)) => {
                for k in items.iter().filter_map(Value::as_str) {
                    out.insert(k.to_string(), (false, true));
                }
            }
            _ => {}
        }
    }
    out
}

/// The services init starts: `runServices`, or every service without a
/// `profiles` key; with what the primary depends on and the service it shares
/// a network with, which may not declare networks of its own. Whether
/// starting them would start the primary inside the engine is decided by
/// compose itself, inside, from the files as it resolves them
/// ([`starting_the_primary`]).
fn side_services(
    service: &str,
    defs: &BTreeMap<String, Vec<Mapping>>,
    run_services: Option<&[String]>,
    host_mode: Option<&str>,
) -> Result<Vec<String>> {
    let has = |name: &str, key: &str| defs.get(name).into_iter().flatten().any(|d| d.contains_key(key));
    let mut side: Vec<String> = match run_services {
        Some(list) => {
            for n in list {
                if !defs.contains_key(n) {
                    bail!("`runServices` names {n:?}, which is not a service of the compose files");
                }
            }
            list.iter().filter(|n| *n != service).cloned().collect()
        }
        // A service with profiles starts only when one is on; an empty list
        // is no profile at all, as compose reads it (the last file's wins).
        None => defs
            .iter()
            .filter(|(n, d)| {
                *n != service && !d.iter().rev().find_map(|m| m.get("profiles")).is_some_and(|p| p.as_sequence().is_some_and(|s| !s.is_empty()))
            })
            .map(|(n, _)| n.clone())
            .collect(),
    };
    // An optional dependency no file defines is skipped, as compose skips it.
    let mut wanted: Vec<String> = primary_dependencies(defs.get(service).map(Vec::as_slice).unwrap_or_default())
        .into_iter()
        .filter(|(n, (_, required))| n != service && (*required || defs.contains_key(n)))
        .map(|(n, _)| n)
        .collect();
    wanted.extend(host_mode.map(str::to_string));
    for n in wanted {
        if !defs.contains_key(&n) {
            bail!("service `{service}` names {n:?}, which is not a service of the compose files");
        }
        if !side.contains(&n) {
            side.push(n);
        }
    }
    if let Some(x) = host_mode
        && (has(x, "networks") || has(x, "network_mode") || has(x, "links"))
    {
        bail!(
            "service `{x}` shares its network with `{service}` (`network_mode: service:{x}`): the sandbox runs it on its own \
             network, so it may not set `networks`, `network_mode` or `links` itself"
        );
    }
    Ok(side)
}

/// Whether starting the side services would start `primary` inside the
/// engine, read from what compose resolved for them (`config --format json
/// <side services>`: they and everything compose starts with them — every
/// variable filled, every `extends` and tag applied, `links`, `volumes_from`
/// and `service:` namespaces written as `depends_on`). `Some`: the service
/// naming it, or the primary itself when compose lists it. An answer of
/// another shape is an error: it says nothing about what would start.
pub fn starting_the_primary(config: &serde_json::Value, primary: &str) -> Result<Option<String>> {
    let services = config
        .get("services")
        .and_then(|s| s.as_object())
        .context("compose's resolution of the services has no `services` map")?;
    // Read both ways: a service naming the primary, and the primary listed.
    let naming = services.iter().find(|(name, s)| {
        *name != primary && s.get("depends_on").and_then(|d| d.as_object()).is_some_and(|d| d.contains_key(primary))
    });
    if let Some((name, _)) = naming {
        return Ok(Some(name.clone()));
    }
    Ok(services.contains_key(primary).then(|| primary.to_string()))
}

/// A variable no source sets, and no default covers.
#[derive(Debug)]
pub struct Unset(pub String);

impl std::fmt::Display for Unset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "`${{{}}}` is set neither in the project's .env nor by a default — the docker sandbox never reads your environment for the compose files",
            self.0
        )
    }
}

impl std::error::Error for Unset {}

/// `text` with compose's variables filled from `lookup`: `$$`, `$VAR`,
/// `${VAR}`, and `${VAR:-d}` / `${VAR-d}` / `${VAR:?e}` / `${VAR?e}` /
/// `${VAR:+r}` / `${VAR+r}` (a word itself filled, when used). A variable
/// unset with no default is an [`Unset`] error.
pub fn interpolate(text: &str, lookup: &dyn Fn(&str) -> Option<String>) -> Result<String> {
    interpolate_at(text, lookup, 0)
}

/// How deep defaults may nest (`${A:-${B:-…}}`): the text is the agent's to
/// write, and each level is a call.
const MAX_NESTING: usize = 16;

fn interpolate_at(text: &str, lookup: &dyn Fn(&str) -> Option<String>, depth: usize) -> Result<String> {
    if depth > MAX_NESTING {
        bail!("a variable's default nests more than {MAX_NESTING} deep");
    }
    let b = text.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    let name_end = |from: usize| {
        let mut j = from;
        while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_') && !(j == from && b[j].is_ascii_digit()) {
            j += 1;
        }
        j
    };
    while i < b.len() {
        if b[i] != b'$' {
            let next = text[i..].find('$').map_or(b.len(), |n| i + n);
            out.push_str(&text[i..next]);
            i = next;
            continue;
        }
        match b.get(i + 1) {
            Some(b'$') => {
                out.push('$');
                i += 2;
            }
            Some(b'{') => {
                let mut open = 1;
                let mut j = i + 2;
                while j < b.len() && open > 0 {
                    match b[j] {
                        b'{' if b[j - 1] == b'$' => open += 1,
                        b'}' => open -= 1,
                        _ => {}
                    }
                    j += 1;
                }
                if open > 0 {
                    bail!("{text:?}: an unclosed `${{`");
                }
                let body = &text[i + 2..j - 1];
                out.push_str(&braced(body, text, lookup, depth)?);
                i = j;
            }
            Some(_) if name_end(i + 1) > i + 1 => {
                let end = name_end(i + 1);
                let name = &text[i + 1..end];
                out.push_str(&lookup(name).ok_or_else(|| anyhow::Error::new(Unset(name.to_string())))?);
                i = end;
            }
            _ => {
                out.push('$');
                i += 1;
            }
        }
    }
    Ok(out)
}

/// The inside of one `${…}`.
fn braced(body: &str, text: &str, lookup: &dyn Fn(&str) -> Option<String>, depth: usize) -> Result<String> {
    let end = body.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).unwrap_or(body.len());
    let (name, rest) = body.split_at(end);
    if name.is_empty() || name.starts_with(|c: char| c.is_ascii_digit()) {
        bail!("{text:?}: `${{{body}}}` is not a variable");
    }
    let value = lookup(name);
    let set_nonempty = value.as_deref().is_some_and(|v| !v.is_empty());
    let unset = || anyhow::Error::new(Unset(name.to_string()));
    let word = |w: &str| interpolate_at(w, lookup, depth + 1);
    Ok(match rest {
        "" => value.ok_or_else(unset)?,
        r if r.starts_with(":-") => if set_nonempty { value.unwrap_or_default() } else { word(&r[2..])? },
        r if r.starts_with(":?") => match value {
            Some(v) if !v.is_empty() => v,
            _ => bail!("{text:?}: `${{{name}}}` is required: {}", &r[2..]),
        },
        r if r.starts_with(":+") => if set_nonempty { word(&r[2..])? } else { String::new() },
        r if r.starts_with('-') => match value {
            Some(v) => v,
            None => word(&r[1..])?,
        },
        r if r.starts_with('?') => value.with_context(|| format!("{text:?}: `${{{name}}}` is required: {}", &r[1..]))?,
        r if r.starts_with('+') => if value.is_some() { word(&r[1..])? } else { String::new() },
        _ => bail!("{text:?}: `${{{body}}}` is not a form compose reads"),
    })
}

/// `path`'s text, `None` when it does not exist.
fn read_optional(path: &Path, read: &dyn Fn(&Path) -> Result<String>) -> Result<Option<String>> {
    match read(path) {
        Ok(text) if text.len() > FILE_CAP => bail!("{} is larger than the sandbox reads ({FILE_CAP} bytes)", path.display()),
        Ok(text) => Ok(Some(text)),
        Err(e) if e.downcast_ref::<std::io::Error>().is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) => Ok(None),
        Err(e) => Err(e.context(format!("read {}", path.display()))),
    }
}

/// The project's `.env`, as compose reads it for its variables (none when
/// there is no file).
fn dotenv(path: &Path, read: &dyn Fn(&Path) -> Result<String>) -> Result<BTreeMap<String, String>> {
    Ok(read_optional(path, read)?.map(|t| parse_dotenv(&t).into_iter().collect()).unwrap_or_default())
}

/// `KEY=VALUE` lines: `#` comments, an `export ` prefix, a value in single
/// quotes (as written), double quotes (`\n`, `\"`, `\\` escaped) or bare (up
/// to a ` #` comment, trimmed). As compose reads it, a bare or double-quoted
/// value's variables are filled from the entries above it (an unset one
/// empty); a value whose variables do not read stays as written.
pub fn parse_dotenv(text: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        let line = line.strip_prefix("export ").map_or(line, str::trim_start);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else { continue };
        let k = k.trim();
        if k.is_empty() || k.contains(char::is_whitespace) || k.contains('\0') {
            continue;
        }
        let v = v.trim_start();
        let earlier = |n: &str| Some(out.iter().rev().find(|(k, _)| k == n).map(|(_, v)| v.clone()).unwrap_or_default());
        let fill = |raw: String| interpolate(&raw, &earlier).unwrap_or(raw);
        let value = if let Some(rest) = v.strip_prefix('\'') {
            rest.split_once('\'').map_or(rest, |(inner, _)| inner).to_string()
        } else if let Some(rest) = v.strip_prefix('"') {
            let mut s = String::new();
            let mut chars = rest.chars();
            while let Some(c) = chars.next() {
                match c {
                    '"' => break,
                    '\\' => match chars.next() {
                        Some('n') => s.push('\n'),
                        Some(other) => s.push(other),
                        None => break,
                    },
                    c => s.push(c),
                }
            }
            fill(s)
        } else {
            fill(v.split_once(" #").map_or(v, |(before, _)| before).trim_end().to_string())
        };
        if !value.contains('\0') {
            out.push((k.to_string(), value));
        }
    }
    out
}

/// `image` as Docker reads a compose file's reference, fully qualified for
/// podman (which reads a short name only with a search list, or a terminal to
/// ask): no registry host is Docker Hub, and one name alone is its `library/`.
fn docker_reference(image: &str) -> String {
    let image = image.strip_prefix("docker://").unwrap_or(image);
    let first = image.split('/').next().unwrap_or_default();
    let has_registry = image.contains('/') && (first.contains(['.', ':']) || first == "localhost");
    match (has_registry, image.contains('/')) {
        (true, _) => image.to_string(),
        (false, true) => format!("docker.io/{image}"),
        (false, false) => format!("docker.io/library/{image}"),
    }
}

/// Whether `name` is one the sandbox answers for a compose service: a single
/// label of letters, digits, `-` and `_` (DNS asks it as written, with no
/// search domain; it goes into `NO_PROXY` and /etc/hosts as it is), never
/// `localhost`.
pub fn local_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        && !name.eq_ignore_ascii_case("localhost")
}

/// `path` with `.` and `..` resolved on the text.
fn normalise(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other),
        }
    }
    out
}

impl ComposeRun {
    /// The container's path of a host path inside the project.
    fn in_container(root: &Path, workspace: &str, host: &Path) -> String {
        match host.strip_prefix(root) {
            Ok(rest) if rest.as_os_str().is_empty() => workspace.to_string(),
            Ok(rest) => format!("{}/{}", workspace.trim_end_matches('/'), rest.to_string_lossy()),
            Err(_) => host.to_string_lossy().into_owned(),
        }
    }

    /// The two argvs init runs, `compose` the binary, with `overlay` (a file in
    /// the container) after the project's files: `config --format json <side
    /// services>` (what compose resolves for them and starts with them), then
    /// `up --detach <side services>`. `None` with no side service: `up` naming
    /// none would start every service, the primary included.
    pub fn up_argv(&self, compose: &str, root: &Path, workspace: &str, overlay: &str) -> Option<(Vec<String>, Vec<String>)> {
        if self.side.is_empty() {
            return None;
        }
        let mut a = vec![
            compose.to_string(),
            "--project-name".into(),
            PROJECT_NAME.into(),
            "--project-directory".into(),
            Self::in_container(root, workspace, &self.project_dir),
        ];
        for f in &self.files {
            a.extend(["--file".into(), Self::in_container(root, workspace, f)]);
        }
        a.extend(["--file".into(), overlay.to_string()]);
        let with = |verb: &[&str]| -> Vec<String> {
            a.iter().cloned().chain(verb.iter().map(|v| v.to_string())).chain(self.side.iter().cloned()).collect()
        };
        // `--remove-orphans`: the engine's volume keeps this project's
        // containers between runs, and one of a service no file defines any
        // more (renamed, removed) would otherwise start again with the engine.
        Some((with(&["config", "--format", "json"]), with(&["up", "--detach", "--remove-orphans"])))
    }

    /// The overlay init adds after the project's files. The primary is not a
    /// container of the engine, so a side service reaches it by its name
    /// through a host entry: the engine's gateway (`host-gateway`, an address
    /// of the sandbox itself, where the agent listens). The service the
    /// primary shares a network with runs on the sandbox's own
    /// (`network_mode: host`, the engine's host being the sandbox), where the
    /// primary is at loopback.
    pub fn overlay(&self) -> serde_json::Value {
        let mut services = serde_json::Map::new();
        // The service on the sandbox's own network is no container of a
        // compose network either: it too is reached at the gateway, never by
        // a name the engine's DNS would hand to the stub (whose loopback answer
        // is the asker's own).
        let hosts: Vec<String> = std::iter::once(&self.service).chain(&self.host_mode).map(|n| format!("{n}:host-gateway")).collect();
        for name in &self.callers {
            services.insert(name.clone(), serde_json::json!({ "extra_hosts": hosts }));
        }
        if let Some(x) = &self.host_mode {
            services.insert(x.clone(), serde_json::json!({ "network_mode": "host", "extra_hosts": [format!("{}:127.0.0.1", self.service)] }));
        }
        serde_json::json!({ "services": services })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;
    use std::collections::HashMap;

    const ROOT: &str = "/p/app";
    const WS: &str = "/workspaces/app";

    fn files(entries: &[(&str, &str)]) -> HashMap<PathBuf, String> {
        entries.iter().map(|(p, t)| (PathBuf::from(ROOT).join(p), t.to_string())).collect()
    }

    fn reader(map: HashMap<PathBuf, String>) -> impl Fn(&Path) -> Result<String> {
        move |p: &Path| {
            map.get(p)
                .cloned()
                .ok_or_else(|| anyhow::Error::new(std::io::Error::new(std::io::ErrorKind::NotFound, p.display().to_string())))
        }
    }

    fn dc(extra: &str) -> serde_json::Map<String, serde_json::Value> {
        let text = format!(r#"{{"dockerComposeFile": "docker-compose.yml", "service": "app", "workspaceFolder": "{WS}"{extra}}}"#);
        serde_json::from_str(&text).unwrap()
    }

    fn run(obj: &serde_json::Map<String, serde_json::Value>, entries: &[(&str, &str)]) -> Result<(ComposeRun, Primary)> {
        let dc_path = PathBuf::from(ROOT).join(".devcontainer/devcontainer.json");
        let entries: Vec<(String, &str)> = entries.iter().map(|(p, t)| (format!(".devcontainer/{p}"), *t)).collect();
        let entries: Vec<(&str, &str)> = entries.iter().map(|(p, t)| (p.as_str(), *t)).collect();
        read(Path::new(ROOT), &dc_path, obj, WS, &reader(files(&entries)))
    }

    const TEMPLATE: &str = "
services:
  app:
    build:
      context: ..
      dockerfile: .devcontainer/Dockerfile
    volumes:
      - ../..:/workspaces:cached
    command: sleep infinity
    network_mode: service:db
  db:
    image: postgres:16
    restart: unless-stopped
    volumes:
      - postgres-data:/var/lib/postgresql/data
volumes:
  postgres-data:
";

    #[test]
    fn the_microsoft_postgres_template_runs_its_database_on_the_sandbox_network() {
        let (run, p) = run(&dc(""), &[("docker-compose.yml", TEMPLATE)]).unwrap();
        assert_eq!(
            p.source,
            ImageSource::Build {
                context: PathBuf::from(ROOT),
                dockerfile: PathBuf::from(ROOT).join(".devcontainer/Dockerfile"),
                target: None,
                args: vec![],
            }
        );
        assert_eq!(run.side, ["db"]);
        assert_eq!(run.host_mode.as_deref(), Some("db"));
        assert_eq!(run.project_dir, PathBuf::from(ROOT).join(".devcontainer"));
        // The ancestor bind mounts only the project, said; `command` is noted.
        assert!(p.notes.iter().any(|n| n.contains("folders beside it")), "{:?}", p.notes);
        assert!(p.notes.iter().any(|n| n.contains("`command`")), "{:?}", p.notes);
        assert_eq!(
            run.overlay(),
            serde_json::json!({"services": {"db": {"network_mode": "host", "extra_hosts": ["app:127.0.0.1"]}}}),
            "no other service: db's own entry only"
        );
        let (config, up) = run.up_argv("/c", Path::new(ROOT), WS, "/run/ssai/o.json").unwrap();
        let head = [
            "/c", "--project-name", PROJECT_NAME, "--project-directory", "/workspaces/app/.devcontainer",
            "--file", "/workspaces/app/.devcontainer/docker-compose.yml", "--file", "/run/ssai/o.json",
        ];
        assert_eq!(config, [&head[..], &["config", "--format", "json", "db"]].concat());
        assert_eq!(up, [&head[..], &["up", "--detach", "--remove-orphans", "db"]].concat());
    }

    #[test]
    fn a_second_file_adds_to_the_primary_and_keeps_the_first_files_build() {
        let base = "
services:
  app:
    build: { context: .., args: { A: '1', B: '2' } }
    environment: [X=1, Y=2]
    env_file: base.env
  redis:
    image: redis:7
";
        let extend = "
services:
  app:
    build: { args: { B: '3' } }
    environment: { Y: '9', Z: '3' }
    env_file: [extra.env]
    volumes: [ '..:/workspaces/app:cached' ]
";
        let obj = dc(r#", "dockerComposeFile": ["docker-compose.yml", "extend.yml"]"#);
        let (run, p) = run(
            &obj,
            &[("docker-compose.yml", base), ("extend.yml", extend), ("base.env", "E=base\nY=fromfile\n"), ("extra.env", "F=extra")],
        )
        .unwrap();
        let ImageSource::Build { context, args, .. } = &p.source else { panic!("{:?}", p.source) };
        assert_eq!(context, Path::new(ROOT));
        assert_eq!(args, &[("A".to_string(), "1".to_string()), ("B".into(), "3".into())]);
        // env_file first, then `environment`, merged by key.
        assert_eq!(
            p.env,
            [("E", "base"), ("Y", "fromfile"), ("F", "extra"), ("X", "1"), ("Y", "9"), ("Z", "3")]
                .map(|(k, v)| (k.to_string(), v.to_string()))
        );
        assert!(p.notes.is_empty(), "the project's own bind, at the workspace: {:?}", p.notes);
        assert_eq!(run.side, ["redis"]);
        assert_eq!(run.files.len(), 2);
    }

    #[test]
    fn each_refused_key_is_refused_by_name_and_an_unknown_one_too() {
        for (key, _) in REFUSED_KEYS {
            let text = format!("services:\n  app:\n    image: a\n    {key}: x\n");
            let err = format!("{:#}", run(&dc(""), &[("docker-compose.yml", &text)]).unwrap_err());
            assert!(err.contains(&format!("`{key}` is refused")), "{key}: {err}");
        }
        let err = format!("{:#}", run(&dc(""), &[("docker-compose.yml", "services:\n  app:\n    image: a\n    oom_score_adj: 5\n")]).unwrap_err());
        assert!(err.contains("`oom_score_adj` is not a key"), "{err}");
        for (key, _) in IGNORED_KEYS {
            let text = format!("services:\n  app:\n    image: a\n    {key}: x\n");
            let (_, p) = run(&dc(""), &[("docker-compose.yml", &text)]).unwrap();
            assert!(p.notes.iter().any(|n| n.contains(&format!("`{key}`"))), "{key}: {:?}", p.notes);
        }
        // An extension key holds anchors: neither refused nor noted.
        let (_, p) = run(&dc(""), &[("docker-compose.yml", "services:\n  app:\n    image: a\n    x-note: 1\n")]).unwrap();
        assert!(p.notes.is_empty());
    }

    #[test]
    fn a_side_services_own_keys_are_not_read() {
        let text = "services:\n  app:\n    image: a\n  dind:\n    image: docker:dind\n    privileged: true\n    devices: [/dev/kvm]\n    volumes: [/:/host]\n";
        let (run, _) = run(&dc(""), &[("docker-compose.yml", text)]).unwrap();
        assert_eq!(run.side, ["dind"]);
    }

    #[test]
    fn variables_come_from_the_projects_env_and_defaults_never_the_environment() {
        let text = "services:\n  app:\n    image: ${REG:-docker.io}/team/${IMG}:${TAG-1}\n    environment:\n      URL: postgres://${DB_HOST:-db}/x\n      TOKEN: ${HOST_TOKEN}\n      LITERAL: $$HOME\n";
        let (_, p) = run(&dc(""), &[("docker-compose.yml", text), (".env", "IMG=dev\n")]).unwrap();
        assert_eq!(p.source, ImageSource::Image("docker.io/team/dev:1".into()));
        // A short name is Docker Hub's, as compose reads it.
        for (short, full) in [
            ("python:3.12", "docker.io/library/python:3.12"),
            ("team/app", "docker.io/team/app"),
            ("ghcr.io/team/app:1", "ghcr.io/team/app:1"),
            ("localhost/app", "localhost/app"),
            ("registry:5000/app", "registry:5000/app"),
            ("docker://redis", "docker.io/library/redis"),
        ] {
            assert_eq!(docker_reference(short), full, "{short}");
        }
        assert!(p.env.contains(&("URL".into(), "postgres://db/x".into())));
        assert!(p.env.contains(&("LITERAL".into(), "$HOME".into())));
        // A variable only the developer's environment could set is not set, and said.
        assert!(!p.env.iter().any(|(k, _)| k == "TOKEN"));
        assert!(p.notes.iter().any(|n| n.contains("TOKEN") && n.contains("${HOST_TOKEN}")), "{:?}", p.notes);
        // In what decides the image, it is refused.
        let err = format!("{:#}", run(&dc(""), &[("docker-compose.yml", "services:\n  app:\n    image: team/${IMG}\n")]).unwrap_err());
        assert!(err.contains("${IMG}") && err.contains("never reads your environment"), "{err}");
        // A filled value naming the developer's environment is refused (the
        // Dev Container CLI would expand it on this machine for `features`).
        let sneaky = "services:\n  app:\n    build: { context: .., args: { T: '${T}' } }\n";
        let err = format!("{:#}", run(&dc(""), &[("docker-compose.yml", sneaky), (".env", "T='${localEnv:GITHUB_TOKEN}'\n")]).unwrap_err());
        assert!(err.contains("names your environment"), "{err}");
        // SAFETY of the claim: a variable set in this process is still not read.
        let lookup = |_: &str| None;
        assert!(interpolate("${PATH}", &lookup).is_err());
    }

    #[test]
    fn the_interpolation_forms_compose_reads() {
        let vars: HashMap<&str, &str> = [("SET", "v"), ("EMPTY", "")].into();
        let l = |n: &str| vars.get(n).map(|v| v.to_string());
        let ok = |t: &str| interpolate(t, &l).unwrap();
        assert_eq!(ok("$SET ${SET} a$$b $1 $"), "v v a$b $1 $");
        assert_eq!(ok("${EMPTY:-d} ${EMPTY-d} ${NONE-d} ${NONE:-${SET}}"), "d  d v");
        assert_eq!(ok("${SET:+r} ${EMPTY:+r} ${EMPTY+r} ${NONE+r}"), "r  r ");
        assert_eq!(ok("${SET:?e} ${EMPTY?e}"), "v ");
        for bad in ["${NONE}", "$NONE", "${EMPTY:?must}", "${NONE?must}", "${", "${1A}", "${SET:x}"] {
            assert!(interpolate(bad, &l).is_err(), "{bad}");
        }
        assert!(interpolate("${NONE}", &l).unwrap_err().downcast_ref::<Unset>().is_some());
        // Nesting is bounded on both sides.
        let nest = |n: usize| format!("{}x{}", "${NONE:-".repeat(n), "}".repeat(n));
        assert_eq!(interpolate(&nest(MAX_NESTING), &l).unwrap(), "x");
        assert!(interpolate(&nest(MAX_NESTING + 2), &l).is_err());
    }

    proptest::proptest! {
        /// Any text: an answer or an error, never a panic or an overflow; and
        /// a variable is only ever filled from `lookup` — `$$` aside, text
        /// with no `$` comes back as it is. Not a property: idempotence (the
        /// output may hold a `$` a second pass would read).
        #[test]
        fn interpolation_answers_any_text_and_leaves_plain_text_alone(text in ".{0,200}", deep in 0usize..40) {
            let l = |n: &str| (n == "SET").then(|| "v".to_string());
            let _ = interpolate(&text, &l);
            let _ = interpolate(&format!("{}{text}{}", "${SET:-".repeat(deep), "}".repeat(deep)), &l);
            if !text.contains('$') {
                proptest::prop_assert_eq!(interpolate(&text, &l).unwrap(), text);
            }
        }

        /// A short-form volume never splits inside a `${…}`, and its parts
        /// joined back are the entry.
        #[test]
        fn a_volume_splits_only_outside_a_variable(a in "[a-z./]{1,8}", def in "[a-z:./-]{0,8}", b in "[a-z/]{1,8}") {
            let entry = format!("${{{a}:-{def}}}:{b}");
            let parts = split_volume(&entry);
            proptest::prop_assert_eq!(parts.len(), 2);
            proptest::prop_assert_eq!(parts.join(":"), entry);
        }

        /// Any `.env` text reads without a panic, and every name it yields is
        /// one an environment can hold.
        #[test]
        fn a_dotenv_reads_any_text(text in ".{0,300}") {
            for (k, v) in parse_dotenv(&text) {
                proptest::prop_assert!(!k.is_empty() && !k.contains(['=', '\0']) && !k.contains(char::is_whitespace));
                proptest::prop_assert!(!v.contains('\0'));
            }
        }
    }

    #[test]
    fn home_conveniences_are_left_out_and_any_other_host_bind_refused() {
        for bind in [
            "~/.ssh:/home/vscode/.ssh:ro",
            "${HOME}/.gitconfig:/root/.gitconfig",
            "$HOME/.aws/credentials:/x",
            "/home/dev/.ssh/id_ed25519:/k",
            "/Users/dev/.gitconfig:/g",
            "/root/.aws:/a",
            "/var/run/docker.sock:/var/run/docker.sock",
        ] {
            let text = format!("services:\n  app:\n    image: a\n    volumes: ['{bind}']\n");
            let (_, p) = run(&dc(""), &[("docker-compose.yml", &text)]).unwrap();
            assert!(p.notes.iter().any(|n| n.contains("is not mounted")), "{bind}: {:?}", p.notes);
        }
        for bind in ["/etc:/etc", "~/.config:/c", "/home/dev/src:/src", "../data:/data", "/:/host", "${HOME}:/h"] {
            let text = format!("services:\n  app:\n    image: a\n    volumes: ['{bind}']\n");
            let err = format!("{:#}", run(&dc(""), &[("docker-compose.yml", &text)]).unwrap_err());
            assert!(err.contains("refused") || err.contains("never reads your environment"), "{bind}: {err}");
        }
        // A variable filling a volume's name is a named volume, not a bind.
        let (_, p) = run(&dc(""), &[("docker-compose.yml", "services:\n  app:\n    image: a\n    volumes: ['${NM:-nm}:/w/node_modules']\n")]).unwrap();
        assert!(p.notes.iter().any(|n| n.contains("volume `nm`")), "{:?}", p.notes);
        // A named or anonymous volume is noted, never refused; a tmpfs is refused.
        let (_, p) = run(&dc(""), &[("docker-compose.yml", "services:\n  app:\n    image: a\n    volumes: [cache:/w/node_modules, /anon]\n")]).unwrap();
        assert_eq!(p.notes.iter().filter(|n| n.contains("is not kept")).count(), 2, "{:?}", p.notes);
        let tmpfs = "services:\n  app:\n    image: a\n    volumes: [{type: tmpfs, target: /t}]\n";
        assert!(run(&dc(""), &[("docker-compose.yml", tmpfs)]).is_err());
        // The project's own bind at another path: the workspace wins, said.
        let (_, p) = run(&dc(""), &[("docker-compose.yml", "services:\n  app:\n    image: a\n    volumes: ['..:/src']\n")]).unwrap();
        assert!(p.notes.iter().any(|n| n.contains("not at /src")), "{:?}", p.notes);
    }

    #[test]
    fn a_build_stays_in_the_project() {
        for build in ["context: ../..", "context: https://github.com/x/y.git", "{ context: .., dockerfile: ../../Dockerfile }", "{ context: .., ssh: [default] }"] {
            let text = format!("services:\n  app:\n    build: {build}\n");
            assert!(run(&dc(""), &[("docker-compose.yml", &text)]).is_err(), "{build}");
        }
        let (_, p) = run(&dc(""), &[("docker-compose.yml", "services:\n  app:\n    build: .\n    image: ignored:1\n")]).unwrap();
        assert_matches!(&p.source, ImageSource::Build { dockerfile, .. } if dockerfile.ends_with(".devcontainer/Dockerfile"));
    }

    #[test]
    fn nothing_started_may_start_the_primary() {
        use serde_json::json;
        // As compose resolves the side services (`config --format json <side>`):
        // every way one starts another — `links`, `volumes_from`, a `service:`
        // namespace, a variable's default — written as `depends_on`,
        // and the primary listed whenever one of them would start it.
        let resolved = json!({"services": {
            "app": {"image": "a"},
            "queue": {"image": "q", "pid": "service:app", "depends_on": {"app": {"condition": "service_started"}}},
            "worker": {"image": "w", "depends_on": {"queue": {"condition": "service_started"}}},
        }});
        assert_eq!(starting_the_primary(&resolved, "app").unwrap().as_deref(), Some("queue"));
        // Listed with no service naming it: still refused, named itself.
        assert_eq!(starting_the_primary(&json!({"services": {"app": {}, "w": {}}}), "app").unwrap().as_deref(), Some("app"));
        // Positive control: a chain that never reaches the primary.
        let clean = json!({"services": {"queue": {"image": "q"}, "worker": {"depends_on": {"queue": {}}}}});
        assert_eq!(starting_the_primary(&clean, "app").unwrap(), None);
        // A service naming it is refused even when the primary is not listed.
        let unlisted = json!({"services": {"queue": {"depends_on": {"app": {}}}}});
        assert_eq!(starting_the_primary(&unlisted, "app").unwrap().as_deref(), Some("queue"));
        // An answer of another shape says nothing: an error, never "nothing starts it".
        assert!(starting_the_primary(&json!({"name": "x"}), "app").is_err());
        assert!(starting_the_primary(&json!({"services": []}), "app").is_err());
        // On the host: a side service's own keys are compose's to resolve, so a
        // chain naming the primary is not refused there, but by the step.
        let text = "services:\n  app:\n    image: a\n  q:\n    image: q\n    network_mode: ${NET:-service:app}\n    extends: { file: other.yml, service: base }\n";
        let (r, _) = run(&dc(""), &[("docker-compose.yml", text)]).unwrap();
        assert_eq!(r.side, ["q"]);
        // A profiled service starts only when `runServices` names it; the
        // primary's own dependencies always start.
        let text = "services:\n  app:\n    image: a\n    depends_on: [db]\n  db:\n    image: p\n  docs:\n    image: d\n    profiles: [docs]\n  extra:\n    image: e\n";
        let (r, _) = run(&dc(""), &[("docker-compose.yml", text)]).unwrap();
        assert_eq!(r.side, ["db", "extra"]);
        // An empty profile list is no profile; an optional dependency no file
        // defines is skipped, a required one refused.
        let optional = "services:\n  app:\n    image: a\n    depends_on: { cache: { condition: service_started, required: false } }\n  db:\n    image: p\n    profiles: []\n";
        let (o, _) = run(&dc(""), &[("docker-compose.yml", optional)]).unwrap();
        assert_eq!(o.side, ["db"]);
        let required = "services:\n  app:\n    image: a\n    depends_on: { cache: { condition: service_started } }\n";
        assert!(run(&dc(""), &[("docker-compose.yml", required)]).is_err());
        let (r, _) = run(&dc(r#", "runServices": ["app", "docs"]"#), &[("docker-compose.yml", text)]).unwrap();
        assert_eq!(r.side, ["docs", "db"]);
        assert!(run(&dc(r#", "runServices": ["nope"]"#), &[("docker-compose.yml", text)]).is_err());
    }

    #[test]
    fn the_network_sharing_service_runs_on_the_sandbox_network_only_without_networks_of_its_own() {
        let text = "services:\n  app:\n    image: a\n    network_mode: service:db\n  db:\n    image: p\n    networks: [back]\n";
        let err = format!("{:#}", run(&dc(""), &[("docker-compose.yml", text)]).unwrap_err());
        assert!(err.contains("may not set `networks`"), "{err}");
        let text = "services:\n  app:\n    image: a\n    network_mode: service:db\n  db:\n    image: p\n  migrate:\n    image: m\n    links: [db]\n";
        let (r, _) = run(&dc(""), &[("docker-compose.yml", text)]).unwrap();
        assert_eq!(r.host_mode.as_deref(), Some("db"));
        // Another service reaches db where it runs, at the gateway, as it reaches the primary.
        assert_eq!(r.overlay()["services"]["migrate"], serde_json::json!({"extra_hosts": ["app:host-gateway", "db:host-gateway"]}));
        for mode in ["host", "container:x", "service:app", "none"] {
            let text = format!("services:\n  app:\n    image: a\n    network_mode: '{mode}'\n");
            assert!(run(&dc(""), &[("docker-compose.yml", &text)]).is_err(), "{mode}");
        }
        let (r, _) = run(&dc(""), &[("docker-compose.yml", "services:\n  app:\n    image: a\n    network_mode: bridge\n")]).unwrap();
        assert!(r.host_mode.is_none());
        assert_eq!(r.overlay(), serde_json::json!({"services": {}}));
    }

    #[test]
    fn with_no_side_service_nothing_is_started() {
        let (r, _) = run(&dc(""), &[("docker-compose.yml", "services:\n  app:\n    image: a\n")]).unwrap();
        assert!(r.side.is_empty());
        assert_eq!(r.up_argv("/c", Path::new(ROOT), WS, "/o"), None, "`up` naming none would start the primary");
        let (r, _) = run(&dc(r#", "runServices": ["app"]"#), &[("docker-compose.yml", "services:\n  app:\n    image: a\n  db:\n    image: p\n")]).unwrap();
        assert_eq!(r.up_argv("/c", Path::new(ROOT), WS, "/o"), None);
    }

    #[test]
    fn what_the_primary_waits_on_to_finish_is_waited_for_to_finish() {
        let text = "services:\n  app:\n    image: a\n    depends_on:\n      migrate: { condition: service_completed_successfully }\n      db: { condition: service_healthy }\n  migrate:\n    image: m\n  db:\n    image: p\n";
        let (r, _) = run(&dc(""), &[("docker-compose.yml", text)]).unwrap();
        assert_eq!(r.must_exit, ["migrate"]);
        assert_eq!(r.names, ["db", "migrate"], "every service but the primary is reached directly");
        // A dotted name is a real host's, never taken for a service; nor is one
        // that could not go into NO_PROXY or /etc/hosts as it is.
        let text = "services:\n  app:\n    image: a\n  migrate:\n    image: m\n  deb.debian.org:\n    image: x\n  localhost:\n    image: y\n  'a,b':\n    image: z\n  'c d':\n    image: z\n";
        let (r, _) = run(&dc(""), &[("docker-compose.yml", text)]).unwrap();
        assert_eq!(r.names, ["migrate"]);
        // A tagged `depends_on` on the primary (`!reset`, `!override`) is refused, as on the keys it reads.
        let text = "services:\n  app:\n    image: a\n    depends_on: !override\n      migrate: { condition: service_completed_successfully }\n  migrate:\n    image: m\n";
        assert!(run(&dc(""), &[("docker-compose.yml", text)]).is_err());
    }

    #[test]
    fn every_other_service_reaches_the_primary_by_name_but_one_on_another_network() {
        let text = "services:\n  app:\n    image: a\n  selenium:\n    image: s\n  worker:\n    image: w\n    profiles: [jobs]\n  sidecar:\n    image: c\n    network_mode: service:selenium\n";
        let (r, _) = run(&dc(""), &[("docker-compose.yml", text)]).unwrap();
        assert_eq!(r.callers, ["selenium", "worker"], "a profiled service may start later; one sharing a network takes no host entry");
        let text = "services:\n  app:\n    image: a\n  base:\n    image: b\n    network_mode: service:selenium\n  selenium:\n    image: s\n  child:\n    extends: base\n";
        let (extended, _) = run(&dc(""), &[("docker-compose.yml", text)]).unwrap();
        assert_eq!(extended.callers, ["selenium"], "one that extends another may inherit its network_mode");
        let text = "services:\n  app:\n    image: a\n  api:\n    image: x\n    network_mode: bridge\n  h:\n    image: y\n    network_mode: host\n";
        let (bridged, _) = run(&dc(""), &[("docker-compose.yml", text)]).unwrap();
        assert_eq!(bridged.callers, ["api"], "bridge is an engine network; host takes no host entry");
        assert_eq!(
            r.overlay(),
            serde_json::json!({"services": {
                "selenium": {"extra_hosts": ["app:host-gateway"]},
                "worker": {"extra_hosts": ["app:host-gateway"]},
            }})
        );
    }

    #[test]
    fn the_files_are_bounded_and_their_shape_checked() {
        assert!(run(&dc(""), &[("docker-compose.yml", "include: [other.yml]\nservices:\n  app:\n    image: a\n")]).is_err());
        assert!(run(&dc(""), &[("docker-compose.yml", "services:\n  web:\n    image: a\n")]).is_err(), "no such service");
        assert!(run(&dc(""), &[]).is_err(), "no file");
        // The cap on both sides: a file of exactly the cap is read.
        let head = "services:\n  app:\n    image: a\n# ";
        let at_cap = format!("{head}{}", "x".repeat(FILE_CAP - head.len()));
        assert_eq!(at_cap.len(), FILE_CAP);
        assert!(run(&dc(""), &[("docker-compose.yml", &at_cap)]).is_ok());
        assert!(run(&dc(""), &[("docker-compose.yml", &format!("{at_cap}x"))]).is_err());
        // An alias bomb stops at the parser's repetition limit.
        let mut bomb = String::from("a: &a [x, x, x, x, x, x, x, x, x, x]\n");
        for i in 0..9 {
            let prev = if i == 0 { "a".to_string() } else { format!("b{}", i - 1) };
            bomb.push_str(&format!("b{i}: &b{i} [*{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}]\n"));
        }
        bomb.push_str("services:\n  app:\n    image: a\n");
        assert!(run(&dc(""), &[("docker-compose.yml", &bomb)]).is_err());
        // Anchors and `<<:` merge keys are applied.
        let anchors = "x-base: &base\n  image: a\n  environment: { A: '1' }\nservices:\n  app:\n    <<: *base\n";
        let (_, p) = run(&dc(""), &[("docker-compose.yml", anchors)]).unwrap();
        assert_eq!(p.source, ImageSource::Image("docker.io/library/a".into()));
        assert_eq!(p.env, [("A".to_string(), "1".to_string())]);
        // A tag on a key the sandbox reads is refused.
        let tagged = "services:\n  app:\n    image: a\n    environment: !reset {}\n";
        assert!(run(&dc(""), &[("docker-compose.yml", tagged)]).is_err());
        // A compose file outside the project, or named by a variable.
        assert!(run(&dc(r#", "dockerComposeFile": "../../x.yml""#), &[]).is_err());
        assert!(run(&dc(r#", "dockerComposeFile": "${X}.yml""#), &[]).is_err());
        assert!(run(&dc(r#", "service": """#), &[("docker-compose.yml", "services: {}")]).is_err());
    }

    #[test]
    fn a_dotenv_reads_as_compose_reads_it() {
        let got = parse_dotenv(
            "# c\nexport A=1\nB = two words # note\nC='$x #y'\nD=\"l1\\nq\\\"\"\n\nE\nbad key=1\nF=\nG=${A}x\nH=\"${B}\"\nI='${A}'\nJ=${NONE}y\nK=${A:?}\n",
        );
        let want: Vec<(String, String)> = [
            ("A", "1"),
            ("B", "two words"),
            ("C", "$x #y"),
            ("D", "l1\nq\""),
            ("F", ""),
            // An earlier entry fills a bare or double-quoted value; single quotes keep it as written.
            ("G", "1x"),
            ("H", "two words"),
            ("I", "${A}"),
            ("J", "y"),
            ("K", "1"),
        ]
        .map(|(k, v)| (k.into(), v.into()))
        .to_vec();
        assert_eq!(got, want);
    }

    #[test]
    fn an_unset_shutdown_action_is_the_default_and_another_is_noted() {
        let text = "services:\n  app:\n    image: a\n";
        let (_, p) = run(&dc(r#", "shutdownAction": "none""#), &[("docker-compose.yml", text)]).unwrap();
        assert!(p.notes.iter().any(|n| n.contains("shutdownAction")));
        let (_, p) = run(&dc(r#", "shutdownAction": "stopCompose""#), &[("docker-compose.yml", text)]).unwrap();
        assert!(p.notes.is_empty());
    }
}
