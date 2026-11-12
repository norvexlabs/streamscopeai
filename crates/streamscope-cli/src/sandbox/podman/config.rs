//! The docker tier's project configuration: `.streamscopeai/sandbox.json`,
//! and the `devcontainer.json` it may name. Pure — the caller reads the files.
//!
//! `sandbox.json` holds named sandboxes: `{ "sandboxes": { "<name>": {…} } }`.
//! Each names its image one of two ways, exactly one of them:
//! `{ "image": "<ref>" }`, or `{ "devcontainer": "<path>" }` — a
//! `devcontainer.json` relative to the project root. Beside it: `docker`
//! (run an engine inside), and the limits `memory`, `cpus`, `pids`. A run
//! starts the one named [`DEFAULT_SANDBOX`]; any other name, or a name given
//! twice, is refused.
//!
//! A `devcontainer.json` key that would widen what the container reaches on
//! the host (`runArgs`, `mounts`, `privileged`, …) is refused by name, never
//! ignored: a project that relies on it would otherwise run without it and
//! fail later, somewhere less clear.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Where `sandbox.json` lives, under the project root.
pub const SANDBOX_FILE: &str = ".streamscopeai/sandbox.json";

/// The sandbox a run starts: the one field of `Sandboxes`.
pub const DEFAULT_SANDBOX: &str = "default";

/// The pids limit when `sandbox.json` sets none: Podman's own default (2048)
/// is too low for a parallel build.
pub const DEFAULT_PIDS: u32 = 16_384;

/// `devcontainer.json` keys refused, and why.
const REFUSED_KEYS: &[(&str, &str)] = &[
    ("runArgs", "it passes arbitrary podman options"),
    ("mounts", "it mounts host paths into the container"),
    ("workspaceMount", "the sandbox mounts the project itself"),
    ("privileged", "use `\"docker\": true` in sandbox.json for an engine inside"),
    ("capAdd", "the sandbox sets the container's capabilities"),
    ("securityOpt", "the sandbox sets the container's security options"),
    ("dockerComposeFile", "compose-based dev containers are not supported"),
    ("dockerFile", "use `build.dockerfile`, which the sandbox confines to the project"),
    ("context", "use `build.context`, which the sandbox confines to the project"),
];

/// `devcontainer.json` keys read but not acted on, and what the user is told.
const IGNORED_KEYS: &[(&str, &str)] = &[
    ("initializeCommand", "never runs: it would run on the host"),
    ("forwardPorts", "is not forwarded by this version"),
    ("appPort", "is not forwarded by this version"),
    ("overrideCommand", "is not applied: the sandbox starts the agent itself"),
    ("userEnvProbe", "is not applied"),
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SandboxesFile {
    sandboxes: Sandboxes,
}

/// The `sandboxes` object: its one entry, [`DEFAULT_SANDBOX`]. Another name
/// is refused at its key, and a name given twice is refused — a JSON reader
/// would keep the last copy, so the copy a developer reads first would not be
/// the one that runs.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Sandboxes {
    default: SandboxFile,
}

/// `sandbox.json` holding `entry` as its default sandbox.
pub fn example(entry: &str) -> String {
    format!(r#"{{"sandboxes": {{"{DEFAULT_SANDBOX}": {entry}}}}}"#)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SandboxFile {
    image: Option<String>,
    devcontainer: Option<String>,
    #[serde(default)]
    docker: bool,
    memory: Option<String>,
    cpus: Option<f64>,
    pids: Option<u32>,
}

/// How the image is obtained.
#[derive(Debug, Clone, PartialEq)]
pub enum ImageSource {
    /// Pulled by reference.
    Image(String),
    /// Built from a Dockerfile.
    Build {
        context: PathBuf,
        dockerfile: PathBuf,
        target: Option<String>,
        args: Vec<(String, String)>,
    },
}

/// The container's resource limits.
#[derive(Debug, Clone, PartialEq)]
pub struct Limits {
    /// A podman `--memory` value (`6g`).
    pub memory: Option<String>,
    pub cpus: Option<f64>,
    pub pids: u32,
}

/// The resolved project configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct DockerConfig {
    pub source: ImageSource,
    /// The `devcontainer.json` file, when the image comes from one.
    pub devcontainer: Option<PathBuf>,
    /// `features` are present: the image needs the devcontainer CLI to build.
    pub has_features: bool,
    /// `remoteUser` and `containerUser`: who the agent runs as, with the
    /// image's own metadata (see `prepare`). Both `None`: the image decides.
    pub remote_user: Option<String>,
    pub container_user: Option<String>,
    /// Where the project is mounted; `None` = the same path as on the host.
    pub workspace_folder: Option<String>,
    /// Run an engine (dockerd) inside.
    pub docker: bool,
    pub limits: Limits,
    /// The lifecycle commands and the environment it sets.
    pub lifecycle: Lifecycle,
    /// One line per key read but not acted on, for the run to print.
    pub notes: Vec<String>,
}

/// The create hooks, run once per home (project and client) and image, in
/// this order; then the start hooks, run on every run.
pub const CREATE_HOOKS: [&str; 3] = ["onCreateCommand", "updateContentCommand", "postCreateCommand"];
pub const START_HOOKS: [&str; 2] = ["postStartCommand", "postAttachCommand"];

/// One lifecycle command: the hook it is from, and its argv (a string is
/// run by `/bin/sh -c`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    pub hook: String,
    pub argv: Vec<String>,
}

/// A Dev Container's lifecycle commands and environment, merged from the
/// image's metadata and the project's `devcontainer.json` (in that order).
/// `${containerEnv:NAME}` is left as written: only the image's environment
/// says what it is ([`fill_container_env`]).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Lifecycle {
    pub create: Vec<Step>,
    pub start: Vec<Step>,
    /// `containerEnv`: a later entry wins.
    pub container_env: Vec<(String, String)>,
    /// `remoteEnv`, laid over the container's: a later entry wins.
    pub remote_env: Vec<(String, String)>,
}

impl Lifecycle {
    /// `other` after `self`.
    pub fn then(mut self, other: Lifecycle) -> Lifecycle {
        self.create.extend(other.create);
        self.start.extend(other.start);
        self.container_env.extend(other.container_env);
        self.remote_env.extend(other.remote_env);
        self
    }

    /// `self` with its variables only.
    pub fn env_only(self) -> Lifecycle {
        Lifecycle { create: Vec::new(), start: Vec::new(), ..self }
    }
}

/// The lifecycle keys of one metadata entry or `devcontainer.json`
/// (`obj`), each text passed through `expand` (key, text).
pub fn lifecycle_of(obj: &serde_json::Map<String, Value>, expand: &dyn Fn(&str, &str) -> Result<String>) -> Result<Lifecycle> {
    // A NUL cannot travel in an argv or an environment: refused here, by key.
    let expand = &|key: &str, text: &str| -> Result<String> {
        if text.contains('\0') {
            bail!("`{key}` holds a NUL character");
        }
        expand(key, text)
    };
    let steps = |hooks: &[&str]| -> Result<Vec<Step>> {
        let mut out = Vec::new();
        for hook in hooks {
            let argv = |v: &Value, key: &str| -> Result<Vec<String>> {
                match v {
                    Value::String(s) if s.trim().is_empty() => Ok(Vec::new()),
                    Value::String(s) => Ok(vec!["/bin/sh".into(), "-c".into(), expand(key, s)?]),
                    Value::Array(a) if a.iter().all(Value::is_string) => {
                        a.iter().filter_map(Value::as_str).map(|s| expand(key, s)).collect()
                    }
                    _ => bail!("`{key}` must be a string or an array of strings"),
                }
            };
            match obj.get(*hook) {
                None | Some(Value::Null) => {}
                // Named commands, which the Dev Container CLI runs in
                // parallel: here one after another, in the order of their names.
                Some(Value::Object(named)) => {
                    for (name, v) in named {
                        let argv = argv(v, &format!("{hook}.{name}"))?;
                        if !argv.is_empty() {
                            out.push(Step { hook: format!("{hook}.{name}"), argv });
                        }
                    }
                }
                Some(v) => {
                    let argv = argv(v, hook)?;
                    if !argv.is_empty() {
                        out.push(Step { hook: hook.to_string(), argv });
                    }
                }
            }
        }
        Ok(out)
    };
    let mut envs = [Vec::new(), Vec::new()];
    for (key, env) in ["containerEnv", "remoteEnv"].into_iter().zip(&mut envs) {
        match obj.get(key) {
            None | Some(Value::Null) => {}
            Some(Value::Object(m)) => {
                for (name, v) in m {
                    // `null` unsets a variable: the image's own value stays.
                    let v = match v {
                        Value::Null => continue,
                        Value::String(v) => v,
                        _ => bail!("`{key}.{name}` must be a string"),
                    };
                    if name.is_empty() || name.contains(['=', '\0']) {
                        bail!("`{key}` names a variable {name:?}, which no environment can hold");
                    }
                    env.push((name.clone(), expand(&format!("{key}.{name}"), v)?));
                }
            }
            Some(_) => bail!("`{key}` must be an object"),
        }
    }
    let [container_env, remote_env] = envs;
    Ok(Lifecycle { create: steps(&CREATE_HOOKS)?, start: steps(&START_HOOKS)?, container_env, remote_env })
}

/// `text` with every `${containerEnv:NAME}` replaced by `lookup(NAME)` (an
/// unset one is empty, as the Dev Container CLI has it; `${containerEnv:NAME:default}`
/// takes the default).
pub fn fill_container_env(text: &str, lookup: &dyn Fn(&str) -> Option<String>) -> String {
    const OPEN: &str = "${containerEnv:";
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find(OPEN) {
        let Some(end) = rest[at..].find('}') else { break };
        out.push_str(&rest[..at]);
        let var = &rest[at + OPEN.len()..at + end];
        let (name, default) = var.split_once(':').map_or((var, None), |(n, d)| (n, Some(d)));
        out.push_str(&lookup(name).or(default.map(str::to_string)).unwrap_or_default());
        rest = &rest[at + end + 1..];
    }
    out.push_str(rest);
    out
}

/// Resolve `sandbox.json` (`text`) for the project at `root`, reading a
/// referenced `devcontainer.json` with `read`.
pub fn resolve(root: &Path, text: &str, read: &dyn Fn(&Path) -> Result<String>) -> Result<DockerConfig> {
    let file: SandboxesFile = serde_json::from_str(text).map_err(|e| {
        let e = anyhow::Error::new(e).context(format!("read {SANDBOX_FILE}"));
        // A sandbox's keys at the top: show the same keys in the form that holds them.
        let flat = serde_json::from_str::<Value>(text)
            .is_ok_and(|v| v.as_object().is_some_and(|o| !o.contains_key("sandboxes") && (o.contains_key("image") || o.contains_key("devcontainer"))));
        if flat { e.context(format!("{SANDBOX_FILE} holds named sandboxes: {}", example(text.trim()))) } else { e }
    })?;
    let file = file.sandboxes.default;
    resolve_one(root, file, read)
}

fn resolve_one(root: &Path, file: SandboxFile, read: &dyn Fn(&Path) -> Result<String>) -> Result<DockerConfig> {
    let limits = limits(&file)?;
    match (file.image, file.devcontainer) {
        (Some(image), None) => {
            let image = image.trim();
            if !image_reference(image) {
                bail!("{SANDBOX_FILE}: `image` must be an image reference, got {image:?}");
            }
            Ok(DockerConfig {
                source: ImageSource::Image(registry_reference(image)),
                devcontainer: None,
                has_features: false,
                remote_user: None,
                container_user: None,
                workspace_folder: None,
                docker: file.docker,
                limits,
                lifecycle: Lifecycle::default(),
                notes: Vec::new(),
            })
        }
        (None, Some(rel)) => {
            let path = inside(root, &rel).with_context(|| format!("{SANDBOX_FILE}: `devcontainer`"))?;
            let text = read(&path).with_context(|| format!("read {}", path.display()))?;
            let value = crate::writer::json::parse_jsonc(&text).with_context(|| format!("parse {}", path.display()))?;
            devcontainer(root, &path, &value, file.docker, limits)
        }
        (Some(_), Some(_)) => bail!("{SANDBOX_FILE}: set `image` or `devcontainer`, not both"),
        (None, None) => bail!("{SANDBOX_FILE}: set `image` (an image reference) or `devcontainer` (a devcontainer.json path)"),
    }
}

fn limits(file: &SandboxFile) -> Result<Limits> {
    if let Some(m) = &file.memory {
        let digits = m.strip_suffix(['b', 'k', 'm', 'g', 'B', 'K', 'M', 'G']).unwrap_or(m);
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            bail!("{SANDBOX_FILE}: `memory` must be a size such as \"6g\", got {m:?}");
        }
    }
    if let Some(c) = file.cpus
        && !(c > 0.0 && c <= 1024.0)
    {
        bail!("{SANDBOX_FILE}: `cpus` must be above 0 and at most 1024, got {c}");
    }
    let pids = file.pids.unwrap_or(DEFAULT_PIDS);
    if pids < 64 {
        bail!("{SANDBOX_FILE}: `pids` must be at least 64, got {pids}");
    }
    Ok(Limits { memory: file.memory.clone(), cpus: file.cpus, pids })
}

/// `rel` under `root`, refusing an absolute path or one that climbs out.
fn inside(root: &Path, rel: &str) -> Result<PathBuf> {
    let p = Path::new(rel);
    if rel.is_empty() || p.is_absolute() || p.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
        bail!("{rel:?} must be a path inside the project");
    }
    Ok(root.join(p))
}

fn devcontainer(root: &Path, path: &Path, value: &Value, docker: bool, limits: Limits) -> Result<DockerConfig> {
    let obj = value.as_object().with_context(|| format!("{}: not a JSON object", path.display()))?;
    let shown = path.display();
    // The developer's environment never reaches the build — nor the Dev
    // Container CLI, which would expand it anywhere in the file.
    let text = value.to_string();
    if names_local_env(&text) {
        bail!(
            "{shown}: `${{localEnv:…}}` (or `${{env:…}}`) is refused by the docker sandbox — it would carry your \
             environment into the image's build"
        );
    }
    for (key, why) in REFUSED_KEYS {
        if obj.contains_key(*key) {
            bail!("{shown}: `{key}` is refused by the docker sandbox — {why}");
        }
    }
    let mut notes: Vec<String> = IGNORED_KEYS
        .iter()
        .filter(|(key, _)| obj.contains_key(*key))
        .map(|(key, what)| format!("{shown}: `{key}` {what}"))
        .collect();
    let features = obj.get("features").and_then(Value::as_object);
    let has_features = features.is_some_and(|f| !f.is_empty());
    if has_features {
        notes.push(format!(
            "{shown}: a feature's own container settings (`privileged`, its entrypoint, its mounts) are not applied — \
             use `\"docker\": true` in sandbox.json for an engine inside"
        ));
    }
    // With `features` the Dev Container CLI builds the image, and pulls a
    // `cacheFrom` itself, from this machine's network.
    if obj.get("build").and_then(|b| b.get("cacheFrom")).is_some() {
        notes.push(if has_features {
            format!("{shown}: `build.cacheFrom` is pulled by the Dev Container CLI, from this machine's network")
        } else {
            format!("{shown}: `build.cacheFrom` is not used: the image builds without that cache")
        });
    }
    let string = |key: &str| -> Result<Option<String>> {
        match obj.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) if !s.trim().is_empty() => Ok(Some(s.trim().to_string())),
            Some(_) => bail!("{shown}: `{key}` must be a non-empty string"),
        }
    };
    let dir = path.parent().unwrap_or(Path::new("."));
    // Variables are expanded where the Dev Container spec allows them; the
    // workspace first, since the others may name it.
    let workspace_folder = string("workspaceFolder")?
        .map(|w| expand(&w, root, None).with_context(|| format!("{shown}: `workspaceFolder`")))
        .transpose()?;
    let container_workspace = workspace_folder.clone().unwrap_or_else(|| root.to_string_lossy().into_owned());
    let expand_here = |text: &str, key: &str| {
        expand(text, root, Some(&container_workspace)).with_context(|| format!("{shown}: `{key}`"))
    };
    let source = match (string("image")?, obj.get("build")) {
        (Some(image), None) if !image_reference(&image) => bail!("{shown}: `image` must be an image reference, got {image:?}"),
        (Some(image), None) => ImageSource::Image(registry_reference(&image)),
        (None, Some(build)) => build_source(root, dir, build, &expand_here).with_context(|| format!("{shown}: `build`"))?,
        (Some(_), Some(_)) => bail!("{shown}: set `image` or `build`, not both"),
        (None, None) => bail!("{shown}: set `image` or `build.dockerfile`"),
    };
    if let Some(w) = &workspace_folder
        && SYSTEM_PATHS
            .iter()
            .any(|s| w.trim_end_matches('/').is_empty() || Path::new(w).starts_with(s) || Path::new(s).starts_with(w))
    {
        bail!("{shown}: `workspaceFolder` {w:?} is a system path of the container — mount the project elsewhere");
    }
    if let Some(w) = &workspace_folder
        && (!w.starts_with('/') || !container_path(w))
    {
        bail!(
            "{shown}: `workspaceFolder` must be an absolute path in the container, without `..`, `:` or `,`, got {w:?}"
        );
    }
    // A local feature (a folder path) is copied into the build as it is,
    // symlinks and all: only published features (a registry reference) are taken.
    if let Some(local) = features.and_then(|f| {
        f.keys().find(|k| k.starts_with('.') || k.starts_with('/') || k.starts_with('~'))
    }) {
        bail!("{shown}: the local feature {local:?} is refused by the docker sandbox — publish it, or install it in a Dockerfile");
    }
    // With `features` the whole file goes to the Dev Container CLI, which may
    // run it on the host while it builds.
    // The same CLI expands `${env:…}` from this machine's environment, the
    // shell's `${env:-x}` included.
    if has_features && text.contains("${env:") {
        bail!("{shown}: `${{env:…}}` is refused beside `features` — the Dev Container CLI that builds them would read it from your environment");
    }
    if has_features && obj.contains_key("initializeCommand") {
        bail!("{shown}: `initializeCommand` is refused beside `features` — the Dev Container CLI that builds them could run it on the host");
    }
    let lifecycle = lifecycle_of(obj, &|key, text| {
        expand_lenient(text, root, &container_workspace).with_context(|| format!("{shown}: `{key}`"))
    })?;
    Ok(DockerConfig {
        source,
        devcontainer: Some(path.to_path_buf()),
        has_features,
        remote_user: string("remoteUser")?.map(|u| expand_here(&u, "remoteUser")).transpose()?,
        container_user: string("containerUser")?.map(|u| expand_here(&u, "containerUser")).transpose()?,
        workspace_folder,
        docker,
        limits,
        lifecycle,
        notes,
    })
}

/// Paths of the container a project is never mounted over: the image's own
/// files, and the sandbox's mount points (`/run/ssai…`).
const SYSTEM_PATHS: &[&str] =
    &["/etc", "/run", "/proc", "/sys", "/dev", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/var/run", "/var/lib/docker"];

/// Whether two container paths overlap: one is the other, or inside it
/// (component-wise: `/opt/a` is not inside `/opt/ab`). A mount on either
/// hides the other.
pub fn overlaps(a: &str, b: &str) -> bool {
    let (a, b) = (Path::new(a), Path::new(b));
    a.starts_with(b) || b.starts_with(a)
}

/// Whether `path`, a path in the container, mounts as given: podman reads a
/// `:` or `,` in a volume as its options (`/w:U` would re-own the project),
/// and a `..` would place the mount elsewhere.
pub fn container_path(path: &str) -> bool {
    !path.contains([':', ','])
        && !path.chars().any(char::is_control)
        && !Path::new(path).components().any(|c| matches!(c, std::path::Component::ParentDir))
}

/// `rel` (relative to the devcontainer.json's `dir`) as a path that stays in
/// the project: what podman builds from is sent with the network open, before
/// any guard runs.
fn in_project(root: &Path, dir: &Path, rel: &str, key: &str) -> Result<PathBuf> {
    let mut out = PathBuf::new();
    for c in dir.join(rel).components() {
        match c {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other),
        }
    }
    if !out.starts_with(root) {
        bail!("`{key}` {rel:?} is outside the project — the image is built from the project only");
    }
    Ok(out)
}

/// Podman transports that read the image from a path, not a registry: one
/// would import a host file from outside the project.
const PATH_TRANSPORTS: &[&str] =
    &["dir", "oci", "oci-archive", "docker-archive", "containers-storage", "docker-daemon", "sif", "tarball", "ostree"];

/// `image` as podman stores it: a `docker://` transport is the registry's own.
fn registry_reference(image: &str) -> String {
    image.strip_prefix("docker://").unwrap_or(image).to_string()
}

/// A positional image reference from a registry: not empty, not an option,
/// one word, no path transport.
fn image_reference(image: &str) -> bool {
    // Checked as podman will read it: a path transport behind `docker://`
    // is still one.
    let image = image.strip_prefix("docker://").unwrap_or(image);
    !image.is_empty()
        && !image.starts_with('-')
        && !image.chars().any(|c| c.is_whitespace() || c.is_control())
        && !image.split_once(':').is_some_and(|(scheme, _)| PATH_TRANSPORTS.contains(&scheme))
}

/// `text` with the Dev Container variables it names expanded:
/// `${localWorkspaceFolder}` and `${localWorkspaceFolderBasename}` (the
/// project on the host), and — given `workspace` — `${containerWorkspaceFolder}`
/// and its `Basename`. Any other variable is refused by name, never passed on
/// as written: `${localEnv:…}` above all, which would carry the developer's
/// environment (a token) into a build that runs before any guard.
fn expand(text: &str, root: &Path, workspace: Option<&str>) -> Result<String> {
    scan(text, root, workspace, false)
}

/// `text` with the Dev Container variables of [`expand`] expanded and any
/// other `${…}` left as written: a lifecycle command is shell text (`${HOME}`
/// is the shell's), and `${containerEnv:…}` is filled in at the run. The
/// developer's own environment never is: `${localEnv:…}` is refused.
pub fn expand_lenient(text: &str, root: &Path, workspace: &str) -> Result<String> {
    scan(text, root, Some(workspace), true)
}

/// Whether `text` names the developer's environment: `${localEnv:NAME}`, or
/// its alias `${env:NAME}` — not the shell's `${env:-default}`.
fn names_local_env(text: &str) -> bool {
    text.contains("${localEnv:")
        || text.match_indices("${env:").any(|(at, m)| {
            text[at + m.len()..].chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        })
}

/// [`expand`] (`lenient`: [`expand_lenient`]).
fn scan(text: &str, root: &Path, workspace: Option<&str>, lenient: bool) -> Result<String> {
    let base = |p: &str| Path::new(p).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find("${") {
        let Some(end) = rest[at..].find('}') else {
            if lenient {
                break;
            }
            bail!("{text:?}: an unclosed `${{`")
        };
        let var = &rest[at + 2..at + end];
        if names_local_env(&rest[at..=at + end]) {
            bail!("`${{{var}}}` is refused by the docker sandbox — it would carry your environment into the container");
        }
        out.push_str(&rest[..at]);
        let root_text = root.to_string_lossy();
        out.push_str(&match (var, workspace) {
            ("localWorkspaceFolder", _) => root_text.into_owned(),
            ("localWorkspaceFolderBasename", _) => base(&root_text),
            ("containerWorkspaceFolder", Some(w)) => w.to_string(),
            ("containerWorkspaceFolderBasename", Some(w)) => base(w),
            _ if lenient => format!("${{{var}}}"),
            _ => bail!("{text:?}: `${{{var}}}` is not a variable the docker sandbox expands here"),
        });
        rest = &rest[at + end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

fn build_source(root: &Path, dir: &Path, build: &Value, expand: &dyn Fn(&str, &str) -> Result<String>) -> Result<ImageSource> {
    let obj = build.as_object().context("must be an object")?;
    // `options` passes arbitrary `podman build` flags (`-v`, `--secret`): it
    // would reach host files while the build runs with the network open.
    for key in obj.keys() {
        match key.as_str() {
            "dockerfile" | "context" | "target" | "args" | "cacheFrom" => {}
            "options" => bail!("`options` is refused by the docker sandbox — it passes arbitrary podman build options"),
            other => bail!("`{other}` is not a `build` key the docker sandbox knows"),
        }
    }
    for key in ["dockerfile", "context", "target"] {
        match obj.get(key) {
            Some(v) if !v.is_string() => bail!("`{key}` must be a string"),
            // The Dev Container CLI would expand it after these checks: a
            // context that leaves the project only once expanded.
            Some(Value::String(s)) if s.contains("${") => bail!("`{key}` may not hold a `${{…}}` variable"),
            _ => {}
        }
    }
    let text = |key: &str| obj.get(key).and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty());
    let dockerfile = in_project(root, dir, text("dockerfile").context("`dockerfile` is required")?, "dockerfile")?;
    let context = in_project(root, dir, text("context").unwrap_or("."), "context")?;
    let args = match obj.get("args") {
        None => Vec::new(),
        Some(Value::Object(m)) => m
            .iter()
            .map(|(k, v)| match v {
                Value::String(s) => Ok((k.clone(), expand(s, &format!("args.{k}"))?)),
                _ => bail!("`args.{k}` must be a string"),
            })
            .collect::<Result<_>>()?,
        Some(_) => bail!("`args` must be an object"),
    };
    Ok(ImageSource::Build { dockerfile, context, target: text("target").map(str::to_string), args })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    /// `entry` as the project's default sandbox.
    fn resolve_entry(root: &Path, entry: &str, read: &dyn Fn(&Path) -> Result<String>) -> Result<DockerConfig> {
        resolve(root, &example(entry), read)
    }

    fn no_file(_: &Path) -> Result<String> {
        bail!("no such file")
    }

    fn with(dc: &'static str) -> impl Fn(&Path) -> Result<String> {
        move |p: &Path| {
            assert!(p.ends_with(".devcontainer/devcontainer.json"), "{}", p.display());
            Ok(dc.to_string())
        }
    }

    const DC: &str = r#"{"devcontainer": ".devcontainer/devcontainer.json"}"#;

    #[test]
    fn an_image_reference_is_taken_with_default_limits() {
        let c = resolve_entry(Path::new("/p"), r#"{"image": " ghcr.io/team/dev:1 "}"#, &no_file).unwrap();
        assert_eq!(c.source, ImageSource::Image("ghcr.io/team/dev:1".into()));
        assert!(!c.docker && c.remote_user.is_none() && c.container_user.is_none() && c.workspace_folder.is_none() && c.notes.is_empty());
        assert_eq!(c.limits, Limits { memory: None, cpus: None, pids: DEFAULT_PIDS });
    }

    #[test]
    fn the_file_holds_named_sandboxes_and_a_run_takes_the_default() {
        let ok = r#"{"sandboxes": {"default": {"image": "a"}}}"#;
        assert_eq!(resolve(Path::new("/p"), ok, &no_file).unwrap().source, ImageSource::Image("a".into()));
        let named = "holds named sandboxes";
        for (text, says) in [
            // A sandbox's keys at the top: shown under `sandboxes`, and refused as unknown.
            (r#"{"devcontainer": "d", "docker": true}"#, vec![r#"{"sandboxes": {"default": {"devcontainer": "d", "docker": true}}}"#, "unknown field `devcontainer`"]),
            (r#"{"image": "a"}"#, vec![named, "unknown field `image`"]),
            (r#"{"sandboxes": {"default": {"image": "a"}}, "image": "b"}"#, vec!["unknown field `image`"]),
            (r#"{"sandbox": {"default": {"image": "a"}}}"#, vec!["unknown field `sandbox`"]),
            (r#"{"sandboxes": {}}"#, vec!["missing field `default`"]),
            // Another name is refused at its key, before its body is read.
            (r#"{"sandboxes": {"gpu": {"gpus": "all"}}}"#, vec!["unknown field `gpu`"]),
            (r#"{"sandboxes": {"default": {"image": "a"}, "gpu": {"image": "b"}}}"#, vec!["unknown field `gpu`"]),
            // Named twice: the copy read first is not the one that would run.
            (r#"{"sandboxes": {"default": {"image": "a"}, "default": {"image": "b", "docker": true}}}"#, vec!["duplicate field `default`"]),
            (r#"{"sandboxes": {"default": {"image": "a", "image": "b"}}}"#, vec!["duplicate field `image`"]),
        ] {
            let err = format!("{:#}", resolve(Path::new("/p"), text, &no_file).unwrap_err());
            for s in says {
                assert!(err.contains(s), "{text}: {err}");
            }
            // Only a sandbox's keys at the top are shown the form that holds them.
            assert_eq!(err.contains(named), !text.contains("sandbox"), "{text}: {err}");
        }
    }

    #[test]
    fn the_lifecycle_commands_and_environment_are_read_in_their_three_forms() {
        let dc = r#"{"image": "a", "workspaceFolder": "/w/app",
            "onCreateCommand": "echo ${containerWorkspaceFolder} $HOME ${HOME}",
            "postCreateCommand": ["npm", "ci", "--prefix", "${localWorkspaceFolderBasename}"],
            "postStartCommand": {"b": "two", "a": ["one"], "empty": ""},
            "updateContentCommand": "  ",
            "containerEnv": {"A": "1", "GONE": null},
            "remoteEnv": {"PATH": "${containerEnv:PATH}:/x", "A": "2"}}"#;
        let c = resolve_entry(Path::new("/p/proj"), DC, &with(Box::leak(dc.to_string().into_boxed_str()))).unwrap();
        let sh = |s: &str| vec!["/bin/sh".to_string(), "-c".into(), s.into()];
        assert_eq!(
            c.lifecycle.create,
            [
                // The shell's own `${HOME}` is left to the shell.
                Step { hook: "onCreateCommand".into(), argv: sh("echo /w/app $HOME ${HOME}") },
                Step { hook: "postCreateCommand".into(), argv: vec!["npm".into(), "ci".into(), "--prefix".into(), "proj".into()] },
            ]
        );
        let hooks: Vec<&str> = c.lifecycle.start.iter().map(|s| s.hook.as_str()).collect();
        assert_eq!(hooks.len(), 2, "an empty named command is dropped: {hooks:?}");
        assert!(hooks.contains(&"postStartCommand.a") && hooks.contains(&"postStartCommand.b"));
        // A `null` unsets: nothing is set for it.
        assert_eq!(c.lifecycle.container_env, [("A".to_string(), "1".to_string())]);
        let remote = &c.lifecycle.remote_env;
        assert!(remote.contains(&("A".into(), "2".into())) && remote.contains(&("PATH".into(), "${containerEnv:PATH}:/x".into())) && remote.len() == 2, "{remote:?}");
        assert!(c.notes.is_empty(), "nothing of it is ignored: {:?}", c.notes);
        // The shell's own `${env:-default}` is not the developer's environment.
        let sh_default = r#"{"image": "a", "postCreateCommand": "echo ${env:-dev}"}"#;
        let c = resolve_entry(Path::new("/p"), DC, &with(sh_default)).unwrap();
        assert_eq!(c.lifecycle.create[0].argv[2], "echo ${env:-dev}");
        for bad in [
            r#""postCreateCommand": 7"#,
            r#""postCreateCommand": ["npm", 1]"#,
            r#""postStartCommand": {"a": {"b": "c"}}"#,
            r#""remoteEnv": {"A": 1}"#,
            r#""remoteEnv": ["A=1"]"#,
            r#""containerEnv": {"A=B": "1"}"#,
            r#""postCreateCommand": "echo ${localEnv:TOKEN}""#,
            r#""postCreateCommand": "echo ${env:TOKEN}""#,
        ] {
            let dc = format!(r#"{{"image": "a", {bad}}}"#);
            assert!(resolve_entry(Path::new("/p"), DC, &with(Box::leak(dc.into_boxed_str()))).is_err(), "{bad}");
        }
    }

    #[test]
    fn container_env_is_filled_from_the_lookup() {
        let lookup = |n: &str| (n == "PATH").then(|| "/usr/bin".to_string());
        assert_eq!(fill_container_env("${containerEnv:PATH}:/x", &lookup), "/usr/bin:/x");
        assert_eq!(fill_container_env("a${containerEnv:NONE}b", &lookup), "ab", "unset is empty");
        assert_eq!(fill_container_env("${containerEnv:NONE:dflt}", &lookup), "dflt");
        assert_eq!(fill_container_env("${containerEnv:PATH:dflt}", &lookup), "/usr/bin");
        assert_eq!(fill_container_env("${HOME} ${containerEnv:PATH", &lookup), "${HOME} ${containerEnv:PATH", "unclosed: as written");
    }

    #[test]
    fn exactly_one_image_source_is_required() {
        for text in [r#"{}"#, r#"{"image": "a", "devcontainer": "b"}"#, r#"{"image": ""}"#, r#"{"image": "-v"}"#, r#"{"image": "a b"}"#] {
            assert!(resolve_entry(Path::new("/p"), text, &no_file).is_err(), "{text}");
        }
        // An unknown key is a typo, not a setting: refused.
        assert!(resolve_entry(Path::new("/p"), r#"{"image": "a", "dockre": true}"#, &no_file).is_err());
    }

    #[test]
    fn the_limits_are_read_and_their_bounds_held() {
        let ok = resolve_entry(Path::new("/p"), r#"{"image": "a", "memory": "6g", "cpus": 3, "pids": 64}"#, &no_file).unwrap();
        assert_eq!(ok.limits, Limits { memory: Some("6g".into()), cpus: Some(3.0), pids: 64 });
        for bad in [r#""memory": "6 g""#, r#""memory": "g""#, r#""memory": "-1""#, r#""cpus": 0"#, r#""cpus": -1"#, r#""pids": 63"#] {
            let text = format!(r#"{{"image": "a", {bad}}}"#);
            assert!(resolve_entry(Path::new("/p"), &text, &no_file).is_err(), "{text}");
        }
    }

    #[test]
    fn a_devcontainer_path_stays_inside_the_project() {
        for rel in ["/etc/dc.json", "../dc.json", "a/../../dc.json", ""] {
            let text = format!(r#"{{"devcontainer": {rel:?}}}"#);
            assert!(resolve_entry(Path::new("/p"), &text, &no_file).is_err(), "{rel}");
        }
    }

    #[test]
    fn a_devcontainer_is_read_as_jsonc_with_its_user_and_folder() {
        let c = resolve_entry(
            Path::new("/p"),
            DC,
            &with(
                r#"{
                // the team image
                "image": "mcr.microsoft.com/devcontainers/base:ubuntu-24.04",
                "remoteUser": "vscode", "containerUser": "root",
                "workspaceFolder": "/workspaces/app",
                "features": {"ghcr.io/devcontainers/features/node:1": {}},
            }"#,
            ),
        )
        .unwrap();
        assert_eq!(c.source, ImageSource::Image("mcr.microsoft.com/devcontainers/base:ubuntu-24.04".into()));
        assert_eq!(c.remote_user.as_deref(), Some("vscode"));
        assert_eq!(c.workspace_folder.as_deref(), Some("/workspaces/app"));
        assert!(c.has_features);
        assert_eq!(c.devcontainer.as_deref(), Some(Path::new("/p/.devcontainer/devcontainer.json")));
        // Each kept as it is: which wins is decided with the image's metadata.
        let c = resolve_entry(Path::new("/p"), DC, &with(r#"{"image": "a", "containerUser": "dev"}"#)).unwrap();
        assert_eq!((c.remote_user.as_deref(), c.container_user.as_deref()), (None, Some("dev")));
    }

    #[test]
    fn a_build_resolves_against_the_devcontainer_dir() {
        let c = resolve_entry(
            Path::new("/p"),
            DC,
            &with(r#"{"build": {"dockerfile": "Dockerfile", "context": "..", "target": "dev", "args": {"V": "1"}}}"#),
        )
        .unwrap();
        assert_eq!(
            c.source,
            ImageSource::Build {
                dockerfile: PathBuf::from("/p/.devcontainer/Dockerfile"),
                context: PathBuf::from("/p"),
                target: Some("dev".into()),
                args: vec![("V".into(), "1".into())],
            }
        );
        for bad in [r#"{"build": {}}"#, r#"{"build": {"dockerfile": "D", "args": {"V": 1}}}"#, r#"{"image": "a", "build": {"dockerfile": "D"}}"#, r#"{}"#] {
            let read = move |_: &Path| Ok(bad.to_string());
            assert!(resolve_entry(Path::new("/p"), DC, &read).is_err(), "{bad}");
        }
    }

    #[test]
    fn every_widening_key_is_refused_by_name() {
        for (key, _) in REFUSED_KEYS {
            let text = format!(r#"{{"image": "a", "{key}": []}}"#);
            let read = move |_: &Path| Ok(text.clone());
            let err = format!("{:#}", resolve_entry(Path::new("/p"), DC, &read).unwrap_err());
            assert!(err.contains(&format!("`{key}`")), "{err}");
        }
        // Positive control: the same file without it resolves.
        assert!(resolve_entry(Path::new("/p"), DC, &with(r#"{"image": "a"}"#)).is_ok());
    }

    #[test]
    fn a_key_acted_on_elsewhere_is_named_in_a_note() {
        let c = resolve_entry(Path::new("/p"), DC, &with(r#"{"image": "a", "forwardPorts": [3000], "initializeCommand": "x"}"#)).unwrap();
        assert_eq!(c.notes.len(), 2, "{:?}", c.notes);
        assert!(c.notes.iter().any(|n| n.contains("`forwardPorts`")) && c.notes.iter().any(|n| n.contains("`initializeCommand`")));
    }

    #[test]
    fn a_relative_workspace_folder_is_refused() {
        assert!(resolve_entry(Path::new("/p"), DC, &with(r#"{"image": "a", "workspaceFolder": "app"}"#)).is_err());
    }

    #[test]
    fn a_workspace_folder_is_never_a_system_path() {
        for bad in ["/", "/etc", "/etc/app", "/run", "/run/ssai-sock", "/usr/src/app", "/proc/x", "/var/lib/docker/app", "/var", "/var/lib"] {
            let dc = format!(r#"{{"image": "a", "workspaceFolder": "{bad}"}}"#);
            let read = move |_: &Path| Ok(dc.clone());
            assert!(resolve_entry(Path::new("/p"), DC, &read).is_err(), "{bad}");
        }
        // Positive control: the usual places, and a name that only starts like one.
        for good in ["/workspaces/app", "/srv/app", "/home/dev/app", "/etcetera"] {
            let dc = format!(r#"{{"image": "a", "workspaceFolder": "{good}"}}"#);
            let read = move |_: &Path| Ok(dc.clone());
            assert!(resolve_entry(Path::new("/p"), DC, &read).is_ok(), "{good}");
        }
    }

    #[test]
    fn a_workspace_folder_cannot_carry_volume_options() {
        for bad in ["/w:U", "/w:ro", "/w,z", "/w/../etc", "/w\nx"] {
            let dc = format!(r#"{{"image": "a", "workspaceFolder": {}}}"#, serde_json::to_string(bad).unwrap());
            let read = move |_: &Path| Ok(dc.clone());
            assert!(resolve_entry(Path::new("/p"), DC, &read).is_err(), "{bad:?}");
        }
        let c = resolve_entry(Path::new("/p"), DC, &with(r#"{"image": "a", "workspaceFolder": "/workspaces/my app"}"#)).unwrap();
        assert_eq!(c.workspace_folder.as_deref(), Some("/workspaces/my app"));
    }

    #[test]
    fn a_build_never_reaches_outside_the_project() {
        for bad in [
            r#"{"build": {"dockerfile": "Dockerfile", "context": "../.."}}"#,
            r#"{"build": {"dockerfile": "Dockerfile", "context": "/home/dev"}}"#,
            r#"{"build": {"dockerfile": "../../x/Dockerfile"}}"#,
            r#"{"build": {"dockerfile": "/etc/Dockerfile"}}"#,
        ] {
            let read = move |_: &Path| Ok(bad.to_string());
            let err = resolve_entry(Path::new("/p"), DC, &read).unwrap_err();
            assert!(format!("{err:#}").contains("outside the project"), "{bad}: {err:#}");
        }
        // Positive control: up to the project root itself, and inside it.
        let c = resolve_entry(Path::new("/p"), DC, &with(r#"{"build": {"dockerfile": "../docker/Dockerfile", "context": "../docker"}}"#)).unwrap();
        assert_matches!(&c.source, ImageSource::Build { dockerfile, context, .. }
            if dockerfile == Path::new("/p/docker/Dockerfile") && context == Path::new("/p/docker"));
    }


    #[test]
    fn paths_overlap_when_one_is_the_other_or_inside_it() {
        for (a, b) in [("/opt", "/opt/ssai-agent"), ("/opt/ssai-agent", "/opt/ssai-agent"), ("/opt/ssai-agent/x", "/opt/ssai-agent"), ("/", "/opt")] {
            assert!(overlaps(a, b) && overlaps(b, a), "{a} {b}");
        }
        for (a, b) in [("/opt/ssai-agentx", "/opt/ssai-agent"), ("/home/vscode", "/opt/ssai-agent"), ("/op", "/opt")] {
            assert!(!overlaps(a, b) && !overlaps(b, a), "{a} {b}");
        }
    }

    #[test]
    fn a_build_takes_only_the_keys_it_knows_and_never_options() {
        for (bad, says) in [
            (r#"{"build": {"dockerfile": "D", "options": ["-v", "/home/dev:/h"]}}"#, "`options` is refused"),
            (r#"{"build": {"dockerfile": "D", "secrets": {}}}"#, "`secrets` is not a `build` key"),
        ] {
            let read = move |_: &Path| Ok(bad.to_string());
            let err = resolve_entry(Path::new("/p"), DC, &read).unwrap_err();
            assert!(format!("{err:#}").contains(says), "{bad}: {err:#}");
        }
        let c = resolve_entry(Path::new("/p"), DC, &with(r#"{"build": {"dockerfile": "D", "cacheFrom": "x", "target": "t"}}"#)).unwrap();
        assert!(c.notes.iter().any(|n| n.contains("`build.cacheFrom` is not used")), "{:?}", c.notes);
        // Built by the Dev Container CLI, which pulls it: said so, never "not used".
        let c = resolve_entry(
            Path::new("/p"),
            DC,
            &with(r#"{"build": {"dockerfile": "D", "cacheFrom": "x"}, "features": {"ghcr.io/devcontainers/features/node:1": {}}}"#),
        )
        .unwrap();
        assert!(c.has_features && !c.notes.iter().any(|n| n.contains("not used")), "{:?}", c.notes);
        assert!(c.notes.iter().any(|n| n.contains("`build.cacheFrom` is pulled by the Dev Container CLI")), "{:?}", c.notes);
    }

    #[test]
    fn a_devcontainer_image_is_checked_like_sandbox_jsons() {
        for bad in ["--tls-verify=false", "a b", "-x", "oci-archive:/home/dev/x.tar", "dir:/etc", "docker-archive:x.tar", "docker://dir:/home/dev", "docker://oci-archive:/x.tar"] {
            let dc = format!(r#"{{"image": {}}}"#, serde_json::to_string(bad).unwrap());
            let read = move |_: &Path| Ok(dc.clone());
            assert!(resolve_entry(Path::new("/p"), DC, &read).is_err(), "{bad:?}");
        }
        for good in ["ghcr.io/team/dev:1", "localhost:5000/dev:1", "docker://ghcr.io/team/dev", "dev@sha256:abc"] {
            let dc = format!(r#"{{"image": "{good}"}}"#);
            let read = move |_: &Path| Ok(dc.clone());
            assert!(resolve_entry(Path::new("/p"), DC, &read).is_ok(), "{good}");
        }
    }

    #[test]
    fn a_local_feature_is_refused_and_a_published_one_taken() {
        for local in ["./feat", "../x/feat", "/abs/feat", "~/feat"] {
            let dc = format!(r#"{{"image": "a", "features": {{"{local}": {{}}}}}}"#);
            let read = move |_: &Path| Ok(dc.clone());
            assert!(format!("{:#}", resolve_entry(Path::new("/p"), DC, &read).unwrap_err()).contains("local feature"), "{local}");
        }
        let c = resolve_entry(Path::new("/p"), DC, &with(r#"{"image": "a", "features": {"ghcr.io/devcontainers/features/node:1": {}}}"#)).unwrap();
        assert!(c.has_features);
    }

    #[test]
    fn initialize_command_beside_features_is_refused() {
        let both = r#"{"image": "a", "features": {"f:1": {}}, "initializeCommand": "x"}"#;
        assert!(format!("{:#}", resolve_entry(Path::new("/p"), DC, &with(both)).unwrap_err()).contains("initializeCommand"));
        // Without features it is noted, never run.
        let c = resolve_entry(Path::new("/p"), DC, &with(r#"{"image": "a", "initializeCommand": "x"}"#)).unwrap();
        assert!(c.notes.iter().any(|n| n.contains("`initializeCommand`")));
        // The CLI building features reads `${env:…}` from this machine, the shell's `${env:-x}` too.
        let env = r#"{"image": "a", "features": {"f:1": {}}, "postCreateCommand": "echo ${env:-dev}"}"#;
        assert!(format!("{:#}", resolve_entry(Path::new("/p"), DC, &with(env)).unwrap_err()).contains("beside `features`"));
        // Without features the shell's form is the shell's (the positive control).
        assert!(resolve_entry(Path::new("/p"), DC, &with(r#"{"image": "a", "postCreateCommand": "echo ${env:-dev}"}"#)).is_ok());
    }


    #[test]
    fn the_spec_variables_are_expanded_and_another_one_refused() {
        let dc = r#"{"image": "a", "workspaceFolder": "/workspaces/${localWorkspaceFolderBasename}",
            "remoteUser": "vscode"}"#;
        let c = resolve_entry(Path::new("/home/dev/my-app"), DC, &with(dc)).unwrap();
        assert_eq!(c.workspace_folder.as_deref(), Some("/workspaces/my-app"));
        assert_eq!(c.remote_user.as_deref(), Some("vscode"));
        let built = r#"{"build": {"dockerfile": "D", "args": {"W": "${containerWorkspaceFolder}", "H": "${localWorkspaceFolder}/x"}},
            "workspaceFolder": "/w"}"#;
        let c = resolve_entry(Path::new("/p"), DC, &with(built)).unwrap();
        assert_matches!(&c.source, ImageSource::Build { args, .. }
            if args == &[("H".to_string(), "/p/x".to_string()), ("W".to_string(), "/w".to_string())]);
        for bad in [
            r#"{"image": "a", "workspaceFolder": "/w/${devcontainerId}"}"#,
            r#"{"image": "a", "workspaceFolder": "/w/${containerWorkspaceFolder}"}"#,
            r#"{"image": "a", "remoteUser": "${localEnv"}"#,
            r#"{"image": "a", "remoteUser": "${localEnv:USER}"}"#,
            r#"{"build": {"dockerfile": "D", "args": {"T": "${localEnv:GITHUB_TOKEN}"}}}"#,
            r#"{"image": "a", "features": {"f:1": {"token": "${localEnv:GITHUB_TOKEN}"}}}"#,
            r#"{"image": "a", "features": {"f:1": {"token": "${env:GITHUB_TOKEN}"}}}"#,
        ] {
            let read = move |_: &Path| Ok(bad.to_string());
            assert!(resolve_entry(Path::new("/p"), DC, &read).is_err(), "{bad}");
        }
    }
}
