//! The docker tier's project configuration: `.streamscopeai/sandbox.json`,
//! and the `devcontainer.json` it may name. Pure — the caller reads the files.
//!
//! `sandbox.json` names the image one of two ways, exactly one of them:
//! `{ "image": "<ref>" }`, or `{ "devcontainer": "<path>" }` — a
//! `devcontainer.json` relative to the project root. Beside it: `docker`
//! (run an engine inside), and the limits `memory`, `cpus`, `pids`.
//!
//! A `devcontainer.json` key that would widen what the container reaches on
//! the host (`runArgs`, `mounts`, `privileged`, …) is refused by name, never
//! ignored: a project that relies on it would otherwise run without it and
//! fail later, somewhere less clear.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use serde_json::Value;

/// Where `sandbox.json` lives, under the project root.
pub const SANDBOX_FILE: &str = ".streamscopeai/sandbox.json";

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
    ("onCreateCommand", "does not run: install what the agent needs in the image"),
    ("updateContentCommand", "does not run: install what the agent needs in the image"),
    ("postCreateCommand", "does not run: install what the agent needs in the image"),
    ("postStartCommand", "does not run"),
    ("postAttachCommand", "does not run"),
    ("containerEnv", "is not applied: set the variable in the image"),
    ("remoteEnv", "is not applied: set the variable in the image"),
    ("overrideCommand", "is not applied: the sandbox starts the agent itself"),
    ("userEnvProbe", "is not applied"),
];

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
    /// One line per key read but not acted on, for the run to print.
    pub notes: Vec<String>,
}

/// Resolve `sandbox.json` (`text`) for the project at `root`, reading a
/// referenced `devcontainer.json` with `read`.
pub fn resolve(root: &Path, text: &str, read: &dyn Fn(&Path) -> Result<String>) -> Result<DockerConfig> {
    let file: SandboxFile = serde_json::from_str(text).with_context(|| format!("read {SANDBOX_FILE}"))?;
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
    if ["${localEnv:", "${env:"].iter().any(|v| text.contains(v)) {
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
    if obj.get("features").and_then(Value::as_object).is_some_and(|f| !f.is_empty()) {
        notes.push(format!(
            "{shown}: a feature's own container settings (`privileged`, its entrypoint, its mounts) are not applied — \
             use `\"docker\": true` in sandbox.json for an engine inside"
        ));
    }
    if obj.get("build").and_then(|b| b.get("cacheFrom")).is_some() {
        notes.push(format!("{shown}: `build.cacheFrom` is not used: the image builds without that cache"));
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
    let has_features = obj.get("features").and_then(Value::as_object).is_some_and(|f| !f.is_empty());
    // A local feature (a folder path) is copied into the build as it is,
    // symlinks and all: only published features (a registry reference) are taken.
    if let Some(local) = obj.get("features").and_then(Value::as_object).and_then(|f| {
        f.keys().find(|k| k.starts_with('.') || k.starts_with('/') || k.starts_with('~'))
    }) {
        bail!("{shown}: the local feature {local:?} is refused by the docker sandbox — publish it, or install it in a Dockerfile");
    }
    // With `features` the whole file goes to the Dev Container CLI, which may
    // run it on the host while it builds.
    if has_features && obj.contains_key("initializeCommand") {
        bail!("{shown}: `initializeCommand` is refused beside `features` — the Dev Container CLI that builds them could run it on the host");
    }
    Ok(DockerConfig {
        source,
        devcontainer: Some(path.to_path_buf()),
        has_features,
        remote_user: string("remoteUser")?.map(|u| expand_here(&u, "remoteUser")).transpose()?,
        container_user: string("containerUser")?.map(|u| expand_here(&u, "containerUser")).transpose()?,
        workspace_folder,
        docker,
        limits,
        notes,
    })
}

/// Paths of the container a project is never mounted over: the image's own
/// files, and the sandbox's mount points (`/run/ssai…`).
const SYSTEM_PATHS: &[&str] =
    &["/etc", "/run", "/proc", "/sys", "/dev", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/var/run", "/var/lib/docker"];

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
    let base = |p: &str| Path::new(p).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find("${") {
        out.push_str(&rest[..at]);
        let Some(end) = rest[at..].find('}') else { bail!("{text:?}: an unclosed `${{`") };
        let var = &rest[at + 2..at + end];
        let root_text = root.to_string_lossy();
        out.push_str(&match (var, workspace) {
            ("localWorkspaceFolder", _) => root_text.into_owned(),
            ("localWorkspaceFolderBasename", _) => base(&root_text),
            ("containerWorkspaceFolder", Some(w)) => w.to_string(),
            ("containerWorkspaceFolderBasename", Some(w)) => base(w),
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
        let c = resolve(Path::new("/p"), r#"{"image": " ghcr.io/team/dev:1 "}"#, &no_file).unwrap();
        assert_eq!(c.source, ImageSource::Image("ghcr.io/team/dev:1".into()));
        assert!(!c.docker && c.remote_user.is_none() && c.container_user.is_none() && c.workspace_folder.is_none() && c.notes.is_empty());
        assert_eq!(c.limits, Limits { memory: None, cpus: None, pids: DEFAULT_PIDS });
    }

    #[test]
    fn exactly_one_image_source_is_required() {
        for text in [r#"{}"#, r#"{"image": "a", "devcontainer": "b"}"#, r#"{"image": ""}"#, r#"{"image": "-v"}"#, r#"{"image": "a b"}"#] {
            assert!(resolve(Path::new("/p"), text, &no_file).is_err(), "{text}");
        }
        // An unknown key is a typo, not a setting: refused.
        assert!(resolve(Path::new("/p"), r#"{"image": "a", "dockre": true}"#, &no_file).is_err());
    }

    #[test]
    fn the_limits_are_read_and_their_bounds_held() {
        let ok = resolve(Path::new("/p"), r#"{"image": "a", "memory": "6g", "cpus": 3, "pids": 64}"#, &no_file).unwrap();
        assert_eq!(ok.limits, Limits { memory: Some("6g".into()), cpus: Some(3.0), pids: 64 });
        for bad in [r#""memory": "6 g""#, r#""memory": "g""#, r#""memory": "-1""#, r#""cpus": 0"#, r#""cpus": -1"#, r#""pids": 63"#] {
            let text = format!(r#"{{"image": "a", {bad}}}"#);
            assert!(resolve(Path::new("/p"), &text, &no_file).is_err(), "{text}");
        }
    }

    #[test]
    fn a_devcontainer_path_stays_inside_the_project() {
        for rel in ["/etc/dc.json", "../dc.json", "a/../../dc.json", ""] {
            let text = format!(r#"{{"devcontainer": {rel:?}}}"#);
            assert!(resolve(Path::new("/p"), &text, &no_file).is_err(), "{rel}");
        }
    }

    #[test]
    fn a_devcontainer_is_read_as_jsonc_with_its_user_and_folder() {
        let c = resolve(
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
        let c = resolve(Path::new("/p"), DC, &with(r#"{"image": "a", "containerUser": "dev"}"#)).unwrap();
        assert_eq!((c.remote_user.as_deref(), c.container_user.as_deref()), (None, Some("dev")));
    }

    #[test]
    fn a_build_resolves_against_the_devcontainer_dir() {
        let c = resolve(
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
            assert!(resolve(Path::new("/p"), DC, &read).is_err(), "{bad}");
        }
    }

    #[test]
    fn every_widening_key_is_refused_by_name() {
        for (key, _) in REFUSED_KEYS {
            let text = format!(r#"{{"image": "a", "{key}": []}}"#);
            let read = move |_: &Path| Ok(text.clone());
            let err = format!("{:#}", resolve(Path::new("/p"), DC, &read).unwrap_err());
            assert!(err.contains(&format!("`{key}`")), "{err}");
        }
        // Positive control: the same file without it resolves.
        assert!(resolve(Path::new("/p"), DC, &with(r#"{"image": "a"}"#)).is_ok());
    }

    #[test]
    fn a_key_acted_on_elsewhere_is_named_in_a_note() {
        let c = resolve(Path::new("/p"), DC, &with(r#"{"image": "a", "forwardPorts": [3000], "initializeCommand": "x"}"#)).unwrap();
        assert_eq!(c.notes.len(), 2, "{:?}", c.notes);
        assert!(c.notes.iter().any(|n| n.contains("`forwardPorts`")) && c.notes.iter().any(|n| n.contains("`initializeCommand`")));
    }

    #[test]
    fn a_relative_workspace_folder_is_refused() {
        assert!(resolve(Path::new("/p"), DC, &with(r#"{"image": "a", "workspaceFolder": "app"}"#)).is_err());
    }

    #[test]
    fn a_workspace_folder_is_never_a_system_path() {
        for bad in ["/", "/etc", "/etc/app", "/run", "/run/ssai-sock", "/usr/src/app", "/proc/x", "/var/lib/docker/app", "/var", "/var/lib"] {
            let dc = format!(r#"{{"image": "a", "workspaceFolder": "{bad}"}}"#);
            let read = move |_: &Path| Ok(dc.clone());
            assert!(resolve(Path::new("/p"), DC, &read).is_err(), "{bad}");
        }
        // Positive control: the usual places, and a name that only starts like one.
        for good in ["/workspaces/app", "/srv/app", "/home/dev/app", "/etcetera"] {
            let dc = format!(r#"{{"image": "a", "workspaceFolder": "{good}"}}"#);
            let read = move |_: &Path| Ok(dc.clone());
            assert!(resolve(Path::new("/p"), DC, &read).is_ok(), "{good}");
        }
    }

    #[test]
    fn a_workspace_folder_cannot_carry_volume_options() {
        for bad in ["/w:U", "/w:ro", "/w,z", "/w/../etc", "/w\nx"] {
            let dc = format!(r#"{{"image": "a", "workspaceFolder": {}}}"#, serde_json::to_string(bad).unwrap());
            let read = move |_: &Path| Ok(dc.clone());
            assert!(resolve(Path::new("/p"), DC, &read).is_err(), "{bad:?}");
        }
        let c = resolve(Path::new("/p"), DC, &with(r#"{"image": "a", "workspaceFolder": "/workspaces/my app"}"#)).unwrap();
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
            let err = resolve(Path::new("/p"), DC, &read).unwrap_err();
            assert!(format!("{err:#}").contains("outside the project"), "{bad}: {err:#}");
        }
        // Positive control: up to the project root itself, and inside it.
        let c = resolve(Path::new("/p"), DC, &with(r#"{"build": {"dockerfile": "../docker/Dockerfile", "context": "../docker"}}"#)).unwrap();
        assert_matches!(&c.source, ImageSource::Build { dockerfile, context, .. }
            if dockerfile == Path::new("/p/docker/Dockerfile") && context == Path::new("/p/docker"));
    }


    #[test]
    fn a_build_takes_only_the_keys_it_knows_and_never_options() {
        for (bad, says) in [
            (r#"{"build": {"dockerfile": "D", "options": ["-v", "/home/dev:/h"]}}"#, "`options` is refused"),
            (r#"{"build": {"dockerfile": "D", "secrets": {}}}"#, "`secrets` is not a `build` key"),
        ] {
            let read = move |_: &Path| Ok(bad.to_string());
            let err = resolve(Path::new("/p"), DC, &read).unwrap_err();
            assert!(format!("{err:#}").contains(says), "{bad}: {err:#}");
        }
        let c = resolve(Path::new("/p"), DC, &with(r#"{"build": {"dockerfile": "D", "cacheFrom": "x", "target": "t"}}"#)).unwrap();
        assert!(c.notes.iter().any(|n| n.contains("`build.cacheFrom` is not used")), "{:?}", c.notes);
    }

    #[test]
    fn a_devcontainer_image_is_checked_like_sandbox_jsons() {
        for bad in ["--tls-verify=false", "a b", "-x", "oci-archive:/home/dev/x.tar", "dir:/etc", "docker-archive:x.tar", "docker://dir:/home/dev", "docker://oci-archive:/x.tar"] {
            let dc = format!(r#"{{"image": {}}}"#, serde_json::to_string(bad).unwrap());
            let read = move |_: &Path| Ok(dc.clone());
            assert!(resolve(Path::new("/p"), DC, &read).is_err(), "{bad:?}");
        }
        for good in ["ghcr.io/team/dev:1", "localhost:5000/dev:1", "docker://ghcr.io/team/dev", "dev@sha256:abc"] {
            let dc = format!(r#"{{"image": "{good}"}}"#);
            let read = move |_: &Path| Ok(dc.clone());
            assert!(resolve(Path::new("/p"), DC, &read).is_ok(), "{good}");
        }
    }

    #[test]
    fn a_local_feature_is_refused_and_a_published_one_taken() {
        for local in ["./feat", "../x/feat", "/abs/feat", "~/feat"] {
            let dc = format!(r#"{{"image": "a", "features": {{"{local}": {{}}}}}}"#);
            let read = move |_: &Path| Ok(dc.clone());
            assert!(format!("{:#}", resolve(Path::new("/p"), DC, &read).unwrap_err()).contains("local feature"), "{local}");
        }
        let c = resolve(Path::new("/p"), DC, &with(r#"{"image": "a", "features": {"ghcr.io/devcontainers/features/node:1": {}}}"#)).unwrap();
        assert!(c.has_features);
    }

    #[test]
    fn initialize_command_beside_features_is_refused() {
        let both = r#"{"image": "a", "features": {"f:1": {}}, "initializeCommand": "x"}"#;
        assert!(format!("{:#}", resolve(Path::new("/p"), DC, &with(both)).unwrap_err()).contains("initializeCommand"));
        // Without features it is noted, never run.
        let c = resolve(Path::new("/p"), DC, &with(r#"{"image": "a", "initializeCommand": "x"}"#)).unwrap();
        assert!(c.notes.iter().any(|n| n.contains("`initializeCommand`")));
    }


    #[test]
    fn the_spec_variables_are_expanded_and_another_one_refused() {
        let dc = r#"{"image": "a", "workspaceFolder": "/workspaces/${localWorkspaceFolderBasename}",
            "remoteUser": "vscode"}"#;
        let c = resolve(Path::new("/home/dev/my-app"), DC, &with(dc)).unwrap();
        assert_eq!(c.workspace_folder.as_deref(), Some("/workspaces/my-app"));
        assert_eq!(c.remote_user.as_deref(), Some("vscode"));
        let built = r#"{"build": {"dockerfile": "D", "args": {"W": "${containerWorkspaceFolder}", "H": "${localWorkspaceFolder}/x"}},
            "workspaceFolder": "/w"}"#;
        let c = resolve(Path::new("/p"), DC, &with(built)).unwrap();
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
            assert!(resolve(Path::new("/p"), DC, &read).is_err(), "{bad}");
        }
    }
}
