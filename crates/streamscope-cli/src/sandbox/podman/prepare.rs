//! The docker tier's prepare phase: the project's image (pulled, or built
//! from its Dockerfile or `devcontainer.json`), the agent layer on top of it,
//! and the agent user's ids. Runs with the network open, and with nothing of
//! the project's but its build context: no gateway key, no secrets.
//!
//! Every step is cached: the base by its reference (a build: by the hash of
//! what it is built from), the agent layer by the base's id, the user's ids by
//! (base id, user). `ssai sandbox prepare` rebuilds both images.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

use super::config::{DockerConfig, ImageSource, Lifecycle};
use super::images::{self, Record};

/// The label naming the base image an agent layer was built on.
pub const BASE_LABEL: &str = "ai.streamscope.sandbox-base";

/// What a run needs from the prepared images.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prepared {
    /// The image the run starts (the agent layer, or the base without one).
    pub image: String,
    pub user: AgentUser,
    /// The image's own environment (`ENV`), which the agent inherits.
    pub env: Vec<(String, String)>,
    /// The container's root for that user, as the sweep sees it.
    pub container_root: super::sweep::Root,
    /// The base image's id: what the create commands last ran on.
    pub base: String,
    /// The lifecycle commands and environment: the image's metadata, then
    /// the project's.
    pub lifecycle: Lifecycle,
}

/// The agent user inside the image.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AgentUser {
    pub uid: u32,
    pub gid: u32,
    pub home: String,
}

/// Prepare the images for `client` (its launch command `command`, its npm
/// package `npm`). `force`: rebuild what is cached.
pub fn prepare(root: &Path, config: &DockerConfig, command: &str, npm: Option<&str>, force: bool) -> Result<Prepared> {
    let base = base_image(root, config, force)?;
    let base_id = inspect(&base, "{{.Id}}")?;
    // A prebuilt Dev Container image names its user in its metadata label
    // rather than in `USER` (which stays root for its build steps). As the Dev
    // Container merge has it: a `remoteUser` (the project's, then the image's)
    // before a `containerUser` (the same), then `USER`.
    let entries = metadata_entries(&inspect(&base, "{{index .Config.Labels \"devcontainer.metadata\"}}")?);
    let (meta_remote, meta_container) = metadata_users(&entries);
    let user = match [&config.remote_user, &meta_remote, &config.container_user, &meta_container].into_iter().flatten().next() {
        Some(u) => u.clone(),
        None => inspect(&base, "{{.Config.User}}")?,
    };
    // No user named: the image's root, by id (a name needs a passwd to read).
    let user = agent_user(&base_id, if user.is_empty() { "0" } else { &user })?;
    // The home (a volume) or the project over the prefix a client is
    // installed in would hide it, and every later install there. Refused
    // before the client is installed.
    if npm.is_some() {
        let workspace = super::workspace(config, root);
        let fixes = [
            ("the agent's home", &user.home, "run as another image user (`remoteUser` / `containerUser`) or use another image"),
            ("the workspace path", &workspace, "set a `workspaceFolder` elsewhere"),
        ];
        for (what, path, fix) in fixes {
            if super::config::overlaps(path, AGENT_PREFIX) {
                bail!("{what} {path} overlaps {AGENT_PREFIX}, where the sandbox installs {command} — {fix}");
            }
        }
    }
    let workspace = super::workspace(config, root);
    // The image's own entries first. One this parser cannot read is the
    // image's, which the developer cannot fix: skipped whole, and said. An
    // image built here with `features` carries, as its own entry, only what
    // its build was given ([`features_recipe`]): the project's commands and
    // variables come from the project's file.
    let lifecycle = label_lifecycle(&entries, &|text| super::config::expand_lenient(text, root, &workspace), &|i, e| {
        eprintln!("ssai: entry {i} of the image {}'s devcontainer.metadata is skipped — {e:#}", config.source_name())
    })
    .then(config.lifecycle.clone());
    let image = if npm.is_some() || config.docker { agent_layer(&base_id, npm, config.docker, force)? } else { base_id.clone() };
    let env = image_env(&inspect(&image, "{{json .Config.Env}}")?);
    let container_root = super::sweep::Root::for_agent(user.uid, user.gid);
    Ok(Prepared { image, user, env, container_root, base: base_id, lifecycle })
}

/// An engine inside makes the container privileged: `"docker": true` that
/// was off at the project's last run (the agent can edit `sandbox.json`) is
/// taken only after `ssai sandbox prepare`.
fn engine_turned_on(before: Option<&Record>, engine: bool, force: bool) -> Result<()> {
    if !force && engine && before.is_some_and(|b| !b.engine) {
        bail!(
            "an engine inside (`\"docker\": true` in sandbox.json, or in your organisation's default image) is new \
             since the project's last run (an engine runs privileged) — check it, then run \
             `ssai sandbox prepare <client>`"
        );
    }
    Ok(())
}

/// An image source (a reference, or a recipe: Dockerfile, devcontainer.json)
/// that changed since the project's last run is not pulled or built on its
/// own: the agent can edit all of them, and a pull or a build runs with the
/// network open before any guard. `ssai sandbox prepare` (`force`) does it
/// after the developer has read the change; a project's first one needs no
/// such step.
fn changed_since_last_build(before: Option<&Record>, source: &str, force: bool) -> Result<()> {
    if !force && before.is_some_and(|b| b.source != source) {
        bail!(
            "the image (its reference — sandbox.json's or your organisation's default —, Dockerfile or \
             devcontainer.json) changed since the last run — read the change, then rebuild with \
             `ssai sandbox prepare <client>`"
        );
    }
    Ok(())
}

/// A build runs what its recipe and its context hold — files the agent can
/// edit, the context possibly the whole project — with the network open
/// before any guard. Only a project's first image is built on a run; every
/// later build (a changed recipe, or an image removed since) waits for `ssai
/// sandbox prepare` (`force`), after the developer has read what it builds.
fn rebuild_needs_prepare(before: Option<&Record>, force: bool) -> Result<()> {
    if !force && before.is_some() {
        bail!(
            "the project's image needs a rebuild (its Dockerfile, devcontainer.json or build context may have \
             changed) — read them, then rebuild with `ssai sandbox prepare <client>`"
        );
    }
    Ok(())
}

/// `path`, resolved through every symlink, is still inside the project:
/// `sandbox.json`'s check is on the text, and a symlink in the project could
/// point a build at the developer's home, sent with the network open.
fn confined(root: &Path, path: &Path, key: &str) -> Result<()> {
    let root = root.canonicalize().with_context(|| format!("resolve {}", root.display()))?;
    let real = path.canonicalize().with_context(|| format!("the build's `{key}` {}", path.display()))?;
    if !real.starts_with(&root) {
        bail!("the build's `{key}` {} leads outside the project (to {}) — the image is built from the project only", path.display(), real.display());
    }
    Ok(())
}

/// The entries of a `devcontainer.metadata` label: a JSON array of them (a
/// later one overriding an earlier), or one entry on its own.
fn metadata_entries(label: &str) -> Vec<serde_json::Value> {
    match serde_json::from_str::<serde_json::Value>(label.trim()) {
        Ok(serde_json::Value::Array(entries)) => entries,
        Ok(one @ serde_json::Value::Object(_)) => vec![one],
        _ => Vec::new(),
    }
}

/// The lifecycle of an image's metadata entries: the variables of every
/// entry, the commands of a feature's only (an entry with an `id`). An entry
/// without one is the `devcontainer.json` an image was built from: its
/// commands are named as not run. One this parser cannot read is passed to
/// `skipped` and left out.
fn label_lifecycle(
    entries: &[serde_json::Value],
    expand: &dyn Fn(&str) -> Result<String>,
    skipped: &dyn Fn(usize, anyhow::Error),
) -> Lifecycle {
    let mut lifecycle = Lifecycle::default();
    for (i, entry) in entries.iter().enumerate() {
        let theirs = entry.as_object().context("not an object").and_then(|entry| {
            let theirs = super::config::lifecycle_of(entry, &|key, text| expand(text).with_context(|| format!("`{key}`")))?;
            if entry.contains_key("id") || (theirs.create.is_empty() && theirs.start.is_empty()) {
                return Ok(theirs);
            }
            let hooks: Vec<&str> = theirs.create.iter().chain(&theirs.start).map(|s| s.hook.as_str()).collect();
            eprintln!("ssai: the image's own devcontainer.json commands ({}) are not run — only its features' are", hooks.join(", "));
            Ok(theirs.env_only())
        });
        match theirs {
            Ok(theirs) => lifecycle = lifecycle.then(theirs),
            Err(e) => skipped(i, e),
        }
    }
    lifecycle
}

/// The users metadata entries name: the last `remoteUser` and the last
/// `containerUser`.
fn metadata_users(entries: &[serde_json::Value]) -> (Option<String>, Option<String>) {
    let last = |key: &str| entries.iter().rev().find_map(|e| e.get(key)?.as_str().filter(|u| !u.is_empty()).map(str::to_string));
    (last("remoteUser"), last("containerUser"))
}

/// The base image's reference, pulled or built when absent (or `force`). The
/// record names the image once it is there; an image the sandbox's pull added
/// is marked as the sandbox's, for `ssai sandbox prune`. A run removes no
/// image: disk is freed on the developer's request (`images`).
fn base_image(root: &Path, config: &DockerConfig, force: bool) -> Result<String> {
    let before = images::read(root)?;
    let before = before.as_ref();
    engine_turned_on(before, config.docker, force)?;
    if let ImageSource::Build { context, dockerfile, .. } = &config.source {
        confined(root, dockerfile, "dockerfile")?;
        confined(root, context, "context")?;
    }
    let record = |source: &str| Record { source: source.to_string(), engine: config.docker, project: None };
    // A build under the tag `tag`, when absent or `force`.
    let build = |tag: &str, run: &dyn Fn() -> Result<()>| -> Result<()> {
        if force || !exists(tag)? {
            rebuild_needs_prepare(before, force)?;
            run()?;
        }
        images::write(root, &record(tag))
    };
    // `features` apply to an `image` and a `build` alike, and only the
    // devcontainer CLI applies them.
    if config.features.is_some() {
        let tag = format!("{}{}", images::BUILD_PREFIX, build_hash(root, config)?);
        build(&tag, &|| build_with_devcontainer_cli(root, config, &tag))?;
        return Ok(tag);
    }
    match &config.source {
        ImageSource::Image(reference) => {
            // A pull reaches the registry it names from this machine's network,
            // before any guard: a reference changed since the last run (the
            // agent can edit it) is pulled only after a `prepare`.
            let source = format!("image:{reference}");
            let now = record(&source);
            let old = if exists(reference)? { Some(inspect(reference, "{{.Id}}")?) } else { None };
            // A `localhost/` image exists only on this machine: no registry
            // serves it, so a `prepare` uses it as it is.
            if !((force && !local_only(reference)) || old.is_none()) {
                images::write(root, &now)?;
                return Ok(reference.clone());
            }
            changed_since_last_build(before, &source, force)?;
            eprintln!("ssai: pulling {reference} for the docker sandbox");
            podman(&["pull", reference]).with_context(|| format!("pull {reference}"))?;
            images::write(root, &now)?;
            // The sandbox made the image when its pull added it — or brought a
            // new id under a name an earlier pull of its own added; never under
            // a name the developer had.
            if old.as_deref().is_none_or(images::pulled_by_sandbox) {
                images::mark_pulled(&inspect(reference, "{{.Id}}")?);
            }
            Ok(reference.clone())
        }
        ImageSource::Build { context, dockerfile, target, args } => {
            let tag = format!("{}{}", images::BUILD_PREFIX, build_hash(root, config)?);
            build(&tag, &|| {
                eprintln!("ssai: building {} for the docker sandbox", dockerfile.display());
                let mut a: Vec<String> = vec![
                    "build".into(),
                    "-t".into(),
                    tag.clone(),
                    "--label".into(),
                    format!("{BASE_LABEL}=project"),
                    "-f".into(),
                    path(dockerfile),
                ];
                if let Some(t) = target {
                    a.extend(["--target".into(), t.clone()]);
                }
                for (k, v) in args {
                    a.extend(["--build-arg".into(), format!("{k}={v}")]);
                }
                a.push(path(context));
                podman(&a.iter().map(String::as_str).collect::<Vec<_>>()).context("build the project's image")
            })?;
            Ok(tag)
        }
    }
}

/// What the Dev Container CLI builds an image with `features` from: a copy of
/// the project's `devcontainer.json` holding only what its build reads — the
/// image or the build (its paths absolute, its variables expanded), the
/// features and their order, the users (a feature's install scripts get them)
/// and the workspace path (a feature option may name it). A lifecycle command
/// or a variable is not in it: they are the project's file's, read at each
/// run, and their change rebuilds nothing.
fn features_recipe(config: &DockerConfig) -> serde_json::Value {
    use serde_json::Value;
    let mut recipe = config.features.clone().unwrap_or_default();
    let cache_from = recipe.remove("cacheFrom");
    match &config.source {
        ImageSource::Image(reference) => {
            recipe.insert("image".into(), Value::String(reference.clone()));
        }
        ImageSource::Build { context, dockerfile, target, args } => {
            let mut build = serde_json::Map::new();
            build.insert("dockerfile".into(), Value::String(path(dockerfile)));
            build.insert("context".into(), Value::String(path(context)));
            if let Some(t) = target {
                build.insert("target".into(), Value::String(t.clone()));
            }
            if !args.is_empty() {
                build.insert("args".into(), args.iter().map(|(k, v)| (k.clone(), Value::String(v.clone()))).collect());
            }
            if let Some(c) = cache_from {
                build.insert("cacheFrom".into(), c);
            }
            recipe.insert("build".into(), Value::Object(build));
        }
    }
    for (key, value) in [
        ("remoteUser", &config.remote_user),
        ("containerUser", &config.container_user),
        ("workspaceFolder", &config.workspace_folder),
    ] {
        if let Some(v) = value {
            recipe.insert(key.into(), Value::String(v.clone()));
        }
    }
    Value::Object(recipe)
}

/// The project's feature lockfile, which pins the features' versions — where
/// the Dev Container CLI looks for it beside `dc` — when there is one.
fn feature_lockfile(dc: &Path) -> Result<Option<Vec<u8>>> {
    let hidden = dc.file_name().is_some_and(|n| n.as_encoded_bytes().starts_with(b"."));
    let lock = dc.with_file_name(if hidden { ".devcontainer-lock.json" } else { "devcontainer-lock.json" });
    match std::fs::read(&lock) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("read {}", lock.display())),
    }
}

/// An image whose `devcontainer.json` has `features` is built by the
/// devcontainer CLI, driving podman, from [`features_recipe`] in a private
/// directory of its own (the project's lockfile beside it); without the CLI,
/// refused naming the install.
fn build_with_devcontainer_cli(root: &Path, config: &DockerConfig, tag: &str) -> Result<()> {
    let Some(dc) = &config.devcontainer else { bail!("features without a devcontainer.json") };
    eprintln!("ssai: building {} (with its features) for the docker sandbox", dc.display());
    let dir = private_build_dir("features")?;
    let built = (|| {
        let copy = dir.join("devcontainer.json");
        std::fs::write(&copy, serde_json::to_vec_pretty(&features_recipe(config))?).context("write the features build's devcontainer.json")?;
        if let Some(lock) = feature_lockfile(dc)? {
            std::fs::write(dir.join("devcontainer-lock.json"), lock).context("copy the features' lockfile")?;
        }
        let status = Command::new("devcontainer")
            .args(["build", "--docker-path", "podman", "--workspace-folder"])
            .arg(root)
            .arg("--config")
            .arg(&copy)
            .args(["--image-name", tag, "--label", &format!("{BASE_LABEL}=project")])
            .stdin(Stdio::null())
            .status();
        match status {
            Ok(s) if s.success() => Ok(()),
            Ok(s) => bail!("the devcontainer CLI could not build {} ({s})", dc.display()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => bail!(
                "{} uses `features`, which only the devcontainer CLI builds — install it \
                 (`npm install -g @devcontainers/cli`), or drop the features and install them in the Dockerfile",
                dc.display()
            ),
            Err(e) => Err(e).context("run the devcontainer CLI"),
        }
    })();
    let _ = std::fs::remove_dir_all(&dir);
    built
}

/// A new private directory under the sandbox's build dir (`what-<pid>-<rand>`),
/// never one that already exists.
fn private_build_dir(what: &str) -> Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    let parent = crate::state::cache_dir()?.join("sandbox-build");
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&parent).with_context(|| format!("create {}", parent.display()))?;
    let dir = parent.join(format!("{what}-{}-{}", std::process::id(), hex::encode(rand::random::<[u8; 6]>())));
    std::fs::DirBuilder::new().mode(0o700).create(&dir).with_context(|| format!("create {}", dir.display()))?;
    Ok(dir)
}

/// What a build is built from (the context's other files are not followed —
/// `ssai sandbox prepare` rebuilds after a change to them): the Dockerfile's
/// text, its context, target and args; with `features`, [`features_recipe`]
/// and the features' lockfile too. A change to a lifecycle command or the
/// environment needs no rebuild.
fn build_hash(root: &Path, config: &DockerConfig) -> Result<String> {
    let mut h = Sha256::new();
    h.update(root.as_os_str().as_encoded_bytes());
    // Each part length-prefixed: no two recipes hash alike.
    let mut part = |b: &[u8]| {
        h.update((b.len() as u64).to_le_bytes());
        h.update(b);
    };
    if config.features.is_some() {
        part(&serde_json::to_vec(&features_recipe(config))?);
        let lock = match &config.devcontainer {
            Some(dc) => feature_lockfile(dc)?,
            None => None,
        };
        part(lock.as_deref().unwrap_or(b"\0"));
    }
    if let ImageSource::Build { dockerfile, context, target, args } = &config.source {
        part(&std::fs::read(dockerfile).with_context(|| format!("read {}", dockerfile.display()))?);
        part(dockerfile.as_os_str().as_encoded_bytes());
        part(context.as_os_str().as_encoded_bytes());
        part(target.as_deref().unwrap_or("\0").as_bytes());
        for (k, v) in args {
            part(k.as_bytes());
            part(v.as_bytes());
        }
    }
    Ok(hex::encode(&h.finalize()[..12]))
}

/// The agent layer on the base: Docker Engine when `engine` and the image
/// has none, and the client `npm` (with the Node runtime it runs on); tagged
/// by the base's id and the recipe, built when absent (or `force`).
fn agent_layer(base_id: &str, npm: Option<&str>, engine: bool, force: bool) -> Result<String> {
    let node = match npm {
        Some(_) => Some(NodeDist::for_image(base_id)?),
        None => None,
    };
    let recipe = layer_dockerfile(base_id, npm.zip(node.as_ref()), engine);
    let tag = layer_tag(npm, engine, base_id, &recipe);
    if !force && exists(&tag)? {
        return Ok(tag);
    }
    let what: Vec<&str> = [engine.then_some("Docker Engine (when the image has none)"), npm].into_iter().flatten().collect();
    eprintln!("ssai: installing {} into the docker sandbox's image", what.join(" and "));
    // An empty, private context (the Dockerfile comes on stdin): created
    // new, never one that already exists. It holds only the Node archive.
    let context = private_build_dir("layer")?;
    let built = (|| {
        if let Some(node) = &node {
            let archive = node.fetch()?;
            std::fs::copy(&archive, context.join(node.file())).context("put the Node archive in the build context")?;
        }
        // A forced rebuild skips the layer cache, or the cached `npm install`
        // step would keep the release it installed last time.
        let mut child = Command::new("podman")
            .args(["build", "-t", &tag, "--label", &format!("{BASE_LABEL}={base_id}"), "-f", "-"])
            .args(force.then_some("--no-cache"))
            .arg(&context)
            .stdin(Stdio::piped())
            .spawn()
            .context("run podman build")?;
        // A podman that stops before reading its Dockerfile is still waited
        // on, and its own status is the one reported.
        let written = child
            .stdin
            .take()
            .context("podman build stdin")
            .and_then(|mut s| Ok(std::io::Write::write_all(&mut s, recipe.as_bytes())?));
        let status = child.wait()?;
        if !status.success() {
            bail!("could not install {} into the image ({status})", what.join(" and "));
        }
        written
    })();
    let _ = std::fs::remove_dir_all(&context);
    built.map(|()| tag)
}

/// `localhost/ssai-agent-<name>:<base id, 12 hex>-<recipe, 8 hex>`: named
/// by the package (`engine` without one; `<package>-with-engine` with both),
/// which `run` and `sandbox prepare` resolve alike whatever name the client
/// is launched by; the recipe is in the tag, so a layer an earlier `ssai`
/// built another way is never taken for this one. A layer with an engine and
/// one without are two repositories: two projects on one base, one with an
/// engine, keep a layer each.
fn layer_tag(package: Option<&str>, engine: bool, base_id: &str, recipe: &str) -> String {
    let name: String = package
        .unwrap_or("engine")
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' })
        .collect();
    // A reference component may not start or end with a separator.
    let name = name.trim_matches('-');
    let name = if package.is_some() && engine { format!("{name}-with-engine") } else { name.to_string() };
    let id = base_id.trim_start_matches("sha256:");
    let recipe = hex::encode(Sha256::digest(recipe.as_bytes()));
    format!("{}{name}:{}-{}", images::LAYER_PREFIX, &id[..id.len().min(12)], &recipe[..8])
}

/// Where the agent layer installs the client, first on the agent's `PATH`.
/// Never the image's own npm prefix: that may lie under the agent's home,
/// which the home volume covers from the first run on, hiding every later
/// install there.
pub const AGENT_PREFIX: &str = "/opt/ssai-agent";

/// The Node release the clients run on — the layer's own, beside the image's
/// (if any), which the project keeps. Pinned with each archive's SHA-256, as
/// the publisher lists it; the musl builds are the publisher's unofficial
/// ones.
const NODE_VERSION: &str = "v24.22.3";
const NODE_ARCHIVES: [(&str, &str, &str); 4] = [
    ("x64", "", "061ec3e3062115705b56b51fa9cc330ab50d34b6969387d4e4b1a50c6809acc2"),
    ("arm64", "", "261af2af250dfd7e9f25cf151d1b2713a0adf8f10a9ad116c4947f68627affe8"),
    ("x64", "-musl", "2db4f8a40abe5f5b5d119964223fedc9c4c7c5e7c632901ae860af522c7844b2"),
    ("arm64", "-musl", "248c96a84f6c8338646b9fd73bf125124678f8fb08db5f23023f462055e0eedc"),
];
/// The largest archive accepted (they are ~30 MB).
const NODE_ARCHIVE_CAP: usize = 128 << 20;

/// The Node archive for one image: this machine's architecture, the image's
/// C library.
#[derive(Debug, Clone, PartialEq, Eq)]
struct NodeDist {
    arch: &'static str,
    libc: &'static str,
    sha256: &'static str,
}

impl NodeDist {
    fn new(arch: &str, musl: bool) -> Result<Self> {
        let arch = match arch {
            "x86_64" => "x64",
            "aarch64" => "arm64",
            other => bail!("the docker sandbox has no Node runtime for {other} — run the client with another sandbox"),
        };
        let libc = if musl { "-musl" } else { "" };
        let (arch, libc, sha256) =
            NODE_ARCHIVES.iter().copied().find(|(a, l, _)| *a == arch && *l == libc).context("no pinned Node archive")?;
        Ok(Self { arch, libc, sha256 })
    }

    fn for_image(base_id: &str) -> Result<Self> {
        Self::new(std::env::consts::ARCH, image_is_musl(base_id)?)
    }

    /// `node-v…-linux-x64[-musl]`: the archive's top directory.
    fn dir(&self) -> String {
        format!("node-{NODE_VERSION}-linux-{}{}", self.arch, self.libc)
    }

    fn file(&self) -> String {
        format!("{}.tar.gz", self.dir())
    }

    fn url(&self) -> String {
        let host = if self.libc.is_empty() { "https://nodejs.org/dist" } else { "https://unofficial-builds.nodejs.org/download/release" };
        format!("{host}/{NODE_VERSION}/{}", self.file())
    }

    /// The archive, from this machine's cache or downloaded into it; its
    /// checksum verified either way.
    fn fetch(&self) -> Result<PathBuf> {
        let dir = crate::state::cache_dir()?.join("sandbox-node");
        std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        let path = dir.join(self.file());
        if let Ok(bytes) = std::fs::read(&path)
            && hex::encode(Sha256::digest(&bytes)) == self.sha256
        {
            return Ok(path);
        }
        eprintln!("ssai: downloading Node {NODE_VERSION} for the docker sandbox ({})", self.url());
        let url = self.url();
        let bytes = std::thread::spawn(move || -> Result<Vec<u8>> {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
            rt.block_on(async {
                let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(300)).build()?;
                let mut resp = client.get(&url).send().await?.error_for_status()?;
                let mut body = Vec::new();
                while let Some(chunk) = resp.chunk().await? {
                    if body.len() + chunk.len() > NODE_ARCHIVE_CAP {
                        bail!("{url} is larger than any Node archive");
                    }
                    body.extend_from_slice(&chunk);
                }
                Ok(body)
            })
        })
        .join()
        .map_err(|_| anyhow::anyhow!("the Node download stopped"))?
        .with_context(|| format!("download {}", self.url()))?;
        let got = hex::encode(Sha256::digest(&bytes));
        if got != self.sha256 {
            bail!("{} does not match its pinned checksum (got {got}) — not used", self.url());
        }
        let part = dir.join(format!("{}.part-{}", self.file(), std::process::id()));
        std::fs::write(&part, &bytes).with_context(|| format!("write {}", part.display()))?;
        std::fs::rename(&part, &path).with_context(|| format!("write {}", path.display()))?;
        Ok(path)
    }
}

/// Whether the image's C library is musl (Alpine and the like), probed once
/// per base id: an image never changes under its id.
fn image_is_musl(base_id: &str) -> Result<bool> {
    let cache = musl_cache(base_id);
    if let Some(path) = &cache
        && let Ok(text) = std::fs::read_to_string(path)
    {
        match text.trim() {
            "musl" => return Ok(true),
            "glibc" => return Ok(false),
            _ => {}
        }
    }
    let Some(musl) = probe_musl(base_id)? else { return Ok(false) };
    if let Some(path) = &cache {
        let _ = std::fs::create_dir_all(path.parent().unwrap_or(Path::new(".")));
        let _ = std::fs::write(path, if musl { "musl" } else { "glibc" });
    }
    Ok(musl)
}

fn musl_cache(base_id: &str) -> Option<PathBuf> {
    let id = hex::encode(&Sha256::digest(base_id.as_bytes())[..12]);
    Some(crate::state::cache_dir().ok()?.join("sandbox-libc").join(id))
}

/// `Some(true)` for musl, `Some(false)` for any other C library; `None` when
/// the probe did not answer (podman failed, no shell) — not cached, read as
/// glibc for this run only.
fn probe_musl(base_id: &str) -> Result<Option<bool>> {
    let out = Command::new("podman")
        .args(["run", "--rm", "--pull=never", "--network=none", "--user=0", "--entrypoint=/bin/sh", base_id, "-c"])
        .arg("for f in /lib/ld-musl-*; do [ -e \"$f\" ] && { echo musl; exit 0; }; done; echo glibc")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .context("read the image's C library")?;
    Ok(match String::from_utf8_lossy(&out.stdout).trim() {
        "musl" if out.status.success() => Some(true),
        "glibc" if out.status.success() => Some(false),
        _ => None,
    })
}

/// Docker Engine from the image's own distribution, when it has no
/// `dockerd`: the engine, its CLI (a package of its own on Debian trixie),
/// `iptables` (it needs one), compose and buildx where the distribution has
/// them.
const ENGINE_INSTALL: &str = "if ! command -v dockerd >/dev/null 2>&1; then \
    if command -v apt-get >/dev/null 2>&1; then \
      export DEBIAN_FRONTEND=noninteractive; apt-get update; \
      apt-get install -y --no-install-recommends docker.io iptables ca-certificates; \
      command -v docker >/dev/null 2>&1 || apt-get install -y --no-install-recommends docker-cli; \
      apt-get install -y --no-install-recommends docker-compose-v2 || apt-get install -y --no-install-recommends docker-compose || true; \
      apt-get install -y --no-install-recommends docker-buildx || true; \
      rm -rf /var/lib/apt/lists/*; \
    elif command -v apk >/dev/null 2>&1; then \
      apk add --no-cache docker-engine docker-cli iptables ip6tables; \
      apk add --no-cache docker-cli-compose docker-cli-buildx || true; \
    elif command -v dnf >/dev/null 2>&1; then \
      dnf install -y moby-engine iptables-nft; dnf install -y docker-compose || true; dnf clean all; \
    else \
      echo 'ssai: the image has no dockerd, nor apt-get, apk or dnf to add one with — install Docker Engine in the image' >&2; exit 1; \
    fi; \
  fi";

/// The layer's recipe: the engine when asked for, then the client with its
/// Node, the client package's own install scripts approved by name (npm 12
/// skips an unapproved one, and a client such as OpenCode then cannot start);
/// the base, `engine` and `client` alone, so every name the client is
/// launched by builds (and finds) the same layer. The client's commands are
/// put first on `PATH` as wrappers running it on the layer's Node; that Node
/// is last on `PATH`, so the project's own `node` wins and an image without
/// one still has `node`, `npm` and `npx` (an `npx` MCP server, say).
fn layer_dockerfile(base_id: &str, client: Option<(&str, &NodeDist)>, engine: bool) -> String {
    let mut df = format!("FROM {base_id}\nUSER root\n");
    if engine {
        df.push_str(&format!("RUN set -e; {ENGINE_INSTALL}\n"));
    }
    if let Some((package, node)) = client {
        let musl = if node.libc.is_empty() { "" } else { "command -v apk >/dev/null 2>&1 && apk add --no-cache libstdc++ libgcc; " };
        df.push_str(&format!(
            "# node {sha}\nADD {file} {AGENT_PREFIX}/\n\
             RUN set -e; {musl}mv {AGENT_PREFIX}/{dir} {AGENT_PREFIX}/node; \
             PATH={AGENT_PREFIX}/node/bin:$PATH npm install -g --no-update-notifier --allow-scripts={package} --prefix {AGENT_PREFIX}/client {package}@latest; \
             mkdir -p {AGENT_PREFIX}/bin; \
             for f in {AGENT_PREFIX}/client/bin/*; do n=${{f##*/}}; \
               if head -n 1 \"$f\" | grep -q node; then \
                 printf '#!/bin/sh\\nexec {AGENT_PREFIX}/node/bin/node \"%s\" \"$@\"\\n' \"$f\" > {AGENT_PREFIX}/bin/$n; chmod 755 {AGENT_PREFIX}/bin/$n; \
               else ln -s \"$f\" {AGENT_PREFIX}/bin/$n; fi; \
             done\n\
             ENV PATH={AGENT_PREFIX}/bin:${{PATH:-/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin}}:{AGENT_PREFIX}/node/bin\n",
            sha = node.sha256,
            file = node.file(),
            dir = node.dir(),
        ));
    }
    df
}

/// The agent user's ids, from the image's `/etc/passwd`, cached per (base id,
/// user). The probe runs with the default user namespace: a keep-id map of
/// its own would re-own a second copy of the image.
fn agent_user(base_id: &str, user: &str) -> Result<AgentUser> {
    let cache = ids_cache(base_id, user);
    if let Some(path) = &cache
        && let Ok(text) = std::fs::read_to_string(path)
        && let Ok(found) = serde_json::from_str::<AgentUser>(&text)
    {
        return Ok(found);
    }
    // An image without `cat` or a passwd file: only a numeric user can run.
    let passwd = image_file(base_id, "/etc/passwd")?;
    // A named group (`USER name:group`) needs the image's group file.
    let named_group = user.split_once(':').is_some_and(|(_, g)| g.parse::<u32>().is_err());
    let group = if named_group { image_file(base_id, "/etc/group")? } else { String::new() };
    let found = lookup(&passwd, &group, user)?;
    if let Some(path) = &cache {
        let _ = std::fs::create_dir_all(path.parent().unwrap_or(Path::new(".")));
        let _ = std::fs::write(path, serde_json::to_string(&found)?);
    }
    Ok(found)
}

fn ids_cache(base_id: &str, user: &str) -> Option<PathBuf> {
    let mut h = Sha256::new();
    h.update(base_id.as_bytes());
    h.update([0]);
    h.update(user.as_bytes());
    Some(crate::state::cache_dir().ok()?.join("sandbox-ids").join(hex::encode(&h.finalize()[..12])))
}

/// `user` (a name, a uid, or `uid:gid`) against a passwd file's text.
/// A file of the image (empty when it cannot be read).
fn image_file(base_id: &str, path: &str) -> Result<String> {
    let out = Command::new("podman")
        .args(["run", "--rm", "--pull=never", "--network=none", "--entrypoint=cat", base_id, path])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .with_context(|| format!("read the image's {path}"))?;
    Ok(if out.status.success() { String::from_utf8_lossy(&out.stdout).into_owned() } else { String::new() })
}

fn lookup(passwd: &str, group_file: &str, user: &str) -> Result<AgentUser> {
    let entries: Vec<(&str, u32, u32, &str)> = passwd
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.len() >= 7).then(|| Some((f[0], f[2].parse().ok()?, f[3].parse().ok()?, f[5])))?
        })
        .collect();
    let (who, group) = match user.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (user, None),
    };
    let by_name = entries.iter().find(|e| e.0 == who);
    let by_id = who.parse::<u32>().ok().map(|uid| (uid, entries.iter().find(|e| e.1 == uid)));
    let (uid, gid, home) = match (by_name, by_id) {
        (Some(e), _) => (e.1, e.2, e.3.to_string()),
        (None, Some((uid, Some(e)))) => (uid, e.2, e.3.to_string()),
        (None, Some((uid, None))) => (uid, uid, if uid == 0 { "/root".into() } else { format!("/home/{uid}") }),
        (None, None) => bail!("the image has no user {who:?} — set `remoteUser` to one it has"),
    };
    let gid = match group {
        None => gid,
        Some(g) => match g.parse() {
            Ok(gid) => gid,
            Err(_) => group_file
                .lines()
                .find_map(|l| {
                    let f: Vec<&str> = l.split(':').collect();
                    (f.len() >= 3 && f[0] == g).then(|| f[2].parse().ok()).flatten()
                })
                .with_context(|| format!("the image has no group {g:?} (from {user:?})"))?,
        },
    };
    if home.is_empty() || !home.starts_with('/') {
        bail!("the image's user {who:?} has no absolute home directory");
    }
    Ok(AgentUser { uid, gid, home })
}

/// Whether `reference` names an image only this machine holds (podman's
/// `localhost/` namespace), which no pull can fetch.
fn local_only(reference: &str) -> bool {
    reference.starts_with("localhost/")
}

/// Whether `image` is on this machine: podman's 0 or 1; any other answer is
/// an error, never "absent" (a pull would then be taken for the sandbox's).
fn exists(image: &str) -> Result<bool> {
    let status = Command::new("podman")
        .args(["image", "exists", image])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("run podman")?;
    match status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => bail!("podman could not say whether {image} is on this machine ({status})"),
    }
}

/// An image's `Config.Env` (`["K=V", …]`, or `null`) as pairs.
fn image_env(json: &str) -> Vec<(String, String)> {
    serde_json::from_str::<Option<Vec<String>>>(json)
        .ok()
        .flatten()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|kv| kv.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())))
        .collect()
}

fn inspect(image: &str, format: &str) -> Result<String> {
    let out = Command::new("podman")
        .args(["image", "inspect", "--format", format, image])
        .stdin(Stdio::null())
        .output()
        .context("run podman image inspect")?;
    if !out.status.success() {
        bail!("inspect {image}: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn podman(args: &[&str]) -> Result<()> {
    let status = Command::new("podman").args(args).stdin(Stdio::null()).status().context("run podman")?;
    if !status.success() {
        bail!("podman {} failed ({status})", args.first().unwrap_or(&""));
    }
    Ok(())
}

fn path(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\n\
                          vscode:x:1000:1000::/home/vscode:/bin/bash\n\
                          dev:x:1001:1002::/srv/dev:/bin/sh\n\
                          broken line\n";

    #[test]
    fn a_user_is_found_by_name_or_id_with_its_home() {
        assert_eq!(lookup(PASSWD, "", "vscode").unwrap(), AgentUser { uid: 1000, gid: 1000, home: "/home/vscode".into() });
        assert_eq!(lookup(PASSWD, "", "1001").unwrap(), AgentUser { uid: 1001, gid: 1002, home: "/srv/dev".into() });
        assert_eq!(lookup(PASSWD, "", "root").unwrap(), AgentUser { uid: 0, gid: 0, home: "/root".into() });
        assert_eq!(lookup(PASSWD, "", "dev:7").unwrap().gid, 7);
    }

    #[test]
    fn a_numeric_user_the_image_does_not_list_still_runs() {
        assert_eq!(lookup("", "", "4242").unwrap(), AgentUser { uid: 4242, gid: 4242, home: "/home/4242".into() });
        assert_eq!(lookup("", "", "0").unwrap().home, "/root");
    }

    #[test]
    fn a_name_the_image_lacks_is_refused() {
        assert!(lookup(PASSWD, "", "nobody-here").is_err());
        assert!(lookup("", "", "vscode").is_err());
        assert!(lookup(PASSWD, "", "dev:staff").is_err(), "a group name with no group file");
        let group = "root:x:0:\nstaff:x:50:\n";
        assert_eq!(lookup(PASSWD, group, "dev:staff").unwrap().gid, 50);
        assert!(lookup(PASSWD, group, "dev:nogroup").is_err());
        assert!(lookup("x:x:5:5::relative:/bin/sh\n", "", "x").is_err());
    }

    #[test]
    fn only_a_localhost_reference_is_local_only() {
        assert!(local_only("localhost/ssai-smoke:node-1"));
        for pulled in ["docker.io/library/ubuntu:24.04", "mcr.microsoft.com/devcontainers/base:ubuntu", "localhost:5000/x", "ghcr.io/localhost/x"] {
            assert!(!local_only(pulled), "{pulled}");
        }
    }

    #[test]
    fn a_build_is_rebuilt_for_what_podman_builds_from_not_for_a_lifecycle_command() {
        let root = std::env::temp_dir().join(format!("ssai-build-hash-{}-{}", std::process::id(), rand::random::<u32>()));
        std::fs::create_dir_all(root.join(".devcontainer")).unwrap();
        std::fs::write(root.join(".devcontainer/Dockerfile"), "FROM a\n").unwrap();
        let hash = |dc: &str| {
            std::fs::write(root.join(".devcontainer/devcontainer.json"), dc).unwrap();
            let entry = r#"{"devcontainer": ".devcontainer/devcontainer.json"}"#;
            let config = super::super::config::resolve(&root, &super::super::config::example(entry), &|p| {
                Ok(std::fs::read_to_string(p)?)
            })
            .unwrap();
            build_hash(&root, &config).unwrap()
        };
        let base = hash(r#"{"build": {"dockerfile": "Dockerfile"}, "postCreateCommand": "a"}"#);
        assert_eq!(base, hash(r#"{"build": {"dockerfile": "Dockerfile"}, "postCreateCommand": "b", "remoteEnv": {"A": "1"}}"#));
        for other in [
            r#"{"build": {"dockerfile": "Dockerfile", "target": "dev"}, "postCreateCommand": "a"}"#,
            r#"{"build": {"dockerfile": "Dockerfile", "args": {"V": "1"}}, "postCreateCommand": "a"}"#,
            r#"{"build": {"dockerfile": "Dockerfile", "context": ".."}, "postCreateCommand": "a"}"#,
        ] {
            assert_ne!(base, hash(other), "{other}");
        }
        std::fs::write(root.join(".devcontainer/Dockerfile"), "FROM b\n").unwrap();
        assert_ne!(base, hash(r#"{"build": {"dockerfile": "Dockerfile"}, "postCreateCommand": "a"}"#), "the Dockerfile's text");
        // With features: what the Dev Container CLI's build reads, never a lifecycle command or a variable.
        let f = r#"{"build": {"dockerfile": "Dockerfile"}, "features": {"ghcr.io/x/y:1": {"v": "1"}}, "postCreateCommand": "a"}"#;
        let with_features = hash(f);
        assert_ne!(with_features, base, "features are part of the build");
        for same in [
            f.replace(r#""postCreateCommand": "a""#, r#""postCreateCommand": "b", "postStartCommand": "c""#),
            f.replace(r#""postCreateCommand": "a""#, r#""remoteEnv": {"A": "2"}, "containerEnv": {"B": "3"}"#),
        ] {
            assert_eq!(with_features, hash(&same), "{same}");
        }
        for other in [
            f.replace(r#"{"v": "1"}"#, r#"{"v": "2"}"#),
            f.replace(r#""ghcr.io/x/y:1""#, r#""ghcr.io/x/y:2""#),
            f.replace(r#""postCreateCommand": "a""#, r#""overrideFeatureInstallOrder": ["ghcr.io/x/y"]"#),
            f.replace(r#""postCreateCommand": "a""#, r#""remoteUser": "dev""#),
            f.replace(r#""dockerfile": "Dockerfile""#, r#""dockerfile": "Dockerfile", "target": "t""#),
        ] {
            assert_ne!(with_features, hash(&other), "{other}");
        }
        // The features' lockfile pins their versions.
        std::fs::write(root.join(".devcontainer/devcontainer-lock.json"), "{}").unwrap();
        assert_ne!(with_features, hash(f), "the lockfile");
        std::fs::write(root.join(".devcontainer/Dockerfile"), "FROM c\n").unwrap();
        let locked = hash(f);
        std::fs::write(root.join(".devcontainer/Dockerfile"), "FROM d\n").unwrap();
        assert_ne!(locked, hash(f), "the Dockerfile's text, with features too");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_features_build_is_given_what_it_reads_and_no_lifecycle() {
        let root = Path::new("/home/dev/app");
        let dc = r#"{"build": {"dockerfile": "Dockerfile", "args": {"V": "${localWorkspaceFolderBasename}"}, "cacheFrom": "c/d"},
            "features": {"ghcr.io/x/y:1": {"v": "1"}}, "overrideFeatureInstallOrder": ["ghcr.io/x/y"],
            "remoteUser": "dev", "workspaceFolder": "/w", "postCreateCommand": "a", "remoteEnv": {"A": "1"}, "containerEnv": {"B": "2"}}"#;
        let config = super::super::config::resolve(root, &super::super::config::example(r#"{"devcontainer": ".devcontainer/devcontainer.json"}"#), &|_| {
            Ok(dc.to_string())
        })
        .unwrap();
        let recipe = features_recipe(&config);
        assert_eq!(
            recipe,
            serde_json::json!({
                "build": {"dockerfile": "/home/dev/app/.devcontainer/Dockerfile", "context": "/home/dev/app/.devcontainer",
                          "args": {"V": "app"}, "cacheFrom": "c/d"},
                "features": {"ghcr.io/x/y:1": {"v": "1"}},
                "overrideFeatureInstallOrder": ["ghcr.io/x/y"],
                "remoteUser": "dev",
                "workspaceFolder": "/w",
            })
        );
        let image = super::super::config::resolve(root, &super::super::config::example(r#"{"devcontainer": ".devcontainer/devcontainer.json"}"#), &|_| {
            Ok(r#"{"image": "ubuntu", "features": {"f:1": {}}}"#.to_string())
        })
        .unwrap();
        assert_eq!(features_recipe(&image), serde_json::json!({"image": "ubuntu", "features": {"f:1": {}}}));
    }

    #[test]
    fn the_agent_layer_is_tagged_by_its_base_and_installs_the_latest_package() {
        let node = NodeDist::new("x86_64", false).unwrap();
        let recipe = layer_dockerfile("sha256:0123456789abcdef0123", Some(("@anthropic-ai/claude-code", &node)), false);
        let tag = layer_tag(Some("@anthropic-ai/claude-code"), false, "sha256:0123456789abcdef0123", &recipe);
        let named = "localhost/ssai-agent-anthropic-ai-claude-code:0123456789ab-";
        assert!(tag.starts_with(named) && tag.len() == named.len() + 8, "{tag}");
        assert!(layer_tag(Some("Qwen.Code"), false, "abc", "r").starts_with("localhost/ssai-agent-qwen-code:abc-"));
        assert!(layer_tag(Some("@scope/tool."), false, "abc", "r").starts_with("localhost/ssai-agent-scope-tool:abc-"));
        // With an engine, another repository; the engine alone, its own.
        assert!(layer_tag(Some("x"), true, "abc", "r").starts_with("localhost/ssai-agent-x-with-engine:abc-"));
        assert!(layer_tag(None, true, "abc", "r").starts_with("localhost/ssai-agent-engine:abc-"));
        // Another recipe on the same base is another layer.
        assert_ne!(layer_tag(Some("@anthropic-ai/claude-code"), false, "sha256:0123456789abcdef0123", "FROM x\n"), tag);
        let df = recipe;
        assert!(df.starts_with("FROM sha256:0123456789abcdef0123\nUSER root\n"), "{df}");
        assert!(df.contains(&format!("ADD node-{NODE_VERSION}-linux-x64.tar.gz /opt/ssai-agent/\n")), "{df}");
        assert!(
            df.contains("npm install -g --no-update-notifier --allow-scripts=@anthropic-ai/claude-code --prefix /opt/ssai-agent/client @anthropic-ai/claude-code@latest"),
            "the client's own install script approved (npm 12 skips an unapproved one): {df}"
        );
        // The layer's Node runs the client, whatever `node` comes first on PATH.
        assert!(df.contains("exec /opt/ssai-agent/node/bin/node"), "{df}");
        // First on PATH, and never an empty entry (the working directory) when the image sets none.
        // The layer's Node last: the image's own `node` wins.
        assert!(df.ends_with("\nENV PATH=/opt/ssai-agent/bin:${PATH:-/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin}:/opt/ssai-agent/node/bin\n"), "{df}");
        assert!(!df.contains("dockerd"), "no engine unless asked: {df}");
        // The engine alone, and with the client: each its own recipe.
        let engine = layer_dockerfile("sha256:aa", None, true);
        assert!(engine.contains("command -v dockerd") && engine.contains("docker.io iptables") && !engine.contains("npm"), "{engine}");
        let both = layer_dockerfile("sha256:aa", Some(("@anthropic-ai/claude-code", &node)), true);
        assert!(both.contains("command -v dockerd") && both.contains("npm install"), "{both}");
        // A musl image gets the musl build, and the C++ runtime it needs.
        let musl = NodeDist::new("x86_64", true).unwrap();
        let df = layer_dockerfile("sha256:aa", Some(("x", &musl)), false);
        assert!(df.contains("-linux-x64-musl.tar.gz") && df.contains("apk add --no-cache libstdc++"), "{df}");
        assert!(musl.url().starts_with("https://unofficial-builds.nodejs.org/"));
        assert!(node.url().starts_with("https://nodejs.org/dist/"));
        // The pin is in the recipe: a new pin is a new layer.
        assert!(layer_dockerfile("sha256:aa", Some(("x", &node)), false).contains(node.sha256));
        assert!(NodeDist::new("riscv64", false).is_err());
        assert_eq!(NodeDist::new("aarch64", false).unwrap().arch, "arm64");
    }


    #[test]
    fn an_images_metadata_runs_its_features_commands_and_every_entrys_variables() {
        let label = r#"[{"id": "ghcr.io/x/f:1", "postCreateCommand": "feature", "containerEnv": {"F": "1"}},
            7,
            {"id": "ghcr.io/x/bad:1", "postCreateCommand": 7},
            {"postCreateCommand": "the project's copy", "remoteEnv": {"R": "2"}}]"#;
        let skipped = std::cell::RefCell::new(Vec::new());
        let l = label_lifecycle(&metadata_entries(label), &|t| Ok(t.to_string()), &|i, _| skipped.borrow_mut().push(i));
        let argv: Vec<&str> = l.create.iter().map(|s| s.argv[2].as_str()).collect();
        assert_eq!(argv, ["feature"], "the entry without an id runs no command");
        assert_eq!(l.container_env, [("F".to_string(), "1".to_string())]);
        assert_eq!(l.remote_env, [("R".to_string(), "2".to_string())], "its variables apply");
        assert_eq!(*skipped.borrow(), [1, 2], "an entry it cannot read is skipped, and said");
    }

    #[test]
    fn a_prebuilt_images_metadata_names_its_user() {
        let label = r#"[{"id":"ghcr.io/devcontainers/features/common-utils:2"},{"remoteUser":"vscode"},{"containerUser":"node"}]"#;
        assert_eq!(metadata_users(&metadata_entries(label)), (Some("vscode".into()), Some("node".into())));
        assert_eq!(metadata_users(&metadata_entries(r#"[{"remoteUser":"a"},{"remoteUser":"b"}]"#)).0.as_deref(), Some("b"), "a later entry overrides");
        assert_eq!(metadata_users(&metadata_entries(r#"[{"containerUser":"node"}]"#)), (None, Some("node".into())));
        assert_eq!(metadata_users(&metadata_entries(r#"{"remoteUser":"node"}"#)).0.as_deref(), Some("node"), "one entry on its own");
        // No label (podman prints `<no value>`), an empty user, no user: the image's `USER` decides.
        for none in ["<no value>", "", r#"[{"remoteUser":""}]"#, r#"[{"id":"x"}]"#, "{}", "7"] {
            assert_eq!(metadata_users(&metadata_entries(none)), (None, None), "{none:?}");
        }
    }


    #[test]
    fn an_images_env_is_read_as_pairs() {
        assert_eq!(
            image_env(r#"["PATH=/usr/bin","JAVA_TOOL_OPTIONS=-Xmx4g -Da=b","EMPTY="]"#),
            [("PATH".into(), "/usr/bin".into()), ("JAVA_TOOL_OPTIONS".into(), "-Xmx4g -Da=b".into()), ("EMPTY".into(), String::new())]
        );
        assert!(image_env("null").is_empty() && image_env("").is_empty());
    }


    #[test]
    fn a_build_path_through_a_symlink_out_of_the_project_is_refused() {
        let base = std::env::temp_dir().join(format!("ssai-confined-{}-{}", std::process::id(), rand::random::<u32>()));
        let (root, home) = (base.join("p"), base.join("home"));
        std::fs::create_dir_all(root.join("docker")).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(root.join("docker/Dockerfile"), "FROM x").unwrap();
        std::os::unix::fs::symlink(&home, root.join("ctx")).unwrap();
        let err = confined(&root, &root.join("ctx"), "context").unwrap_err();
        assert!(format!("{err}").contains("leads outside the project"), "{err}");
        // Positive control: real paths inside, the root itself included.
        assert!(confined(&root, &root.join("docker/Dockerfile"), "dockerfile").is_ok());
        assert!(confined(&root, &root, "context").is_ok());
        let _ = std::fs::remove_dir_all(&base);
    }
}
