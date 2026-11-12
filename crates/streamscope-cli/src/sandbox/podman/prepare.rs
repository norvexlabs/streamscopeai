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
    // image's, which the developer cannot fix: skipped whole, and said.
    // An image built here with `features` carries the project's own entry.
    let lifecycle = label_lifecycle(&entries, !config.has_features, &|text| super::config::expand_lenient(text, root, &workspace), &|i, e| {
        eprintln!("ssai: entry {i} of the image {}'s devcontainer.metadata is skipped — {e:#}", config.source_name())
    })
    .then(config.lifecycle.clone());
    let image = match npm {
        Some(package) => agent_layer(&base_id, package, force)?,
        None => base_id.clone(),
    };
    let env = image_env(&inspect(&image, "{{json .Config.Env}}")?);
    let container_root = super::sweep::Root::for_agent(user.uid, user.gid);
    Ok(Prepared { image, user, env, container_root, base: base_id, lifecycle })
}

/// Where the image source a project's last run used is recorded: its
/// reference (`image:<ref>`) or its build's tag.
fn build_record(root: &Path) -> Result<PathBuf> {
    let mut h = Sha256::new();
    h.update(root.as_os_str().as_encoded_bytes());
    Ok(crate::state::cache_dir()?.join("sandbox-builds").join(hex::encode(&h.finalize()[..12])))
}

/// The guard below fails closed: a record that cannot be written stops the
/// run, rather than leaving every later build unasked.
fn record_build(root: &Path, tag: &str, engine: bool) -> Result<()> {
    let path = build_record(root)?;
    std::fs::create_dir_all(path.parent().unwrap_or(Path::new("."))).context("create the sandbox's build records")?;
    std::fs::write(&path, format!("{tag}\n{}", if engine { "engine" } else { "no-engine" }))
        .with_context(|| format!("record the project's image in {}", path.display()))
}

/// An engine inside makes the container privileged: `"docker": true` that
/// was off at the project's last run (the agent can edit `sandbox.json`) is
/// taken only after `ssai sandbox prepare`.
fn engine_turned_on(root: &Path, engine: bool, force: bool) -> Result<()> {
    let path = build_record(root)?;
    let was = match std::fs::read_to_string(&path) {
        Ok(text) => text.lines().nth(1).map(|l| l.trim() == "engine"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };
    if !force && engine && was == Some(false) {
        bail!(
            "`\"docker\": true` is new in sandbox.json since the project's last run (an engine runs privileged) — \
             check it, then run `ssai sandbox prepare <client>`"
        );
    }
    Ok(())
}

/// The recorded source, `None` when there is none; an unreadable record is
/// an error, never "none".
fn last_build(root: &Path) -> Result<Option<String>> {
    let path = build_record(root)?;
    match std::fs::read_to_string(&path) {
        Ok(text) => Ok(text.lines().next().map(|l| l.trim().to_string())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
    }
}

/// An image source (a reference, or a recipe: Dockerfile, devcontainer.json)
/// that changed since the project's last run is not pulled or built on its
/// own: the agent can edit all of them, and a pull or a build runs with the
/// network open before any guard. `ssai sandbox prepare` (`force`) does it
/// after the developer has read the change; a project's first one needs no
/// such step.
fn changed_since_last_build(root: &Path, source: &str, force: bool) -> Result<()> {
    if !force && last_build(root)?.is_some_and(|last| last != source) {
        bail!(
            "the image (its reference, Dockerfile or devcontainer.json) changed since the last run — read the \
             change, then rebuild with `ssai sandbox prepare <client>`"
        );
    }
    Ok(())
}

/// A build runs what its recipe and its context hold — files the agent can
/// edit, the context possibly the whole project — with the network open
/// before any guard. Only a project's first image is built on a run; every
/// later build (a changed recipe, or an image removed since) waits for `ssai
/// sandbox prepare` (`force`), after the developer has read what it builds.
fn rebuild_needs_prepare(root: &Path, force: bool) -> Result<()> {
    if !force && last_build(root)?.is_some() {
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
/// without one is the `devcontainer.json` the image was built from — the
/// project's own, for an image built from it, which runs its commands
/// itself; `say_own` names the commands left out (an image this project did
/// not build). One this parser cannot read is passed to `skipped` and left out.
fn label_lifecycle(
    entries: &[serde_json::Value],
    say_own: bool,
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
            if say_own {
                let hooks: Vec<&str> = theirs.create.iter().chain(&theirs.start).map(|s| s.hook.as_str()).collect();
                eprintln!(
                    "ssai: the image's own devcontainer.json commands ({}) are not run — only its features' are",
                    hooks.join(", ")
                );
            }
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

/// The base image's reference, pulled or built when absent (or `force`).
fn base_image(root: &Path, config: &DockerConfig, force: bool) -> Result<String> {
    engine_turned_on(root, config.docker, force)?;
    if let ImageSource::Build { context, dockerfile, .. } = &config.source {
        confined(root, dockerfile, "dockerfile")?;
        confined(root, context, "context")?;
    }
    // `features` apply to an `image` and a `build` alike, and only the
    // devcontainer CLI applies them.
    if config.has_features {
        let tag = format!("localhost/ssai-base:{}", build_hash(root, config)?);
        if force || !exists(&tag)? {
            rebuild_needs_prepare(root, force)?;
            build_with_devcontainer_cli(root, config, &tag)?;
        }
        // The image this run uses is the one a later change is compared with.
        record_build(root, &tag, config.docker)?;
        return Ok(tag);
    }
    match &config.source {
        ImageSource::Image(reference) => {
            // A pull reaches the registry it names from this machine's network,
            // before any guard: a reference changed since the last run (the
            // agent can edit it) is pulled only after a `prepare`.
            let source = format!("image:{reference}");
            // A `localhost/` image exists only on this machine: no registry
            // serves it, so a `prepare` uses it as it is.
            if (force && !local_only(reference)) || !exists(reference)? {
                changed_since_last_build(root, &source, force)?;
                eprintln!("ssai: pulling {reference} for the docker sandbox");
                podman(&["pull", reference]).with_context(|| format!("pull {reference}"))?;
            }
            record_build(root, &source, config.docker)?;
            Ok(reference.clone())
        }
        ImageSource::Build { context, dockerfile, target, args } => {
            let tag = format!("localhost/ssai-base:{}", build_hash(root, config)?);
            if force || !exists(&tag)? {
                rebuild_needs_prepare(root, force)?;
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
                podman(&a.iter().map(String::as_str).collect::<Vec<_>>()).context("build the project's image")?;
            }
            record_build(root, &tag, config.docker)?;
            Ok(tag)
        }
    }
}

/// An image whose `devcontainer.json` has `features` is built by the
/// devcontainer CLI, driving podman; without it, refused naming the install.
fn build_with_devcontainer_cli(root: &Path, config: &DockerConfig, tag: &str) -> Result<()> {
    let Some(dc) = &config.devcontainer else { bail!("features without a devcontainer.json") };
    eprintln!("ssai: building {} (with its features) for the docker sandbox", dc.display());
    let status = Command::new("devcontainer")
        .args(["build", "--docker-path", "podman", "--workspace-folder"])
        .arg(root)
        .arg("--config")
        .arg(dc)
        .args(["--image-name", tag])
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
}

/// What a build is built from (the context's other files are not followed —
/// `ssai sandbox prepare` rebuilds after a change to them). With `features`,
/// the whole devcontainer.json: the Dev Container CLI reads all of it, and
/// writes its lifecycle commands into the image's metadata. Without, what
/// `podman build` is given — the Dockerfile's text, its context, target and
/// args — so a change to a lifecycle command or the environment needs no
/// rebuild.
fn build_hash(root: &Path, config: &DockerConfig) -> Result<String> {
    let mut h = Sha256::new();
    h.update(root.as_os_str().as_encoded_bytes());
    if config.has_features
        && let Some(dc) = &config.devcontainer
    {
        h.update(std::fs::read(dc).with_context(|| format!("read {}", dc.display()))?);
    }
    if let ImageSource::Build { dockerfile, context, target, args } = &config.source {
        h.update(std::fs::read(dockerfile).with_context(|| format!("read {}", dockerfile.display()))?);
        // Each part length-prefixed: no two recipes hash alike.
        let mut part = |b: &[u8]| {
            h.update((b.len() as u64).to_le_bytes());
            h.update(b);
        };
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

/// The agent layer: `package` installed on the base, tagged by the base's
/// id, built when absent (or `force`).
fn agent_layer(base_id: &str, package: &str, force: bool) -> Result<String> {
    let recipe = layer_dockerfile(base_id, package);
    let tag = layer_tag(package, base_id, &recipe);
    if !force && exists(&tag)? {
        return Ok(tag);
    }
    eprintln!("ssai: installing {package} into the docker sandbox's image");
    // An empty, private context (the Dockerfile comes on stdin): created
    // new, never one that already exists.
    let context = {
        use std::os::unix::fs::DirBuilderExt;
        let parent = crate::state::cache_dir()?.join("sandbox-build");
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&parent)
            .with_context(|| format!("create {}", parent.display()))?;
        let dir = parent.join(format!("layer-{}-{}", std::process::id(), hex::encode(rand::random::<[u8; 6]>())));
        std::fs::DirBuilder::new().mode(0o700).create(&dir).context("create the agent layer's build context")?;
        dir
    };
    let built = (|| {
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
            bail!("could not install {package} into the image ({status})");
        }
        written
    })();
    let _ = std::fs::remove_dir_all(&context);
    built.map(|()| tag)
}

/// `localhost/ssai-agent-<package>:<base id, 12 hex>-<recipe, 8 hex>`: named
/// by the package, which `run` and `sandbox prepare` resolve alike whatever
/// name the client is launched by; the recipe is in the tag, so a layer an
/// earlier `ssai` built another way is never taken for this one.
fn layer_tag(package: &str, base_id: &str, recipe: &str) -> String {
    let name: String = package.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' }).collect();
    // A reference component may not start or end with a separator.
    let name = name.trim_matches('-');
    let id = base_id.trim_start_matches("sha256:");
    let recipe = hex::encode(Sha256::digest(recipe.as_bytes()));
    format!("localhost/ssai-agent-{name}:{}-{}", &id[..id.len().min(12)], &recipe[..8])
}

/// Where the agent layer installs the client, first on the agent's `PATH`.
/// Never the image's own npm prefix: that may lie under the agent's home,
/// which the home volume covers from the first run on, hiding every later
/// install there.
pub const AGENT_PREFIX: &str = "/opt/ssai-agent";

/// The layer's recipe: `package` and the base alone, so every name the client
/// is launched by builds (and finds) the same layer.
fn layer_dockerfile(base_id: &str, package: &str) -> String {
    format!(
        "FROM {base_id}\nUSER root\nRUN command -v npm >/dev/null 2>&1 || {{ echo \"ssai: the image has no npm — add \
         Node.js to it to run {package} in the docker sandbox\" >&2; exit 1; }}; \
         npm install -g --prefix {AGENT_PREFIX} {package}@latest\n\
         ENV PATH={AGENT_PREFIX}/bin:${{PATH:-/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin}}\n"
    )
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

fn exists(image: &str) -> Result<bool> {
    let status = Command::new("podman")
        .args(["image", "exists", image])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("run podman")?;
    Ok(status.success())
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
        // With features the Dev Container CLI reads the whole file, its commands into the image's metadata.
        let f = r#"{"build": {"dockerfile": "Dockerfile"}, "features": {"ghcr.io/x/y:1": {}}, "postCreateCommand": "a"}"#;
        assert_ne!(hash(f), hash(&f.replace(r#""a""#, r#""b""#)));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_agent_layer_is_tagged_by_its_base_and_installs_the_latest_package() {
        let recipe = layer_dockerfile("sha256:0123456789abcdef0123", "@anthropic-ai/claude-code");
        let tag = layer_tag("@anthropic-ai/claude-code", "sha256:0123456789abcdef0123", &recipe);
        let named = "localhost/ssai-agent-anthropic-ai-claude-code:0123456789ab-";
        assert!(tag.starts_with(named) && tag.len() == named.len() + 8, "{tag}");
        assert!(layer_tag("Qwen.Code", "abc", "r").starts_with("localhost/ssai-agent-qwen-code:abc-"));
        assert!(layer_tag("@scope/tool.", "abc", "r").starts_with("localhost/ssai-agent-scope-tool:abc-"));
        // Another recipe on the same base is another layer.
        assert_ne!(layer_tag("@anthropic-ai/claude-code", "sha256:0123456789abcdef0123", "FROM x\n"), tag);
        let df = layer_dockerfile("sha256:aa", "@anthropic-ai/claude-code");
        assert!(df.starts_with("FROM sha256:aa\nUSER root\n"), "{df}");
        assert!(df.contains("npm install -g --prefix /opt/ssai-agent @anthropic-ai/claude-code@latest"), "{df}");
        // First on PATH, and never an empty entry (the working directory) when the image sets none.
        assert!(df.ends_with("\nENV PATH=/opt/ssai-agent/bin:${PATH:-/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin}\n"), "{df}");
        assert!(df.contains("has no npm"), "{df}");
    }


    #[test]
    fn an_images_metadata_runs_its_features_commands_and_every_entrys_variables() {
        let label = r#"[{"id": "ghcr.io/x/f:1", "postCreateCommand": "feature", "containerEnv": {"F": "1"}},
            7,
            {"id": "ghcr.io/x/bad:1", "postCreateCommand": 7},
            {"postCreateCommand": "the project's copy", "remoteEnv": {"R": "2"}}]"#;
        let skipped = std::cell::RefCell::new(Vec::new());
        let l = label_lifecycle(&metadata_entries(label), false, &|t| Ok(t.to_string()), &|i, _| skipped.borrow_mut().push(i));
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
