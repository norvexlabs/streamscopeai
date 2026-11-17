//! `--sandbox docker` — the client in a rootless Podman container
//! (`--userns=keep-id`): the project mounted at its workspace path, no network
//! but the guard's unix socket, the image and its user the project's own
//! (`.streamscopeai/sandbox.json`). Linux only; refused on a rootful podman.
//!
//! A run, in order: read the project's configuration; preflight the host;
//! remove a killed run's container, then sweep the project its run dir names
//! and remove that dir; prepare the images (network open, no key); start the
//! guard on the run's socket; run the container — its init relays the guard
//! and starts the agent; then sweep the project and remove the run's files.

pub mod config;
mod images;
pub mod init;
mod plan;
mod prepare;
pub mod preflight;
mod routing;
pub mod sweep;

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use rand::Rng;
use sha2::{Digest, Sha256};

use super::{guard, LaunchSpec};

/// The loopback port the container's relay listens on.
const RELAY_PORT: u16 = 3128;

/// Node's additive trust variable: the one a docker run may set for the
/// host's store without dropping the image's own roots.
const NODE_CA_VAR: &str = "NODE_EXTRA_CA_CERTS";

/// The host's system store, in the run dir.
const HOST_CA_FILE: &str = "host-ca.pem";

/// Launch `spec` in a container; the client's exit code.
pub async fn launch(mut spec: LaunchSpec, verbose: bool) -> Result<i32> {
    let root = spec.project_root.clone();
    let config = read_config(&root, spec.default_image.as_ref())?;
    for note in &config.notes {
        eprintln!("ssai: {note}");
    }
    let facts = {
        let (docker, cpus) = (config.docker, config.limits.cpus.is_some());
        tokio::task::spawn_blocking(move || preflight::run(docker, cpus)).await??
    };
    let exe = std::env::current_exe().context("locate ssai")?;
    if !plan::mountable(&root.to_string_lossy()) {
        bail!("{} holds a `:` or `,`, which podman cannot mount — move it to a plain path", root.display());
    }
    if remove_stale_containers().await {
        remove_stale_runs(&exe).await;
    }
    // An engine's cache is one volume per project: two engines on it at
    // once would corrupt it.
    if config.docker && records_root().is_ok_and(|r| live_engine_on(&r, &boot_id(), &root)) {
        bail!("another `--sandbox docker` run is live on this project, and its engine's cache cannot be shared — end it first");
    }
    let prepared = {
        let (root, config, command) = (root.clone(), config.clone(), spec.command.clone());
        let npm = super::profiles::agent_for(&spec.command).and_then(|a| a.npm_package);
        tokio::task::spawn_blocking(move || prepare::prepare(&root, &config, &command, npm, false)).await??
    };
    // `network: gateway` in sandbox.json narrows the run, unless `--network` said otherwise.
    if spec.network.or(config.network) == Some(super::NetworkChoice::Gateway) {
        spec.destinations.posture =
            spec.destinations.posture.narrower(streamscope_client_templates::destination::Posture::Gateway);
    }
    eprintln!(
        "ssai: sandbox=docker — rootless podman {}, image {}, the project at {}, egress only to {}{}",
        facts.version,
        config.source_name(),
        workspace(&config, &root),
        spec.proxy_origins.join(", "),
        super::destinations_note(&spec.destinations),
    );

    let container_root = prepared.container_root;
    let mut run = RunDir::create(&root, container_root, config.docker)?;
    // Again, now that this run's record is there: two engine runs that
    // started together each see the other, and both stop.
    if config.docker && records_root().is_ok_and(|r| live_engine_on(&r, &boot_id(), &root)) {
        bail!("another `--sandbox docker` run is live on this project, and its engine's cache cannot be shared — end it first");
    }
    let result = run_container(&spec, &config, &prepared, &facts, &exe, &run, verbose).await;
    // Only a container that started can have written as root. A sweep that
    // failed keeps the run dir, so the next run (its owner gone) sweeps again.
    if run.started.get() {
        // Another live run on the project is still writing there: this
        // record waits, and a later run sweeps once none is.
        let live = records_root().is_ok_and(|r| live_run_on(&r, &boot_id(), &root));
        if live {
            eprintln!(
                "ssai: another `--sandbox docker` run is live on (part of) this project — files this run's container \
                 wrote as root are given back when no run is left on it"
            );
        }
        if live || !sweep_project(&exe, &root, container_root).await {
            run.keep = true;
        }
    }
    drop(run);
    result
}

/// The project's `sandbox.json`; without one, the workspace's default image
/// (`default_image`), said; without either, refused naming the file.
fn read_config(
    root: &Path,
    default_image: Option<&streamscope_client_templates::sandbox_image::DefaultImage>,
) -> Result<config::DockerConfig> {
    let file = root.join(config::SANDBOX_FILE);
    let text = match std::fs::read_to_string(&file) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && default_image.is_some() => {
            let default = default_image.context("checked above")?;
            let mut config = config::from_profile_default(default)?;
            config.notes.push(format!(
                "no {} here — the image is your organisation's default for this workspace, {}",
                config::SANDBOX_FILE,
                default.image
            ));
            return Ok(config);
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => bail!(
            "--sandbox docker needs {} naming the image, or a default image your administrator sets on the workspace — e.g. {} or {}",
            file.display(),
            config::example(r#"{"image": "mcr.microsoft.com/devcontainers/base:ubuntu-24.04"}"#),
            config::example(r#"{"devcontainer": ".devcontainer/devcontainer.json"}"#)
        ),
        Err(e) => return Err(e).with_context(|| format!("read {}", file.display())),
    };
    config::resolve(root, &text, &|p| std::fs::read_to_string(p).map_err(Into::into))
}

impl config::DockerConfig {
    /// The image as the banner names it.
    fn source_name(&self) -> String {
        match (&self.source, &self.devcontainer) {
            (config::ImageSource::Image(r), _) => r.clone(),
            (config::ImageSource::Build { .. }, Some(dc)) => format!("built from {}", dc.display()),
            (config::ImageSource::Build { dockerfile, .. }, None) => format!("built from {}", dockerfile.display()),
        }
    }
}

/// The project's path in the container.
fn workspace(config: &config::DockerConfig, root: &Path) -> String {
    config.workspace_folder.clone().unwrap_or_else(|| root.to_string_lossy().into_owned())
}

/// A run's private files, removed when dropped. Its record — the run dir
/// (read-only in the container), and the project, container root and owner
/// a later run reads when this one was killed before its sweep — lives under
/// the cache dir, which outlives a logout and a reboot. Its socket dir (the
/// guard's socket, the exit file) lives under the runtime dir when there is
/// one, for the short path a unix socket needs, and is named in the record.
struct RunDir {
    base: PathBuf,
    run: PathBuf,
    sock: PathBuf,
    /// The container was started.
    started: std::cell::Cell<bool>,
    /// Left for the next run to sweep and remove.
    keep: bool,
}

/// What a run's record holds beside its `run` dir. The owner ([`owner`]) is
/// written last: a record without it is a run starting now.
const PROJECT_FILE: &str = "project";
const OWNER_FILE: &str = "owner";
/// The container's root as the sweep sees it ([`sweep::Root::record`]).
const CONTAINER_ROOT_FILE: &str = "container-root";
/// The socket dir's path.
const SOCK_FILE: &str = "sock";
/// Present when the run has an engine inside (its cache volume in use).
const ENGINE_FILE: &str = "engine";

/// This run's owner, as a run's record and its container record it: `<pid>:<boot
/// id>:<host>`. The boot id makes a record or container left by an earlier
/// boot stale whatever process holds its pid now; the host keeps another
/// machine's record (a shared home) out of this one's judgement.
fn owner() -> String {
    format!("{}:{}:{}", std::process::id(), boot_id(), host_name())
}

/// This machine's name: a home shared between machines (NFS) holds other
/// machines' records, which only their own machine can judge.
fn host_name() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname").map(|s| s.trim().replace(':', "_")).unwrap_or_default()
}

fn boot_id() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id").map(|s| s.trim().to_string()).unwrap_or_default()
}

/// Whether the run `owner` names is still running: this boot, its pid
/// alive (a pid `kill` may not signal, EPERM, is alive). An owner that does
/// not parse is a dead one's. With no boot id to compare (`boot` empty), the
/// pid alone decides — never a live run removed.
fn owner_alive(owner: &str, boot: &str) -> bool {
    let mut parts = owner.trim().splitn(3, ':');
    let (Some(pid), Some(owner_boot)) = (parts.next(), parts.next()) else { return false };
    // Another machine's run (another host, another boot): alive for all this
    // one can tell. This boot's is judged here, whatever the host is called now.
    if parts.next().is_some_and(|host| host != host_name()) && owner_boot != boot {
        return true;
    }
    let Ok(pid) = pid.parse::<i32>() else { return false };
    if !(boot.is_empty() || owner_boot == boot) {
        return false;
    }
    super::pid_alive(pid)
}

/// The longest path a unix socket binds (`sun_path`, less its NUL).
const MAX_SOCKET_PATH: usize = 107;

/// Where runs' records live.
fn records_root() -> Result<PathBuf> {
    Ok(crate::state::cache_dir()?.join("sandbox-runs"))
}

/// Where runs' socket dirs live: the user's runtime dir (short, private)
/// when there is one, else the cache dir.
fn sockets_root() -> Result<PathBuf> {
    match std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from).filter(|d| d.is_absolute() && d.is_dir()) {
        Some(dir) => Ok(dir.join("streamscopeai").join("sandbox-sockets")),
        None => Ok(crate::state::cache_dir()?.join("sandbox-sockets")),
    }
}

impl RunDir {
    fn create(project: &Path, container_root: sweep::Root, engine: bool) -> Result<Self> {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let mut suffix = [0u8; 6];
        rand::rng().fill_bytes(&mut suffix);
        let name = format!("{}-{}", std::process::id(), hex::encode(suffix));
        let (base, sock) = (records_root()?.join(&name), sockets_root()?.join(&name));
        let socket = sock.join("guard.sock");
        if socket.as_os_str().len() > MAX_SOCKET_PATH {
            bail!(
                "the sandbox's socket path {} is longer than a unix socket allows — set XDG_RUNTIME_DIR \
                 (or XDG_CACHE_HOME) to a shorter directory",
                socket.display()
            );
        }
        for parent in [base.parent(), sock.parent()].into_iter().flatten() {
            std::fs::DirBuilder::new().recursive(true).mode(0o700).create(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
        std::fs::DirBuilder::new().mode(0o700).create(&base).with_context(|| format!("create {}", base.display()))?;
        let dir = Self { run: base.join("run"), sock, base, started: Default::default(), keep: false };
        std::fs::write(dir.base.join(PROJECT_FILE), project.as_os_str().as_encoded_bytes())
            .context("record the run's project")?;
        std::fs::write(dir.base.join(CONTAINER_ROOT_FILE), container_root.record())
            .context("record the run's container root")?;
        std::fs::write(dir.base.join(SOCK_FILE), dir.sock.as_os_str().as_encoded_bytes())
            .context("record the run's socket dir")?;
        if engine {
            std::fs::write(dir.base.join(ENGINE_FILE), "").context("record the run's engine")?;
        }
        std::fs::write(dir.base.join(OWNER_FILE), owner()).context("record the run's owner")?;
        // Private to the developer: the container reaches the two it mounts
        // through its root's capabilities over the developer's files (and the
        // agent, under keep-id, is the developer).
        for d in [&dir.run, &dir.sock] {
            std::fs::DirBuilder::new().mode(0o700).create(d).with_context(|| format!("create {}", d.display()))?;
        }
        std::fs::set_permissions(&dir.base, std::fs::Permissions::from_mode(0o700))?;
        Ok(dir)
    }
}

impl Drop for RunDir {
    fn drop(&mut self) {
        if self.keep {
            // Kept for a later sweep, a record needs its project, owner,
            // container root and socket dir — never the start file, which holds
            // the gateway key, nor the CA bundle.
            remove_run_dirs(&[&self.run]);
        } else {
            remove_run_dirs(&[&self.sock, &self.base]);
        }
    }
}

/// Remove a run's socket dir and record. What the container's root made in
/// the socket dir (a directory only it can open) is not the developer's to
/// delete, but is under `podman unshare`.
fn remove_run_dirs(dirs: &[&Path]) {
    for dir in dirs {
        if dir.exists() && std::fs::remove_dir_all(dir).is_err() {
            let _ = std::process::Command::new("podman")
                .args(["unshare", "rm", "-rf", "--"])
                .arg(dir)
                .stdin(std::process::Stdio::null())
                .status();
        }
    }
}

async fn run_container(
    spec: &LaunchSpec,
    config: &config::DockerConfig,
    prepared: &prepare::Prepared,
    facts: &preflight::HostFacts,
    exe: &Path,
    run: &RunDir,
    verbose: bool,
) -> Result<i32> {
    let root = &spec.project_root;
    let workspace = workspace(config, root);
    let cwd = match spec.cwd.strip_prefix(root) {
        Ok(rel) if rel.as_os_str().is_empty() => workspace.clone(),
        Ok(rel) => format!("{}/{}", workspace.trim_end_matches('/'), rel.display()),
        Err(_) => workspace.clone(),
    };
    let home = prepared.user.home.clone();
    // The image names the home (its passwd), the project the workspace: each
    // becomes a volume's container side, where podman reads `:` as options.
    for (what, path) in [("the image's home for the agent user", &home), ("the workspace path", &workspace)] {
        if !path.starts_with('/') || !config::container_path(path) {
            bail!("{what}, {path:?}, is not a path the sandbox can mount (absolute, without `..`, `:` or `,`)");
        }
    }
    // Two mounts on one path, or one inside the other: podman refuses the
    // first, and the second hides one of them.
    if config::overlaps(&workspace, &home) {
        bail!(
            "the workspace path {workspace} overlaps the agent's home {home} — name the image through a \
             devcontainer.json (`\"devcontainer\"` in sandbox.json) with a `workspaceFolder` elsewhere"
        );
    }
    let FileMounts { mounts: mut files, rebased, home_dirs } =
        file_mounts(spec, &home, crate::state::home_dir().ok().as_deref())?;
    // What is mounted read-only is a copy in the run dir, never the original:
    // with an engine the container is privileged, and its root could remount
    // a bind read-write and change the developer's file — the `ssai` binary
    // above all, which the developer runs next, unconfined.
    // The run's dirs (the copies among them) are mounted too.
    for dir in [&run.run, &run.sock] {
        if !plan::mountable(&dir.to_string_lossy()) {
            bail!(
                "{} holds a `:` or `,`, which podman cannot mount — set XDG_CACHE_HOME (and XDG_RUNTIME_DIR) to a plain path",
                dir.display()
            );
        }
    }
    // Only a privileged container (an engine inside) can remount; without
    // one the originals are mounted as they are.
    let binary = if config.docker { copy_into(&run.run, exe, "ssai", Some(0o755))? } else { exe.to_path_buf() };
    if !plan::mountable(&binary.to_string_lossy()) {
        bail!("{} holds a `:` or `,`, which podman cannot mount — move `ssai` to a plain path", binary.display());
    }
    // Where each file is in the container, by its original path: the copies
    // below replace the paths the mounts read from.
    let mounted: Vec<(PathBuf, String)> = files.clone();
    for (i, (from, _)) in files.iter_mut().enumerate() {
        if config.docker && from.is_file() {
            *from = copy_into(&run.run, from, &format!("file-{i}"), None)?;
        }
    }

    // The guard, on the run's socket.
    let socket = run.sock.join("guard.sock");
    // SAFETY: getuid(2) cannot fail.
    let admit = guard::Admit { uid: unsafe { libc::getuid() }, ranges: facts.uid_ranges.clone() };
    let egress = guard::EgressPolicy {
        gateway: super::allow_targets(&spec.proxy_origins)?,
        destinations: spec.destinations.clone(),
    };
    let guard = guard::start_unix(egress, verbose, &socket, admit).await?;

    // The agent's environment: the native one, its paths rebased onto the
    // container's.
    // What the agent inherits is the image's environment, not this process's;
    // git's `core.sshCommand` is the project's, read on the host.
    // The project's `containerEnv` lies over it, then its `remoteEnv`;
    // `${containerEnv:NAME}` reads the container's own: the image's, then
    // `containerEnv`. The home is the sandbox's (the agent's config and the
    // create marker live there).
    let lookup = |over: &[(String, String)], key: &str| {
        over.iter().rev().chain(prepared.env.iter().rev()).find(|(k, _)| k == key).map(|(_, v)| v.clone())
    };
    // A `PATH` of the project's that drops the prefix the tool is installed
    // in keeps it first, or the tool would not be found.
    let agent_bin = format!("{}/bin", prepare::AGENT_PREFIX);
    let on_path = |path: &str| path.split(':').any(|d| d == agent_bin);
    let installed = lookup(&[], "PATH").is_some_and(|p| on_path(&p));
    let keep_tool = |env: &mut Vec<(String, String)>| {
        if installed
            && let Some(path) = lookup(env, "PATH").filter(|p| !on_path(p))
        {
            env.push(("PATH".into(), format!("{agent_bin}:{path}")));
        }
    };
    let mut container: Vec<(String, String)> = Vec::new();
    for (k, v) in prepared.lifecycle.container_env.iter().filter(|(k, _)| k != "HOME") {
        // `${containerEnv:…}` here reads the image's: `containerEnv` cannot name itself.
        let v = config::fill_container_env(v, &|name| lookup(&[], name));
        container.push((k.clone(), v));
    }
    keep_tool(&mut container);
    let container_env = |name: &str| lookup(&container, name);
    let mut user_env = container.clone();
    for (k, v) in prepared.lifecycle.remote_env.iter().filter(|(k, _)| k != "HOME") {
        user_env.push((k.clone(), config::fill_container_env(v, &container_env)));
    }
    keep_tool(&mut user_env);
    let inherited = |key: &str| {
        if key == super::GIT_CORE_SSH_COMMAND {
            return super::git_core_ssh_command(root);
        }
        lookup(&user_env, key).filter(|v| !v.is_empty())
    };
    // With an engine inside, the proxy is the relay on the routing stub's
    // address (`routing.rs`), which the engine's containers reach too: a tool
    // that copies the variable into a container (kind) hands it a working
    // proxy, never `127.0.0.1`, the container's own loopback.
    let relay_host = if config.docker { routing::STUB.to_string() } else { "127.0.0.1".to_string() };
    let mut env = super::sandbox_env_with(spec, (&relay_host, RELAY_PORT), Some(plan::INIT_BINARY), &inherited);
    for (_, v) in env.iter_mut() {
        if let Some(to) = host_to_container(&rebased, &[], root, &workspace, v) {
            *v = to;
        }
    }
    // A config the container does not have is reported by init as one OpenCode
    // does not load there.
    let opencode = spec.opencode.as_ref().map(|launch| {
        let shown = launch.config.to_string_lossy().into_owned();
        let config = host_to_container(&rebased, &mounted, root, &workspace, &shown).unwrap_or(shown);
        init::OpencodeCheck { provider: launch.provider.clone(), config, global: launch.global }
    });
    // A `--ca-file` bundle: in the run dir, every trust-store variable on
    // it — first, so a user's own `-e` for one of them still wins.
    if let Some(pem) = &spec.ca_bundle {
        std::fs::write(run.run.join("ca.pem"), pem).context("write the combined CA bundle")?;
        let at = format!("{}/ca.pem", plan::RUN_MOUNT);
        env.splice(0..0, super::CA_BUNDLE_VARS.iter().map(|k| (k.to_string(), at.clone())));
    }
    // Node's one extra-CA file, when neither the run (no gateway bundle was
    // captured, no `--ca-file`, no `-e`) nor the image or the project names
    // one: the host's system store, so a gateway whose root the host trusts
    // is trusted inside — the image holds only its own public roots. Node
    // reads ONE such file, so an image's own is left as it is. Only Node's
    // additive variable: the replacing ones would drop the image's roots.
    // Best effort: a host with no readable store runs without it.
    if !env.iter().any(|(k, _)| k == NODE_CA_VAR)
        && lookup(&user_env, NODE_CA_VAR).is_none_or(|v| v.is_empty())
        && let Ok(Some(pem)) = crate::commands::run::system_ca_pem()
        && !pem.is_empty()
    {
        match std::fs::write(run.run.join(HOST_CA_FILE), pem) {
            Ok(()) => env.insert(0, (NODE_CA_VAR.to_string(), format!("{}/{HOST_CA_FILE}", plan::RUN_MOUNT))),
            Err(e) => eprintln!("ssai: the host's certificate store is not given to the sandbox ({e})"),
        }
    }
    if let Some(engine) = super::profiles::agent_for(&spec.command).and_then(|a| a.engine) {
        env.extend(engine.env.iter().map(|(k, v)| (k.to_string(), v.to_string())));
    }

    // The lifecycle commands, their `${containerEnv:…}` filled in like the
    // variables'.
    let steps = |steps: &[config::Step]| -> Vec<config::Step> {
        steps
            .iter()
            .map(|s| config::Step {
                hook: s.hook.clone(),
                argv: s.argv.iter().map(|a| config::fill_container_env(a, &container_env)).collect(),
            })
            .collect()
    };
    let create_steps = steps(&prepared.lifecycle.create);
    let start_steps = steps(&prepared.lifecycle.start);
    let create_key = {
        let mut h = Sha256::new();
        h.update(prepared.base.as_bytes());
        h.update(serde_json::to_vec(&create_steps)?);
        // What they run with — the environment, the user, the workspace: a
        // change runs them again.
        h.update(serde_json::to_vec(&(&user_env, prepared.user.uid, prepared.user.gid, &workspace))?);
        hex::encode(&h.finalize()[..12])
    };
    // Laid over the image's environment, last entry winning: the sandbox's
    // own variables (the proxy, the client's) over the project's.
    let env: Vec<(String, String)> = user_env.iter().cloned().chain(env).collect();

    let tty = std::io::IsTerminal::is_terminal(&std::io::stdin());
    let exit_file = run.sock.join("exit");
    let start = init::Start {
        argv: std::iter::once(spec.command.clone()).chain(spec.args.iter().cloned()).collect(),
        env,
        workspace: workspace.clone(),
        create_steps,
        start_steps,
        create_key,
        uid: prepared.user.uid,
        gid: prepared.user.gid,
        home: home.clone(),
        home_dirs,
        cwd: cwd.clone(),
        guard_socket: format!("{}/guard.sock", plan::SOCK_MOUNT),
        relay_port: RELAY_PORT,
        engine: config.docker,
        exit_file: format!("{}/exit", plan::SOCK_MOUNT),
        tty,
        opencode,
    };
    let start_file = run.run.join(plan::START_FILE);
    {
        let mut f = crate::state::create_new_private_file(&start_file)?;
        std::io::Write::write_all(&mut f, serde_json::to_string(&start)?.as_bytes())?;
    }
    std::fs::write(&exit_file, b"")?;
    // Both stay the developer's: the container's root reads the start file
    // and writes the exit file through its capabilities over the developer's
    // (mapped) files. That is also the boundary: the container's root can read
    // whatever of the developer's the container is given, so the run dir holds
    // only what this run hands the agent anyway.

    // The project's grants and holds: git's hooks and config read-only, its
    // git dirs unrenamable, a linked worktree's git dirs reachable.
    let grants = crate::sandbox::protect::resolve(root);
    grants.prepare().context("prepare the project's protected git folders")?;
    let project_mounts = plan::project_mounts(&grants, root, &workspace).context(
        "a git folder of this project has a `:` or `,` in its path, which podman cannot mount — use --sandbox native",
    )?;

    let mut suffix = [0u8; 4];
    rand::rng().fill_bytes(&mut suffix);
    let facts = plan::RunFacts {
        image: prepared.image.clone(),
        name: format!("ssai-{}-{}", std::process::id(), hex::encode(suffix)),
        owner: owner(),
        uid: prepared.user.uid,
        gid: prepared.user.gid,
        project: root.clone(),
        workspace,
        cwd,
        binary,
        run_dir: run.run.clone(),
        sock_dir: run.sock.clone(),
        files,
        home_volume: home_volume(root, &spec.command),
        home,
        engine_volume: config.docker.then(|| engine_volume(root)),
        limits: config.limits.clone(),
        tty,
        project_mounts,
    };
    let mut cmd = tokio::process::Command::new("podman");
    cmd.args(plan::run_argv(&facts));
    let mut signals = super::RunSignals::take()?;
    run.started.set(true);
    let status = super::wait_client(&mut cmd, &mut signals).await.context("run podman")?;
    signals.restore_defaults();

    let refused = guard.refused();
    if !refused.is_empty() {
        eprintln!(
            "ssai: the sandbox refused egress to {} — ask your administrator to add what the project \
             needs to an allowed destination list",
            refused.join(", ")
        );
    }
    let written = read_exit(&exit_file);
    // Podman killed by a signal `n` reads as 128 + n, as the agent's would.
    let code = status.code().unwrap_or_else(|| 128 + std::os::unix::process::ExitStatusExt::signal(&status).unwrap_or(0));
    match written {
        Some(agent) => Ok(agent),
        None if (125..=127).contains(&code) => bail!("podman could not run the sandbox (exit {code}) — see its message above"),
        None => Ok(code),
    }
}

/// The agent's exit code, from the file init wrote in the socket dir — which
/// the agent can write too: never through a symlink, never a FIFO's endless
/// read, a few bytes at most.
fn read_exit(path: &Path) -> Option<i32> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path).ok()?;
    if !f.metadata().ok()?.is_file() {
        return None;
    }
    let mut text = String::new();
    f.take(16).read_to_string(&mut text).ok()?;
    text.trim().parse().ok()
}

/// The single files the container is given read-only.
#[derive(Default)]
struct FileMounts {
    /// `(host path, container path)`.
    mounts: Vec<(PathBuf, String)>,
    /// `(host path, container path)` for every env value to rewrite.
    rebased: Vec<(String, String)>,
    /// The directories under the container's home that hold a mounted file,
    /// for init to give the agent user.
    home_dirs: Vec<String>,
}

/// Every file (or directory) the run's CA list names — its CA bundles and
/// the paths `-e KEY=/path` names — at a path of its own; and a home-scoped
/// client's provisioned files, at their place under the container's home.
fn file_mounts(spec: &LaunchSpec, home: &str, host_home: Option<&Path>) -> Result<FileMounts> {
    let mut out = FileMounts::default();
    let FileMounts { mounts, rebased, home_dirs } = &mut out;
    for (i, file) in spec.ca_files.iter().enumerate() {
        let shown = file.to_string_lossy().into_owned();
        // The env names it: left out, the value would name a path the
        // container does not have.
        // Anything that exists mounts (a file, a directory, `/dev/null`).
        if std::fs::metadata(file).is_err() {
            bail!("{shown} does not exist — the sandbox cannot give it to the client");
        }
        if !plan::mountable(&shown) {
            bail!("{shown} holds a `:` or `,`, which podman cannot mount");
        }
        let name = file.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let to = format!("/run/ssai-files/{i}-{name}");
        mounts.push((file.clone(), to.clone()));
        rebased.push((shown, to));
    }
    let home = home.trim_end_matches('/');
    for file in &spec.home_files {
        let rel = host_home.and_then(|h| file.strip_prefix(h).ok());
        // Plain components only: a `..` would place the mount, and the
        // directories init gives the agent, outside the home.
        let plain = |rel: &Path| rel.components().all(|c| matches!(c, std::path::Component::Normal(_)));
        let Some(rel) = rel.filter(|r| plain(r) && file.is_file() && plan::mountable(&file.to_string_lossy())) else {
            eprintln!(
                "ssai: {} is not given to the sandbox (not a plain file under your home) — the client runs \
                 without it",
                file.display()
            );
            continue;
        };
        mounts.push((file.clone(), format!("{home}/{}", rel.display())));
        let mut dir = PathBuf::new();
        for part in rel.parent().into_iter().flat_map(Path::components) {
            dir.push(part);
            let at = format!("{home}/{}", dir.display());
            if !home_dirs.contains(&at) {
                home_dirs.push(at);
            }
        }
    }
    Ok(out)
}

/// Where host path `host` is in the container: a value `rebased` names, a
/// file `mounts` mounts, or a path under the project `root`, under the
/// `workspace`. `None` for anything else.
fn host_to_container(rebased: &[(String, String)], mounts: &[(PathBuf, String)], root: &Path, workspace: &str, host: &str) -> Option<String> {
    if let Some((_, to)) = rebased.iter().find(|(from, _)| from == host) {
        return Some(to.clone());
    }
    if let Some((_, to)) = mounts.iter().find(|(from, _)| from.as_os_str() == host) {
        return Some(to.clone());
    }
    let rest = host.strip_prefix(root.to_string_lossy().as_ref())?;
    (rest.is_empty() || rest.starts_with('/')).then(|| format!("{}{rest}", workspace.trim_end_matches('/')))
}

/// A copy of `from` in the run dir, named `name`: with `mode`, or the
/// original's (a 0600 key stays 0600, or ssh refuses it).
fn copy_into(run: &Path, from: &Path, name: &str, mode: Option<u32>) -> Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let to = run.join("copies").join(name);
    std::fs::create_dir_all(to.parent().unwrap_or(run)).context("create the run's copies")?;
    // `copy` carries the original's permission bits.
    std::fs::copy(from, &to).with_context(|| format!("copy {} into the run", from.display()))?;
    if let Some(mode) = mode {
        std::fs::set_permissions(&to, std::fs::Permissions::from_mode(mode))?;
    }
    Ok(to)
}

/// A short stable key for the project, leading its volumes' names.
fn project_key(root: &Path) -> String {
    let mut h = Sha256::new();
    h.update(root.as_os_str().as_encoded_bytes());
    h.update([0]);
    hex::encode(&h.finalize()[..8])
}

/// `ssai-home-<project key>`: what every home volume of the project's clients
/// starts with, then `-<client key>`.
fn home_volume_prefix(root: &Path) -> String {
    format!("ssai-home-{}", project_key(root))
}

/// The agent's home for `client` (its launch command) in the project.
fn home_volume(root: &Path, client: &str) -> String {
    format!("{}-{}", home_volume_prefix(root), hex::encode(&Sha256::digest(client.as_bytes())[..4]))
}

/// The engine's cache (`/var/lib/docker`) of the project.
fn engine_volume(root: &Path) -> String {
    format!("ssai-engine-{}", project_key(root))
}

/// Sweep the project under `podman unshare` (see [`sweep`]); `container_root`
/// is [`container_root`]'s answer for the run that wrote it. Best effort: a
/// failure is reported, never fatal — the files stay deletable.
async fn sweep_project(exe: &Path, root: &Path, container_root: sweep::Root) -> bool {
    let status = tokio::process::Command::new("podman")
        .arg("unshare")
        .arg(exe)
        .arg("__sandbox-sweep")
        .arg(root)
        .args(container_root.args())
        .stdin(std::process::Stdio::null())
        .status()
        .await;
    let ok = matches!(&status, Ok(s) if s.success());
    if !ok {
        eprintln!(
            "ssai: could not sweep {} — files the container wrote as root may stay read-only to you until the next run sweeps it",
            root.display()
        );
    }
    ok
}

/// Remove every docker-tier container whose `ssai` is gone (a run killed
/// before it could).
/// Whether every such container is known to be gone: a killed run's
/// container may still be writing, so its project is swept only after.
async fn remove_stale_containers() -> bool {
    let out = tokio::process::Command::new("podman")
        .args(["ps", "-a", "--filter", &format!("label={}", plan::RUN_LABEL), "--format"])
        .arg(format!("{{{{.ID}}}} {{{{index .Labels \"{}\"}}}}", plan::RUN_LABEL))
        .stdin(std::process::Stdio::null())
        .output()
        .await;
    let Ok(out) = out.map_err(drop).and_then(|o| if o.status.success() { Ok(o) } else { Err(()) }) else { return false };
    let boot = boot_id();
    let mut all_gone = true;
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let mut f = line.split_whitespace();
        let Some(id) = f.next() else { continue };
        if !owner_alive(f.next().unwrap_or(""), &boot) {
            let removed = tokio::process::Command::new("podman")
                .args(["rm", "-f", id])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .status()
                .await
                .is_ok_and(|s| s.success());
            all_gone &= removed;
        }
    }
    all_gone
}

/// Remove every run dir whose `ssai` is gone (a run killed before it could),
/// after sweeping the project it names: files that run's container wrote as
/// root would otherwise stay the container's. A live owner's dir is left.
async fn remove_stale_runs(exe: &Path) {
    use std::os::unix::ffi::OsStringExt;
    let Ok(root) = records_root() else { return };
    let boot = boot_id();
    let path_in = |base: &Path, file: &str| std::fs::read(base.join(file)).ok().map(|b| PathBuf::from(std::ffi::OsString::from_vec(b)));
    for (base, owner) in records(&root, &boot) {
        if owner_alive(&owner, &boot) {
            continue;
        }
        // A dead run's start file (its gateway key) and copies go now,
        // whether or not its record has to wait.
        let run_files = base.join("run");
        let _ = tokio::task::spawn_blocking(move || remove_run_dirs(&[&run_files])).await;
        if let Some(project) = path_in(&base, PROJECT_FILE) {
            // A live run on the same project is still writing there: the
            // record waits for it to end.
            if live_run_on(&root, &boot, &project) {
                continue;
            }
            // Unreadable, the keep-id shape: what a non-root agent's run has.
            let container_root = std::fs::read_to_string(base.join(CONTAINER_ROOT_FILE))
                .ok()
                .and_then(|s| sweep::Root::parse(&s))
                .unwrap_or(sweep::Root { uid: Some(1), gid: Some(1) });
            // A project that is no longer a real directory has nothing left to
            // sweep; one whose sweep keeps failing is retired after a few runs,
            // saying so, rather than retried by every run forever.
            let real = std::fs::symlink_metadata(&project).is_ok_and(|m| m.is_dir());
            if real && !sweep_project(exe, &project, container_root).await {
                let tries = std::fs::read_to_string(base.join(TRIES_FILE))
                    .ok()
                    .and_then(|s| s.trim().parse::<u32>().ok())
                    .unwrap_or(0)
                    + 1;
                if tries < MAX_SWEEP_TRIES {
                    let _ = std::fs::write(base.join(TRIES_FILE), tries.to_string());
                    continue;
                }
                eprintln!("ssai: giving up sweeping {} after {tries} tries — check it for files you cannot edit", project.display());
            }
        }
        // Only a socket dir where runs keep them — `…/streamscopeai/sandbox-sockets/`
        // under any session's runtime dir, or the cache dir — is removed,
        // whatever the record says.
        let sock = path_in(&base, SOCK_FILE).filter(|s| s.parent().is_some_and(|p| p.ends_with("streamscopeai/sandbox-sockets")));
        let _ = tokio::task::spawn_blocking(move || {
            let dirs: Vec<&Path> = sock.iter().map(PathBuf::as_path).chain([base.as_path()]).collect();
            remove_run_dirs(&dirs);
        })
        .await;
    }
}

/// How long another machine's record counts as live without a word from it.
const FOREIGN_RECORD_AGE: std::time::Duration = std::time::Duration::from_secs(7 * 24 * 3600);

/// How many runs try a stale record's sweep before giving it up.
const MAX_SWEEP_TRIES: u32 = 3;
/// A stale record's failed sweeps so far.
const TRIES_FILE: &str = "tries";

/// Every run's record under `root` with its owner. A record whose owner is
/// not written yet (absent, or created and not filled) is a run starting
/// now, this boot: the pid in its name stands in.
fn records(root: &Path, boot: &str) -> Vec<(PathBuf, String)> {
    let Ok(entries) = std::fs::read_dir(root) else { return Vec::new() };
    entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name();
            let pid = name.to_str()?.split('-').next().filter(|p| p.parse::<u32>().is_ok())?.to_string();
            let base = entry.path();
            let owner = std::fs::read_to_string(base.join(OWNER_FILE))
                .ok()
                .filter(|o| o.contains(':'))
                .unwrap_or_else(|| format!("{pid}:{boot}"));
            // Another machine's record is alive for all this one can tell —
            // for a while: one that machine left behind for a week is stale.
            let foreign = owner.trim().splitn(3, ':').nth(2).is_some_and(|h| h != host_name());
            let old = std::fs::metadata(base.join(OWNER_FILE))
                .and_then(|m| m.modified())
                .is_ok_and(|t| t.elapsed().is_ok_and(|age| age > FOREIGN_RECORD_AGE));
            let owner = if foreign && old { "0:stale".to_string() } else { owner };
            Some((base, owner))
        })
        .collect()
}

/// Whether another live run (not this one) has an engine on `project` itself
/// (whose cache volume is that project's).
fn live_engine_on(root: &Path, boot: &str, project: &Path) -> bool {
    let me = format!("{}:", std::process::id());
    records(root, boot).into_iter().any(|(base, owner)| {
        !owner.starts_with(&me)
            && owner_alive(&owner, boot)
            && base.join(ENGINE_FILE).exists()
            && std::fs::read(base.join(PROJECT_FILE)).is_ok_and(|p| p == project.as_os_str().as_encoded_bytes())
    })
}

/// Whether another live run (not this one) has a project that overlaps
/// `project` — the same one, or one inside the other: a sweep of either
/// walks what the other's container is writing.
fn live_run_on(root: &Path, boot: &str, project: &Path) -> bool {
    use std::os::unix::ffi::OsStringExt;
    let me = format!("{}:", std::process::id());
    records(root, boot).into_iter().any(|(base, owner)| {
        !owner.starts_with(&me)
            && owner_alive(&owner, boot)
            && std::fs::read(base.join(PROJECT_FILE))
                .map(|p| PathBuf::from(std::ffi::OsString::from_vec(p)))
                .is_ok_and(|other| other.starts_with(project) || project.starts_with(&other))
    })
}

/// `ssai sandbox prepare`: (re)build the project's images.
pub fn prepare_project(
    root: &Path,
    command: &str,
    default_image: Option<&streamscope_client_templates::sandbox_image::DefaultImage>,
) -> Result<()> {
    let config = read_config(root, default_image)?;
    for note in &config.notes {
        eprintln!("ssai: {note}");
    }
    preflight::run(config.docker, config.limits.cpus.is_some())?;
    let npm = super::profiles::agent_for(command).and_then(|a| a.npm_package);
    let prepared = prepare::prepare(root, &config, command, npm, true)?;
    eprintln!("ssai: the docker sandbox's image for {command} is {}", prepared.image);
    Ok(())
}

/// `ssai sandbox status`: each project's images and volumes, with sizes.
pub fn status() -> Result<()> {
    images::status()
}

/// `ssai sandbox prune --project`: remove one project's images and volumes;
/// refused while a run is live on it.
pub fn prune_project(root: &Path) -> Result<()> {
    if records_root().is_ok_and(|r| live_run_on(&r, &boot_id(), root)) {
        bail!("a `--sandbox docker` run is still running on {} — end it first, then prune", root.display());
    }
    images::prune_project(root)
}

/// `ssai sandbox prune`: remove every docker-tier volume and image of this
/// user (the agents' homes and engine caches of every project).
pub fn prune() -> Result<()> {
    let run = |args: &[&str]| std::process::Command::new("podman").args(args).stdin(std::process::Stdio::null()).output();
    // A forced volume removal would take a live run's container with it.
    let label = format!("label={}", plan::RUN_LABEL);
    let format = format!("{{{{index .Labels \"{}\"}}}}", plan::RUN_LABEL);
    let owners = run(&["ps", "-a", "--filter", &label, "--format", &format]).context("list podman containers")?;
    // Nothing listed because podman failed is not "nothing running".
    if !owners.status.success() {
        bail!("could not list the sandbox's containers — {}", String::from_utf8_lossy(&owners.stderr).trim());
    }
    let boot = boot_id();
    if String::from_utf8_lossy(&owners.stdout).lines().any(|o| owner_alive(o, &boot)) {
        bail!("a `--sandbox docker` run is still running — end it first, then prune");
    }
    let volumes = run(&["volume", "ls", "--format", "{{.Name}}"]).context("list podman volumes")?;
    let names: Vec<String> = String::from_utf8_lossy(&volumes.stdout)
        .lines()
        .filter(|n| n.starts_with("ssai-home-") || n.starts_with("ssai-engine-"))
        .map(str::to_string)
        .collect();
    let removed = |args: &[&str]| run(args).is_ok_and(|o| o.status.success());
    let volumes = names.iter().filter(|n| removed(&["volume", "rm", "-f", n])).count();
    // The images by the one rule (`images`), without force: one a container
    // of the developer's uses, or named by them too, stays.
    let (images, kept) = images::prune_all()?;
    // The cached user ids go with the images; the build records stay: they
    // are what a changed recipe or reference is compared with, and a prune
    // must not let the next run build or pull unasked.
    if let Ok(cache) = crate::state::cache_dir() {
        let _ = std::fs::remove_dir_all(cache.join("sandbox-ids"));
    }
    eprintln!("ssai: removed {volumes} sandbox volume(s) and {images} image(s)");
    if kept > 0 {
        eprintln!("ssai: kept {kept} image(s) a container uses or you named too");
    }
    if volumes < names.len() {
        bail!("{} volume(s) could not be removed", names.len() - volumes);
    }
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_host_path_is_found_where_the_container_has_it() {
        let rebased = [("/home/dev/ca.pem".to_string(), "/run/ssai-files/0-ca.pem".to_string())];
        let mounts = [(PathBuf::from("/home/dev/.config/opencode/opencode.json"), "/home/agent/.config/opencode/opencode.json".to_string())];
        let at = |host: &str| host_to_container(&rebased, &mounts, Path::new("/home/dev/app"), "/workspaces/app/", host);
        assert_eq!(at("/home/dev/ca.pem").as_deref(), Some("/run/ssai-files/0-ca.pem"));
        assert_eq!(at("/home/dev/.config/opencode/opencode.json").as_deref(), Some("/home/agent/.config/opencode/opencode.json"));
        assert_eq!(at("/home/dev/app/.opencode/opencode.json").as_deref(), Some("/workspaces/app/.opencode/opencode.json"));
        assert_eq!(at("/home/dev/app").as_deref(), Some("/workspaces/app"));
        assert_eq!(at("/home/dev/apple/x"), None);
        assert_eq!(at("/home/dev/other.json"), None);
    }

    fn spec(home_files: Vec<PathBuf>) -> LaunchSpec {
        LaunchSpec {
            command: "codex".into(),
            args: vec![],
            project_root: PathBuf::from("/p"),
            cwd: PathBuf::from("/p"),
            proxy_origins: vec![],
            destinations: Default::default(),
            network: None,
            default_image: None,
            env: vec![],
            ca_files: vec![],
            ca_bundle: None,
            home_files,
            client_files: vec![],
            private_project: false,
            opencode: None,
        }
    }

    #[test]
    fn a_project_without_sandbox_json_takes_the_profile_default_and_its_own_file_wins() {
        use streamscope_client_templates::sandbox_image::DefaultImage;
        let root = std::env::temp_dir().join(format!("ssai-default-image-{}-{}", std::process::id(), rand::random::<u32>()));
        std::fs::create_dir_all(root.join(".streamscopeai")).unwrap();
        let default = DefaultImage { image: "ghcr.io/team/dev:1".into(), docker: true, memory: Some("8g".into()), cpus: Some(2.0) };
        // No file, no default: refused, naming the file.
        let err = read_config(&root, None).unwrap_err();
        assert!(format!("{err:#}").contains("sandbox.json naming the image"), "{err:#}");
        // No file: the default, whole, and said.
        let c = read_config(&root, Some(&default)).unwrap();
        assert_eq!(c.source, config::ImageSource::Image("ghcr.io/team/dev:1".into()));
        assert!(c.docker);
        assert_eq!((c.limits.memory.as_deref(), c.limits.cpus, c.limits.pids), (Some("8g"), Some(2.0), config::DEFAULT_PIDS));
        assert!(c.notes.iter().any(|n| n.contains("your organisation's default")), "{:?}", c.notes);
        // A default the rules refuse is refused here too.
        let bad = DefaultImage { image: "dir:/etc".into(), ..default.clone() };
        assert!(read_config(&root, Some(&bad)).is_err());
        // The project's own file wins whole.
        std::fs::write(root.join(config::SANDBOX_FILE), config::example(r#"{"image": "ubuntu:24.04"}"#)).unwrap();
        let c = read_config(&root, Some(&default)).unwrap();
        assert_eq!(c.source, config::ImageSource::Image("ubuntu:24.04".into()));
        assert!(!c.docker && c.limits.memory.is_none() && c.notes.is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_home_file_is_mounted_in_place_and_its_directories_go_to_the_agent() {
        let host = std::env::temp_dir().join(format!("ssai-mounts-{}", std::process::id()));
        std::fs::create_dir_all(host.join(".config/goose")).unwrap();
        std::fs::write(host.join(".config/goose/config.yaml"), "x").unwrap();
        std::fs::write(host.join(".codex.toml"), "x").unwrap();
        let files = vec![
            host.join(".config/goose/config.yaml"),
            host.join(".codex.toml"),
            // Each refused, and named on stderr: outside the home, a `..`, absent.
            PathBuf::from("/etc/passwd"),
            host.join(".config/../.codex.toml"),
            host.join(".config/missing.toml"),
        ];
        let m = file_mounts(&spec(files), "/home/vscode/", Some(&host)).unwrap();
        assert_eq!(
            m.mounts,
            [
                (host.join(".config/goose/config.yaml"), "/home/vscode/.config/goose/config.yaml".to_string()),
                (host.join(".codex.toml"), "/home/vscode/.codex.toml".to_string()),
            ]
        );
        assert_eq!(m.home_dirs, ["/home/vscode/.config", "/home/vscode/.config/goose"]);
        // No host home: nothing under it to mount.
        let none = file_mounts(&spec(vec![host.join(".codex.toml")]), "/home/vscode", None).unwrap();
        assert!(none.mounts.is_empty() && none.home_dirs.is_empty());
        let _ = std::fs::remove_dir_all(&host);
    }


    #[test]
    fn an_owner_is_alive_only_this_boot_with_its_pid_running() {
        let boot = "b0b0";
        let me = std::process::id();
        assert!(owner_alive(&format!("{me}:{boot}"), boot), "this run, this boot");
        assert!(owner_alive(&format!("{me}:{boot}\n"), boot), "as read back from its file");
        assert!(!owner_alive(&format!("{me}:another-boot"), boot), "a live pid from an earlier boot is a reused one");
        // A pid above the kernel's maximum is never running.
        assert!(!owner_alive(&format!("{}:{boot}", i32::MAX), boot));
        for bad in ["", "42", ":b0b0", "x:b0b0", "0:b0b0", "-1:b0b0"] {
            assert!(!owner_alive(bad, boot), "{bad:?}");
        }
        assert!(owner_alive(&format!("{me}:{boot}"), ""), "no boot id to compare: the pid decides");
        assert!(owner().starts_with(&format!("{me}:")));
        // Another machine's record (a shared home): never judged dead here.
        assert!(owner_alive(&format!("{}:another-boot:another-host", i32::MAX), boot));
        assert!(!owner_alive(&format!("{}:{boot}:{}", i32::MAX, host_name()), boot), "this machine's, dead");
    }


    #[test]
    fn a_live_run_on_an_overlapping_project_holds_the_sweep() {
        let root = std::env::temp_dir().join(format!("ssai-records-{}-{}", std::process::id(), rand::random::<u32>()));
        // A live run (pid 1 is always running) on /mono/svc.
        let rec = root.join("1-aa");
        std::fs::create_dir_all(&rec).unwrap();
        std::fs::write(rec.join(PROJECT_FILE), "/mono/svc").unwrap();
        std::fs::write(rec.join(OWNER_FILE), "1:b").unwrap();
        for overlapping in ["/mono/svc", "/mono", "/mono/svc/sub"] {
            assert!(live_run_on(&root, "b", Path::new(overlapping)), "{overlapping}");
        }
        for apart in ["/mono/web", "/mono/svc2", "/other"] {
            assert!(!live_run_on(&root, "b", Path::new(apart)), "{apart}");
        }
        // Positive control: the same record from an earlier boot is not live.
        assert!(!live_run_on(&root, "another-boot", Path::new("/mono/svc")));
        // This run's own record never holds it.
        let mine = root.join(format!("{}-bb", std::process::id()));
        std::fs::create_dir_all(&mine).unwrap();
        std::fs::write(mine.join(PROJECT_FILE), "/mine").unwrap();
        std::fs::write(mine.join(OWNER_FILE), owner()).unwrap();
        assert!(!live_run_on(&root, &boot_id(), Path::new("/mine")));
        // An engine is held only by a live engine run on the same project.
        assert!(!live_engine_on(&root, "b", Path::new("/mono/svc")), "no engine in that run");
        std::fs::write(rec.join(ENGINE_FILE), "").unwrap();
        assert!(live_engine_on(&root, "b", Path::new("/mono/svc")));
        assert!(!live_engine_on(&root, "b", Path::new("/mono")), "a nested project has its own engine cache");
        let _ = std::fs::remove_dir_all(&root);
    }


    #[test]
    fn the_exit_file_is_read_only_as_a_short_regular_file() {
        let dir = std::env::temp_dir().join(format!("ssai-exit-{}-{}", std::process::id(), rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("exit");
        std::fs::write(&f, "7\n").unwrap();
        assert_eq!(read_exit(&f), Some(7));
        // A symlink to an endless device, a FIFO with no writer, a long file:
        // none is read as a code, and none blocks.
        std::os::unix::fs::symlink("/dev/zero", dir.join("link")).unwrap();
        assert_eq!(read_exit(&dir.join("link")), None);
        let fifo = std::ffi::CString::new(dir.join("fifo").to_string_lossy().as_bytes()).unwrap();
        // SAFETY: a valid C path.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert_eq!(read_exit(&dir.join("fifo")), None);
        std::fs::write(dir.join("long"), "1".repeat(1 << 20)).unwrap();
        assert_eq!(read_exit(&dir.join("long")), None, "read 16 bytes at most");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
