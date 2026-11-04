//! Sandbox backend for `ssai run` — launch a provisioned agent CLI
//! confined to the project (filesystem) with network egress allowed only to the
//! gateway proxy and the destinations the tenant's lists allow for the
//! workspace. One enforcing backend: `native`, the always-on,
//! zero-prerequisite in-process path (Landlock + seccomp + a loopback egress
//! guard). Fail-closed.

pub mod guard;
pub mod profiles;
pub mod protect;

#[cfg(target_os = "linux")]
mod interposer;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "linux")]
mod podman;
// Windows confines by the account, whose temp folder is its own.
#[cfg(not(windows))]
mod scratch;
#[cfg(any(windows, test))]
pub mod windows;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod state_dirs;

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use rand::Rng;
#[cfg(target_os = "linux")]
use serde::{Deserialize, Serialize};

/// What the user asked for via `--sandbox`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxChoice {
    Auto,
    Native,
    Off,
    Learn,
    /// A rootless Podman container (Linux). Asked for by name only: `auto`
    /// never chooses it.
    Docker,
}

impl SandboxChoice {
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "native" => Ok(Self::Native),
            "off" | "none" => Ok(Self::Off),
            "learn" => Ok(Self::Learn),
            "docker" => Ok(Self::Docker),
            other => bail!("unknown --sandbox {other:?} — use auto|native|docker|off|learn"),
        }
    }
}

/// The resolved backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Native,
    Off,
    /// A one-shot observation pass (Linux only): the client runs with egress still
    /// pinned to the gateway and secrets still denied, but the filesystem is NOT
    /// Landlock-restricted — instead every file it opens is recorded, and the
    /// non-secret `$HOME` paths it touched are merged into the user's global
    /// sandbox profile so the next confined run allows them. Not an enforcing
    /// sandbox — a debugging aid to teach the profile what a client needs.
    ///
    /// Constructed only under `cfg(linux)` — `select_tier` refuses `--sandbox
    /// learn` elsewhere — so off Linux it is a variant nothing can reach.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Learn,
    /// The client in a rootless Podman container: the project mounted, no
    /// network but the guard's socket. Constructed only under `cfg(linux)`.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Docker,
}

/// Everything needed to launch one confined client.
pub struct LaunchSpec {
    pub command: String,
    pub args: Vec<String>,
    /// The project root (the `.streamscopeai/` ancestor) — confined read-write.
    pub project_root: PathBuf,
    /// Where to launch the client (the invocation cwd; always under the root).
    pub cwd: PathBuf,
    /// Gateway proxy origins (`scheme://host[:port]`) — always reachable.
    pub proxy_origins: Vec<String>,
    /// What else the client may reach: the workspace's destination lists.
    pub destinations: streamscope_client_templates::destination::Policy,
    /// Extra env for the client (CA vars, per-agent quirks, user `-e`). The
    /// proxy vars are added by the native launcher once the guard port is known.
    pub env: Vec<(String, String)>,
    /// CA files to expose read-only inside the sandbox. Read by the Linux
    /// backend, which adds them to the Landlock ruleset, and on Windows, which
    /// grants them to the sandbox account; macOS confines through Seatbelt and
    /// reaches its CA through the env vars in `env` instead.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub ca_files: Vec<PathBuf>,
    /// A combined trust bundle (`--ca-file`) for the launch to write and point
    /// every trust-store variable at ([`point_at_ca_bundle`]): beside the
    /// run's scratch dir when confined — outside every run's grant, so no
    /// other confined run can add a CA to it — else a private temp file.
    pub ca_bundle: Option<Vec<u8>>,
    /// A home-scoped client's provisioned files, under the developer's home:
    /// the docker tier mounts each read-only at its place under the
    /// container's home. The native tiers reach them where they are.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub home_files: Vec<PathBuf>,
    /// Every file the client was provisioned with, in the project or the
    /// home. Windows grants the sandbox account each one to read: they are
    /// written readable by the developer alone (they hold the gateway key),
    /// so the account's grant on their folder does not reach them.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub client_files: Vec<PathBuf>,
    /// Windows: the developer accepted a project outside their profile
    /// (`--allow-outside-profile`).
    #[cfg_attr(not(windows), allow(dead_code))]
    pub allow_outside_profile: bool,
}

/// The trust-store variables a combined bundle answers: the three that
/// REPLACE the store (why the bundle is complete), and Node's additive one.
const CA_BUNDLE_VARS: [&str; 4] = ["SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS"];

/// Point every [`CA_BUNDLE_VARS`] entry at the bundle written to `path`, and
/// grant it read-only. Prepended, so a user's own `-e` for one of them still wins.
fn point_at_ca_bundle(spec: &mut LaunchSpec, path: &Path) {
    let value = path.to_string_lossy().into_owned();
    spec.env.splice(0..0, CA_BUNDLE_VARS.iter().map(|k| (k.to_string(), value.clone())));
    spec.ca_files.push(path.to_path_buf());
}

/// An unconfined run's combined trust bundle: a private temp file — a random
/// name, created exclusively, 0600 — removed when dropped. No confined run
/// shares an unconfined one's lifetime.
struct TempCaBundle(PathBuf);

impl TempCaBundle {
    fn write_in(dir: &Path, pem: &[u8]) -> Result<Self> {
        let mut suffix = [0u8; 8];
        rand::rng().fill_bytes(&mut suffix);
        let path = dir.join(format!("streamscope-ca-{}.pem", hex::encode(suffix)));
        let mut file = crate::state::create_new_private_file(&path).context("create the combined CA bundle")?;
        // Ours from here: a failed write removes it.
        let bundle = Self(path);
        std::io::Write::write_all(&mut file, pem)
            .with_context(|| format!("write combined CA {}", bundle.0.display()))?;
        Ok(bundle)
    }
}

impl Drop for TempCaBundle {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}


/// The filesystem + network policy the native trampoline applies to itself.
/// Serialized to the re-exec child so it can confine a single-threaded process
/// (avoids the fork-with-threads hazard of `pre_exec` in the tokio parent).
/// Linux-only: macOS confines through Seatbelt (`/usr/bin/sandbox-exec`)
/// without a trampoline, so the policy struct doesn't apply there.
#[cfg(target_os = "linux")]
#[derive(Debug, Serialize, Deserialize)]
pub struct SandboxPolicy {
    /// Loopback TCP ports the client may connect to: the guard's, plus the
    /// engine's for an engine-backed client.
    pub net_connect: Vec<u16>,
    pub fs_rw: Vec<PathBuf>,
    pub fs_ro: Vec<PathBuf>,
    /// Path prefixes denied even when a broader allow would cover them. In learn
    /// mode these are the secret prefixes the observer refuses to record.
    pub fs_deny: Vec<PathBuf>,
    /// Learn mode (`Some`): don't Landlock-restrict the filesystem; instead record
    /// every non-secret `$HOME` path the client opens to this file, one per line,
    /// for the parent to fold into the global sandbox profile. `None` = enforce.
    #[serde(default)]
    pub learn_record: Option<PathBuf>,
}

/// Resolve the backend for the requested choice, probing host capabilities and
/// failing closed when the requested (or any) confinement isn't available.
pub fn select_tier(choice: SandboxChoice) -> Result<Tier> {
    match choice {
        SandboxChoice::Off => Ok(Tier::Off),
        SandboxChoice::Learn => {
            // Learn observes at the syscall layer (seccomp user-notification on
            // `openat`), which the native Linux backend provides; there is no
            // equivalent on the macOS Seatbelt backend yet.
            #[cfg(target_os = "linux")]
            {
                ensure_native_supported()?;
                Ok(Tier::Learn)
            }
            #[cfg(not(target_os = "linux"))]
            {
                bail!(
                    "--sandbox learn is only supported on Linux — run the confined client with \
                     --sandbox native and add any missing path with `-e KEY=/abs/path`"
                )
            }
        }
        SandboxChoice::Native => {
            ensure_native_supported()?;
            Ok(Tier::Native)
        }
        // The container's own preflight (podman, rootless, user namespaces)
        // runs at launch, where it can name each missing piece.
        SandboxChoice::Docker => {
            #[cfg(target_os = "linux")]
            {
                Ok(Tier::Docker)
            }
            #[cfg(not(target_os = "linux"))]
            {
                bail!("--sandbox docker runs on Linux only — on this host use --sandbox native")
            }
        }
        SandboxChoice::Auto => {
            match native_probe() {
                Ok(()) => Ok(Tier::Native),
                Err(reason) => bail!(
                    "no usable sandbox on this host — the native sandbox isn't available ({reason}). \
                     Run on a host with native-sandbox support, or re-run with --sandbox off to \
                     launch unconfined."
                ),
            }
        }
    }
}

/// Whether the native sandbox can be enforced on this host, and if not, why:
/// a short parenthetical naming what is missing, so a developer on the wrong
/// platform (or without the Windows setup) gets actionable advice.
fn native_probe() -> std::result::Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        if linux::confinement_supported() {
            Ok(())
        } else {
            Err("Linux native confinement needs Landlock filesystem+network confinement — typically \
                 kernel ≥6.7 with the LSM enabled and not blocked by container/seccomp policy"
                .into())
        }
    }
    #[cfg(target_os = "macos")]
    {
        if macos::confinement_supported() {
            Ok(())
        } else {
            Err("macOS native confinement needs `/usr/bin/sandbox-exec` (Seatbelt), which is normally \
                 shipped by Apple"
                .into())
        }
    }
    #[cfg(windows)]
    {
        windows::setup::probe().map(drop)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        Err("the native sandbox is implemented on Linux, macOS and Windows only".into())
    }
}

fn ensure_native_supported() -> Result<()> {
    native_probe()
        .map_err(|reason| anyhow::anyhow!("--sandbox native requested but this host can't enforce it ({reason})"))
}

/// Parse the proxy origins into `(host, port)` CONNECT targets for the guard.
pub fn allow_targets(origins: &[String]) -> Result<Vec<(String, u16)>> {
    let mut out = Vec::new();
    for o in origins {
        let url = url::Url::parse(o).map_err(|e| anyhow::anyhow!("bad proxy origin {o:?}: {e}"))?;
        let host = url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("proxy origin {o:?} has no host"))?
            .to_string();
        let port = url.port_or_known_default().unwrap_or(443);
        out.push((host, port));
    }
    if out.is_empty() {
        bail!("no gateway proxy origin recorded — re-run `ssai provision` (or `sync`)");
    }
    Ok(out)
}

/// One startup line naming the active sandbox and what it enforces. Printed for
/// every mode before the client takes over the terminal, so the operator always
/// knows which confinement is live (and, for `off`, that there is none).
fn print_sandbox_banner(spec: &LaunchSpec, tier: Tier) {
    match tier {
        Tier::Off => eprintln!(
            "ssai: sandbox=off — WARNING: {} runs with no filesystem or egress confinement",
            spec.command,
        ),
        Tier::Native => {
            eprintln!(
                "ssai: sandbox=native — filesystem confined to {}, egress only to {}{}",
                spec.project_root.display(),
                spec.proxy_origins.join(", "),
                destinations_note(&spec.destinations),
            );
            // Landlock grants a tree whole: nothing inside the project can be
            // held read-only (`protect`), which the other backends do.
            if cfg!(target_os = "linux") {
                eprintln!(
                    "ssai: note — on Linux the agent can also change the project's git hooks and config \
                     (.git/hooks, .git/config — in a linked worktree, its main repository's too) and \
                     .streamscopeai/; look at them before running git or ssai there outside the sandbox \
                     (`--sandbox docker` holds them read-only)"
                );
            }
        }
        Tier::Learn => eprintln!(
            "ssai: sandbox=learn — OBSERVE ONLY: filesystem NOT confined (egress still only \
             to {}); recording the paths {} opens to teach your global sandbox profile",
            spec.proxy_origins.join(", "),
            spec.command,
        ),
        // Printed by the container launch, once it knows the image.
        Tier::Docker => {}
    }
}

/// The banner's account of the destination lists, empty when none applies.
fn destinations_note(policy: &streamscope_client_templates::destination::Policy) -> String {
    let (allow, block) = (policy.allow.len(), policy.block.len());
    match (allow, block) {
        (0, 0) => String::new(),
        (a, 0) => format!(" and {a} allowed destination(s)"),
        (0, b) => format!(" ({b} blocked destination(s))"),
        (a, b) => format!(" and {a} allowed destination(s), {b} blocked"),
    }
}

/// Launch `spec` under the resolved `tier`. Returns the client's exit code.
/// `verbose` surfaces the egress guard's per-connection denial lines; they stay
/// silent by default so they can't corrupt the client's TUI.
pub async fn launch(mut spec: LaunchSpec, tier: Tier, verbose: bool) -> Result<i32> {
    print_sandbox_banner(&spec, tier);
    match tier {
        Tier::Off => {
            let bundle = match spec.ca_bundle.take() {
                Some(pem) => Some(TempCaBundle::write_in(&std::env::temp_dir(), &pem)?),
                None => None,
            };
            if let Some(b) = &bundle {
                point_at_ca_bundle(&mut spec, &b.0);
            }
            spawn_unconfined(&spec).await
        }
        Tier::Native => launch_confined(spec, verbose, false).await,
        Tier::Learn => launch_confined(spec, verbose, true).await,
        #[cfg(target_os = "linux")]
        Tier::Docker => podman::launch(spec, verbose).await,
        #[cfg(not(target_os = "linux"))]
        Tier::Docker => bail!("--sandbox docker runs on Linux only"),
    }
}

/// `ssai __sandbox-init <start file>`: a docker-sandbox container's PID 1.
pub fn podman_init(start_file: &Path) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        podman::init::main(start_file)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = start_file;
        bail!("__sandbox-init runs only in a Linux container")
    }
}

/// `ssai __sandbox-sweep <root> [--container-root-uid <id>] [--container-root-gid <id>]`,
/// under `podman unshare`.
pub fn podman_sweep(root: &Path, uid: Option<u32>, gid: Option<u32>) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        podman::sweep::main(root, podman::sweep::Root { uid, gid })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (root, uid, gid);
        bail!("__sandbox-sweep runs only on Linux")
    }
}

/// `ssai sandbox prepare`: (re)build the project's docker-sandbox images for
/// the client launched as `command`.
pub fn podman_prepare(root: &Path, command: &str) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        podman::prepare_project(root, command)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (root, command);
        bail!("the docker sandbox runs on Linux only")
    }
}

/// `ssai sandbox prune`: remove every docker-sandbox volume and image.
pub fn podman_prune() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        podman::prune()
    }
    #[cfg(not(target_os = "linux"))]
    {
        bail!("the docker sandbox runs on Linux only")
    }
}

async fn spawn_unconfined(spec: &LaunchSpec) -> Result<i32> {
    // On Windows the program is resolved as the shell would, on the PATH and
    // PATHEXT the client is given (`-e PATH=…` picks the binary): an npm-installed client
    // is a `.cmd`, which a bare name given to the OS never reaches. Elsewhere
    // the OS searches the child's PATH itself.
    #[cfg(windows)]
    let program = {
        let child = |name: &str| spec.env.iter().rev().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str());
        crate::program::find_on(&spec.command, child("PATH").map(std::ffi::OsStr::new), child("PATHEXT"))
            .unwrap_or_else(|| PathBuf::from(&spec.command))
    };
    #[cfg(not(windows))]
    let program = PathBuf::from(&spec.command);
    let mut cmd = tokio::process::Command::new(&program);
    cmd.args(&spec.args).current_dir(&spec.cwd).env("PWD", &spec.cwd);
    for (k, v) in &spec.env {
        cmd.env(k, v);
    }
    // While the client runs, Ctrl-C is its own: this process takes no default
    // action on it (exiting would leave a `.cmd` client's "Terminate batch
    // job?" prompt on a terminal nothing waits on any more).
    #[cfg(windows)]
    let _ctrl_c = tokio::signal::windows::ctrl_c().ok();
    let status = cmd.status().await.map_err(|e| {
        // A `.cmd` launcher runs through cmd.exe, which cannot be given a line
        // break inside an argument: Rust refuses one (it escapes `"` and `%`).
        let batch = std::path::Path::new(&program)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("cmd") || ext.eq_ignore_ascii_case("bat"));
        let line_break = spec.args.iter().any(|a| a.contains(['\r', '\n']));
        if cfg!(windows) && batch && line_break && e.kind() == std::io::ErrorKind::InvalidInput {
            anyhow::anyhow!(
                "{e} — {} is a `.cmd` launcher, which cannot be given an argument holding a line break; \
                 pass that text some other way (a file, the tool's own prompt)",
                spec.command
            )
        } else {
            anyhow::Error::new(e).context(format!("start {}", spec.command))
        }
    })?;
    Ok(status.code().unwrap_or(1))
}

/// The client's env under a sandbox: `spec.env` plus the proxy vars that
/// funnel it through the guard. Node ignores `HTTPS_PROXY` without
/// `NODE_USE_ENV_PROXY=1`. Loopback is exempt (`NO_PROXY`): a client that talks
/// to a local helper over HTTP — an engine-backed client to its engine — would
/// otherwise send that traffic to the guard, which refuses it. A loopback name
/// a gateway origin uses is NOT exempt — that gateway is reached through the
/// guard like any other.
///
/// `inherited` reads a value the child would inherit from this process (and
/// git's `core.sshCommand`): the JVM options are the user's own, extended; an
/// ssh setting of the user's own is left as it is.
fn sandbox_env(spec: &LaunchSpec, guard_port: u16, inherited: &dyn Fn(&str) -> Option<String>) -> Vec<(String, String)> {
    let exe = std::env::current_exe().ok().map(|e| e.to_string_lossy().into_owned());
    sandbox_env_with(spec, guard_port, exe.as_deref(), inherited)
}

/// [`sandbox_env`] with the `ssai` binary the client's git runs for SSH
/// named: its path as the client sees it.
fn sandbox_env_with(
    spec: &LaunchSpec,
    guard_port: u16,
    exe: Option<&str>,
    inherited: &dyn Fn(&str) -> Option<String>,
) -> Vec<(String, String)> {
    let proxy = format!("http://127.0.0.1:{guard_port}");
    // `PWD` names the launch directory, as a shell would set it: a client that
    // takes its working directory from `$PWD` (OpenCode does, before `cwd()`)
    // would otherwise work in whatever directory `ssai` was started
    // from, outside the confinement root.
    let mut env = vec![("PWD".to_string(), spec.cwd.to_string_lossy().into_owned())];
    env.extend(spec.env.iter().cloned());
    for k in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"] {
        env.push((k.to_string(), proxy.clone()));
    }
    env.push(("NODE_USE_ENV_PROXY".to_string(), "1".to_string()));
    let gateway_hosts: Vec<String> = spec
        .proxy_origins
        .iter()
        .filter_map(|o| url::Url::parse(o).ok()?.host_str().map(|h| h.trim_matches(['[', ']']).to_ascii_lowercase()))
        .collect();
    let exempt: Vec<&str> = LOOPBACK_NAMES.iter().copied().filter(|n| !gateway_hosts.iter().any(|h| h == n)).collect();
    let own = |key: &str| -> Option<String> {
        spec.env.iter().rev().find(|(k, _)| k == key).map(|(_, v)| v.clone()).or_else(|| inherited(key))
    };
    // The JVM reads proxy system properties, not the variables; appended to
    // the user's own options. Its exemptions are the `NO_PROXY` loopback ones
    // (its default exempts every loopback name, a gateway's too).
    let java_proxy = format!(
        "-Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort={guard_port} -Dhttp.proxyHost=127.0.0.1 \
         -Dhttp.proxyPort={guard_port} -Dhttp.nonProxyHosts={}",
        exempt.iter().map(|n| if n.contains(':') { format!("[{n}]") } else { n.to_string() }).collect::<Vec<_>>().join("|")
    );
    let java = match own("JAVA_TOOL_OPTIONS").filter(|v| !v.is_empty()) {
        Some(own) => format!("{own} {java_proxy}"),
        None => java_proxy,
    };
    env.push(("JAVA_TOOL_OPTIONS".to_string(), java));
    // `ssh` reads neither: git over SSH goes through the guard by
    // `ssai __connect` — unless the user has an ssh command of their own
    // (`GIT_SSH_COMMAND`, `GIT_SSH`, git's `core.sshCommand`), which is theirs
    // to route (`-o ProxyCommand="ssai __connect %h %p"`): rewriting it would
    // change what it does.
    let user_ssh = ["GIT_SSH_COMMAND", "GIT_SSH", GIT_CORE_SSH_COMMAND].iter().any(|k| own(k).is_some_and(|v| !v.is_empty()));
    if !user_ssh
        && let Some(exe) = exe
        && let Some(command) = git_ssh_command(exe)
    {
        env.push(("GIT_SSH_COMMAND".to_string(), command));
    }
    let user_no_proxy =
        spec.env.iter().rev().find(|(k, _)| k == "NO_PROXY" || k == "no_proxy").map(|(_, v)| v.as_str());
    let no_proxy = user_no_proxy
        .filter(|v| !v.is_empty())
        .into_iter()
        .chain(exempt)
        .collect::<Vec<_>>()
        .join(",");
    if !no_proxy.is_empty() {
        for k in ["NO_PROXY", "no_proxy"] {
            env.push((k.to_string(), no_proxy.clone()));
        }
    }
    env
}

/// `GIT_SSH_COMMAND` taking `ssh` through the guard by `ssai __connect`. The
/// value is read by two shells — git's, then ssh's for the ProxyCommand — and
/// ssh expands `%` tokens in it, so the path is single-quoted inside a
/// double-quoted argument; a path holding a quote, `$`, `\\`, a backtick or
/// `%` gets none (`None`). On Windows the path is written with forward
/// slashes, which Git for Windows' shell and ssh read as the same path.
fn git_ssh_command(exe: &str) -> Option<String> {
    git_ssh_command_on(exe, cfg!(windows))
}

fn git_ssh_command_on(exe: &str, windows: bool) -> Option<String> {
    let exe = if windows { exe.replace('\\', "/") } else { exe.to_string() };
    if exe.chars().any(|c| matches!(c, '\'' | '"' | '$' | '\\' | '`' | '%') || c.is_control()) {
        return None;
    }
    Some(format!("ssh -o ProxyCommand=\"'{exe}' __connect %h %p\""))
}

/// The key [`inherited_value`] answers git's `core.sshCommand` under.
const GIT_CORE_SSH_COMMAND: &str = "git:core.sshCommand";

/// What the child inherits for `key` from this process; for
/// [`GIT_CORE_SSH_COMMAND`], git's `core.sshCommand` in `cwd`.
fn inherited_value(cwd: &Path, key: &str) -> Option<String> {
    if key == GIT_CORE_SSH_COMMAND {
        return git_core_ssh_command(cwd);
    }
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

/// git's `core.sshCommand` in `cwd`, if set.
fn git_core_ssh_command(cwd: &Path) -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["config", "--get", "core.sshCommand"])
        .current_dir(cwd)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    let v = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (out.status.success() && !v.is_empty()).then_some(v)
}

/// The loopback names `NO_PROXY` exempts.
const LOOPBACK_NAMES: &[&str] = &["127.0.0.1", "localhost", "::1"];

/// Exempt the engine's own address from the proxy when `127.0.0.1` as a whole
/// is not (a gateway uses it): the engine is attached as `127.0.0.1:<port>`,
/// and a port-qualified entry leaves the gateway going through the guard. A
/// runtime that ignores port-qualified entries sends the engine traffic to the
/// guard, which refuses it — the run then fails visibly.
fn exempt_engine_from_proxy(env: &mut Vec<(String, String)>, port: u16) {
    let current = env
        .iter()
        .rev()
        .find(|(k, _)| k == "NO_PROXY")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    if current.split(',').any(|e| e.trim() == "127.0.0.1") {
        return;
    }
    let entry = format!("127.0.0.1:{port}");
    let value = if current.is_empty() { entry } else { format!("{current},{entry}") };
    for k in ["NO_PROXY", "no_proxy"] {
        env.push((k.to_string(), value.clone()));
    }
}

/// A command confined by this platform's backend, and the process it
/// starts: tokio's on Linux and macOS, the sandbox account's launcher on
/// Windows (the same calls).
#[cfg(not(windows))]
type ConfinedCommand = tokio::process::Command;
#[cfg(not(windows))]
type ConfinedChild = tokio::process::Child;
#[cfg(windows)]
type ConfinedCommand = windows::launch::Command;
#[cfg(windows)]
type ConfinedChild = windows::launch::Child;

/// "No stream" for a [`ConfinedCommand`].
#[cfg(not(windows))]
fn null_io() -> std::process::Stdio {
    std::process::Stdio::null()
}
#[cfg(windows)]
fn null_io() -> windows::launch::Io {
    windows::launch::Io::Null
}

/// What a confined process of this run is granted beyond the policy built
/// from its spec: connect to these loopback ports (the guard's, plus an
/// engine's), the run's scratch dir (see [`scratch`]), and the project's own
/// grants and holds ([`protect`]). No `Debug`: on Windows it carries the
/// account's password.
#[derive(Clone)]
struct RunGrants {
    connect: Vec<u16>,
    #[cfg(not(windows))]
    scratch: PathBuf,
    project: protect::ProjectGrants,
    /// Windows: the account the run signs in as.
    #[cfg(windows)]
    account: std::sync::Arc<windows::launch::Account>,
}

/// A private engine for one run of an engine-backed client (see
/// [`profiles::EngineSpec`]): the port it listens on, its password, and where
/// the client's argv takes the attach arguments.
struct EnginePlan {
    spec: &'static profiles::EngineSpec,
    port: u16,
    secret: String,
    attach_at: usize,
}

impl EnginePlan {
    /// `Some` when `spec`'s client has an engine and this invocation uses it.
    fn for_launch(spec: &LaunchSpec) -> Result<Option<Self>> {
        let Some(engine) = profiles::agent_for(&spec.command).and_then(|a| a.engine) else {
            return Ok(None);
        };
        let Some(attach_at) = engine.attach_at(&spec.args) else {
            return Ok(None);
        };
        // A free loopback port, released for the engine to take. A process that
        // takes it first makes the engine fail to start, which is reported;
        // the readiness probe refuses to attach to anything that is not this
        // engine (see `wait_ready`).
        let port = std::net::TcpListener::bind(("127.0.0.1", 0))
            .and_then(|l| l.local_addr())
            .context("pick a loopback port for the engine")?
            .port();
        let mut bytes = [0u8; 24];
        rand::rng().fill_bytes(&mut bytes);
        Ok(Some(Self { spec: engine, port, secret: hex::encode(bytes), attach_at }))
    }

    fn fill(&self, args: &[&str]) -> Vec<String> {
        args.iter().map(|a| a.replace("{port}", &self.port.to_string())).collect()
    }

    fn serve_args(&self) -> Vec<String> {
        self.fill(self.spec.serve)
    }

    /// The client argv attached to this engine: `attach` at `attach_at`, and
    /// every `private_flags` entry dropped (the sandbox's engine is already
    /// private to the run).
    fn client_args(&self, args: &[String]) -> Vec<String> {
        // `attach_at` is computed on the args before any `--`, which are the
        // client's own options; what follows `--` is passed through untouched.
        let end = args.iter().position(|a| a == "--").unwrap_or(args.len());
        let mut out = args[..end].to_vec();
        out.splice(self.attach_at..self.attach_at, self.fill(self.spec.attach));
        out.retain(|a| !self.spec.private_flags.contains(&a.split('=').next().unwrap_or(a)));
        out.extend_from_slice(&args[end..]);
        out
    }

    /// Env both processes get: the password. (The engine's egress switches
    /// are set for every sandboxed launch of the client, engine or not.)
    fn env(&self) -> Vec<(String, String)> {
        vec![(self.spec.secret_env.to_string(), self.secret.clone())]
    }

    /// Wait until the engine answers its readiness probe, or fail with the tail
    /// of its log when it exits or does not answer in time, or when the run is
    /// signalled meanwhile. Ready means 401 without a password, then 200 with
    /// this run's: a server that took the port first and answers anyone (an
    /// OpenCode engine of the user's, started without a password) is never
    /// attached to — the agent's tools would run in it, outside the sandbox —
    /// and is asked before the password is sent. A process deliberately racing
    /// for the port is out of this guard's scope.
    async fn wait_ready(&self, child: &mut ConfinedChild, log: &std::path::Path) -> Result<()> {
        use base64::Engine as _;
        let auth = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", self.spec.basic_user, self.secret));
        let request = |authorization: &str| {
            format!(
                "GET {} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n{authorization}Connection: close\r\n\r\n",
                self.spec.ready_path, self.port
            )
        };
        let with_secret = request(&format!("Authorization: Basic {auth}\r\n"));
        let without = request("");
        let deadline = tokio::time::Instant::now() + ENGINE_READY_TIMEOUT;
        loop {
            if let Some(status) = child.try_wait()? {
                bail!("the sandboxed engine exited before it was ready ({status}){}", log_tail(log));
            }
            match probe_status(self.port, &without).await {
                // Up and asking for a password: ours only if it takes this run's.
                Some(401) => match probe_status(self.port, &with_secret).await {
                    Some(200) => return Ok(()),
                    // Our engine still starting answers something else; only
                    // a refusal of this run's password marks another server.
                    Some(status @ (401 | 403)) => bail!(
                        "the server on 127.0.0.1:{} refuses this run's engine password (HTTP \
                         {status}) — another password-protected server holds the port; refusing \
                         to attach to it",
                        self.port
                    ),
                    _ => {}
                },
                None => {}
                Some(_) => bail!(
                    "something other than the sandboxed engine answers on 127.0.0.1:{} without a \
                     password — refusing to attach to it",
                    self.port
                ),
            }
            if tokio::time::Instant::now() >= deadline {
                bail!(
                    "the sandboxed engine did not answer within {}s{}",
                    ENGINE_READY_TIMEOUT.as_secs(),
                    log_tail(log)
                );
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
}

const ENGINE_READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// One readiness probe: the HTTP status `request` gets on loopback `port`,
/// `None` when nothing answers in time.
async fn probe_status(port: u16, request: &str) -> Option<u16> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let attempt = async {
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.ok()?;
        stream.write_all(request.as_bytes()).await.ok()?;
        let mut head = Vec::with_capacity(32);
        let mut buf = [0u8; 32];
        while head.len() < 12 {
            let n = stream.read(&mut buf).await.ok()?;
            if n == 0 {
                break;
            }
            head.extend_from_slice(&buf[..n]);
        }
        status_of(&head)
    };
    tokio::time::timeout(std::time::Duration::from_secs(2), attempt).await.ok().flatten()
}

/// The status code of an HTTP/1.x status line (`HTTP/1.1 200 OK`).
fn status_of(head: &[u8]) -> Option<u16> {
    let line = std::str::from_utf8(head.get(..12)?).ok()?;
    let (version, code) = line.split_once(' ')?;
    version.starts_with("HTTP/1.").then(|| code.trim().parse().ok()).flatten()
}

/// The last lines of the engine log, formatted to follow an error message.
fn log_tail(log: &std::path::Path) -> String {
    let text = std::fs::read_to_string(log).unwrap_or_default();
    let lines: Vec<&str> = text.lines().collect();
    let tail = lines[lines.len().saturating_sub(20)..].join("\n");
    if tail.is_empty() {
        format!(" — its log ({}) is empty", log.display())
    } else {
        format!(" — last lines of {}:\n{tail}", log.display())
    }
}

/// Stop the engine: SIGTERM, then SIGKILL if it is still up after a grace
/// period. On Linux the child may be the trampoline's connect() supervisor,
/// which passes the SIGTERM on to the engine and exits after it (a learn pass
/// writes its record then).
async fn stop_engine(child: &mut ConfinedChild) {
    #[cfg(unix)]
    if let Some(pid) = child.id() {
        // SAFETY: plain kill(2) on a child we spawned and have not reaped.
        unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
        if tokio::time::timeout(std::time::Duration::from_secs(3), child.wait()).await.is_ok() {
            return;
        }
    }
    let _ = child.kill().await;
}

/// The confined launch, native or learn. An engine-backed client gets a private
/// engine first, confined by the same rules, with the client attached to it;
/// both are stopped and reaped before this returns. On Linux, anything else the
/// run started that outlives the client (a daemon an agent's shell tool spawned)
/// is reaped too.
async fn launch_confined(mut spec: LaunchSpec, verbose: bool, learn: bool) -> Result<i32> {
    // Once per launch, before any of its confined commands (client, probe,
    // engine) builds a policy that grants them.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    state_dirs::prepare_state_dirs(&spec)?;
    // Windows: the sandbox account, checked; the run adjusted for it; the
    // account granted this project and what the client needs.
    #[cfg(windows)]
    let (account_sid, owner_sid, account, project) = {
        let ready = windows::setup::probe().map_err(anyhow::Error::msg)?;
        // Written before `prepare`, which grants the account every CA file.
        if let Some(pem) = spec.ca_bundle.take() {
            let path = windows::run::shared_ca_bundle(&pem)?;
            point_at_ca_bundle(&mut spec, &path);
        }
        let dirs = windows::run::prepare(&mut spec)?;
        let project = windows::run::grant(&spec, &ready.record.account_sid, &dirs)?;
        let account = windows::launch::Account {
            name: ready.record.account,
            sid: ready.record.account_sid.clone(),
            password: ready.password,
        };
        (ready.record.account_sid, ready.record.owner_sid, std::sync::Arc::new(account), project)
    };
    // Windows: what the account left running or scheduled (a run killed
    // before its own cleanup) is ended before this one starts — only when no
    // other run of the developer's is live, since it ends every process of
    // the account.
    #[cfg(windows)]
    let hold = {
        let (hold, alone) = windows::leftovers::RunHold::open(&crate::state::config_dir()?.join("sandbox-run.lock"))
            .context("open the sandbox's run lock")?;
        if alone {
            windows::leftovers::end(account.clone(), account_sid.clone(), "before the run").await;
        }
        tokio::task::block_in_place(|| hold.share(alone)).context("hold the sandbox's run lock")?;
        hold
    };
    // The run's private temp dir, shared by all its confined commands and
    // removed when this function returns, however it returns. Windows needs
    // none: the account's own temp folder is no one else's.
    #[cfg(not(windows))]
    let scratch = scratch::ScratchDir::create()?;
    #[cfg(not(windows))]
    if let Some(pem) = spec.ca_bundle.take() {
        let path = scratch.write_ca_bundle(&pem)?;
        point_at_ca_bundle(&mut spec, &path);
    }
    let egress = guard::EgressPolicy {
        gateway: allow_targets(&spec.proxy_origins)?,
        destinations: spec.destinations.clone(),
    };
    #[cfg(not(windows))]
    let guard = guard::start(egress, verbose).await?;
    // Windows: only the sandbox account's processes may use the guard.
    #[cfg(windows)]
    let guard = guard::start_for_account(egress, verbose, account_sid.clone()).await?;
    // This process must outlive the client to stop the engine and whatever
    // else the run left behind, so until the client exits it takes SIGINT /
    // SIGTERM / SIGHUP instead of dying of them (`wait_client`). SIGTERM and
    // SIGHUP are passed on to the client; SIGINT is not — the terminal's
    // Ctrl-C reaches the client itself, and a second copy reads as "quit" to
    // clients that cancel a turn on the first.
    #[cfg(unix)]
    let mut signals = RunSignals::take()?;
    let mut env = sandbox_env(&spec, guard.port, &|k| inherited_value(&spec.cwd, k));
    // (On Windows, resolved and prepared by the grant above.)
    #[cfg(not(windows))]
    let project = {
        let project = protect::resolve(&spec.project_root);
        // Landlock holds nothing inside the project: the empty folders that
        // `prepare` makes to be held would serve no purpose on Linux.
        #[cfg(target_os = "macos")]
        project.prepare().context("prepare the project's protected git folders")?;
        project
    };
    let mut grants = RunGrants {
        connect: vec![guard.port],
        #[cfg(not(windows))]
        scratch: scratch.path().to_path_buf(),
        project,
        #[cfg(windows)]
        account,
    };

    #[cfg(target_os = "linux")]
    linux::become_child_subreaper();

    // An engine-backed client's egress switches apply to every sandboxed
    // invocation, including those that run without an engine: whatever runs
    // the client's code here would otherwise attempt fetches the guard refuses.
    if let Some(engine) = profiles::agent_for(&spec.command).and_then(|a| a.engine) {
        env.extend(engine.env.iter().map(|(k, v)| (k.to_string(), v.to_string())));
    }
    // Every learn record of this run, removed whichever way the run ends; on
    // a normal end they are folded into the profile first.
    let mut records = LearnRecords::default();
    let engine = EnginePlan::for_launch(&spec)?;
    let mut client_args = spec.args.clone();
    if let Some(plan) = &engine {
        grants.connect.push(plan.port);
        env.extend(plan.env());
        exempt_engine_from_proxy(&mut env, plan.port);
        client_args = plan.client_args(&spec.args);
    }

    // Every temp variable names the scratch dir the policy grants (read,
    // write, execute), so a runtime that extracts a native library and loads
    // it — Bun, for OpenCode's TUI — never writes outside the grant. Last, so
    // nothing appended to `env` above can override it.
    #[cfg(not(windows))]
    scratch.pin_env(&mut env);

    // Everything that can fail is built before the engine starts, so once it
    // runs every path below reaches the teardown.
    let mut client = confined_command(&spec, &grants, records.next(learn, "client"), &client_args, &env)?;
    let mut engine_child = None;
    if let Some(plan) = &engine {
        let probe =
            confined_command(&spec, &grants, records.next(learn, "version"), &["--version".to_string()], &env)?;
        let (log, file) = private_log_file()?;
        let mut cmd = confined_command(&spec, &grants, records.next(learn, "engine"), &plan.serve_args(), &env)?;
        cmd.stdin(null_io())
            .stdout(file.try_clone()?)
            .stderr(file)
            .kill_on_drop(true);
        let mut child = cmd.spawn().with_context(|| format!("start the {} engine", spec.command))?;
        // The version check runs while the engine starts, so it costs no
        // time; an engine started for a client it refuses is stopped.
        let starting = async {
            let version = check_client_version(&spec.command, plan.spec, probe);
            let ready = plan.wait_ready(&mut child, &log);
            tokio::pin!(version, ready);
            tokio::select! {
                // A refusal ends the wait at once.
                v = &mut version => {
                    v?;
                    ready.await
                }
                // An engine that fails may be an old client's: its version
                // refusal says why better than the readiness error does.
                r = &mut ready => {
                    let v = version.await;
                    v.and(r)
                }
            }
        };
        #[cfg(unix)]
        let ready = tokio::select! {
            // A Ctrl-C reaches the engine too; name the signal, not the
            // engine's death of it.
            biased;
            sig = signals.next() => Err(anyhow::anyhow!("interrupted by {sig} while the engine was starting")),
            ready = starting => ready,
        };
        #[cfg(not(unix))]
        let ready = starting.await;
        if let Err(e) = ready {
            #[cfg(unix)]
            signals.restore_defaults();
            stop_engine(&mut child).await;
            reap_leftovers().await;
            #[cfg(windows)]
            windows_after_run(&spec, &grants, &account_sid, &owner_sid, &hold).await;
            // The log stays only where the error points the user at it — and,
            // like a failed run's, only among the newest few kept.
            if !format!("{e:#}").contains(&log.display().to_string()) {
                let _ = std::fs::remove_file(&log);
            } else {
                prune_own_kept_logs(&log);
            }
            return Err(e);
        }
        eprintln!(
            "ssai: {} engine confined on 127.0.0.1:{} (log: {})",
            spec.command,
            plan.port,
            log.display()
        );
        engine_child = Some((child, log));
    }

    #[cfg(unix)]
    let status = wait_client(&mut client, &mut signals).await;
    #[cfg(not(unix))]
    let status = client.status().await;
    // From here a signal ends this process as it would without a sandbox: a
    // user who interrupts the teardown gets their terminal back at once.
    // Dropping the streams is not enough — tokio keeps its handlers for the
    // life of the process — so the default actions are put back.
    #[cfg(unix)]
    signals.restore_defaults();

    if let Some((mut child, log)) = engine_child {
        stop_engine(&mut child).await;
        // The engine log is the only record of why a run failed (a refused
        // provider, a hung boot, a crash), so it outlives a client that FAILED;
        // a clean run, or one the user stopped (`interrupted_by_user`), removes
        // it. It holds session content, so only the newest few kept logs stay.
        let failed = match &status {
            Err(_) => true,
            Ok(s) => !s.success() && !interrupted_by_user(s),
        };
        if failed {
            eprintln!("ssai: the {} engine log is kept: {}", spec.command, log.display());
            prune_own_kept_logs(&log);
        } else {
            let _ = std::fs::remove_file(log);
        }
    }
    reap_leftovers().await;
    #[cfg(windows)]
    windows_after_run(&spec, &grants, &account_sid, &owner_sid, &hold).await;
    #[cfg(target_os = "linux")]
    records.apply(&spec, &scratch);

    // Once the client has the terminal back: what the sandbox refused.
    let refused = guard.refused();
    if !refused.is_empty() {
        eprintln!(
            "ssai: the sandbox refused egress to {} — ask your administrator to add what the project \
             needs to an allowed destination list",
            refused.join(", ")
        );
    }

    Ok(status?.code().unwrap_or(1))
}

/// Windows, once the run's processes are gone, and only when no other run of
/// the developer's is live: what the account left running or scheduled is
/// ended, then what the agent created or replaced is the developer's again
/// (a run killed before this, or one that ended beside another, leaves its
/// files to the sweep of the next run that ends alone).
#[cfg(windows)]
async fn windows_after_run(
    spec: &LaunchSpec,
    grants: &RunGrants,
    account_sid: &str,
    owner_sid: &str,
    hold: &windows::leftovers::RunHold,
) {
    // While another run is live its agent is still writing: both wait for
    // the last run to end.
    if !hold.last() {
        return;
    }
    windows::leftovers::end(grants.account.clone(), account_sid.to_string(), "after the run").await;
    tokio::task::block_in_place(|| {
        for dir in std::iter::once(&spec.project_root).chain(&grants.project.extra_rw) {
            if let Err(e) = windows::sweep::reown_reporting(dir, account_sid, owner_sid) {
                crate::ui::warn("", format_args!("could not give the project's files back to you: {e:#}"));
            }
        }
    });
}

/// Whether a client's exit was the user stopping it — Ctrl-C (exit 130, or
/// SIGINT), SIGTERM or SIGHUP — rather than a failure. A crash signal (SIGSEGV,
/// SIGABRT, an OOM kill) is a failure, and keeps the log.
fn interrupted_by_user(status: &std::process::ExitStatus) -> bool {
    if status.code() == Some(130) {
        return true;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        matches!(status.signal(), Some(libc::SIGINT | libc::SIGTERM | libc::SIGHUP))
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// How many failed runs' engine logs are kept.
const KEPT_ENGINE_LOGS: usize = 3;
/// How long a log whose run still looks alive is spared from pruning.
const LIVE_LOG_GRACE: std::time::Duration = std::time::Duration::from_secs(24 * 3600);

/// Prune the kept logs beside `log` — only in this user's own log directory,
/// never a shared temp dir a fallback log landed in.
fn prune_own_kept_logs(log: &Path) {
    if let (Some(dir), Ok(own)) = (log.parent(), engine_log_dir())
        && dir == own
    {
        prune_kept_engine_logs(dir, KEPT_ENGINE_LOGS);
    }
}

/// Remove all but the `keep` newest `streamscope-engine-*.log` files in `dir`,
/// never the log of a `ssai run` still running (its pid is in the name:
/// `streamscope-engine-<pid>-<suffix>.log`), however old its last write.
fn prune_kept_engine_logs(dir: &Path, keep: usize) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    let mut logs: Vec<(std::time::SystemTime, PathBuf)> = entries
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name();
            let name = name.to_string_lossy();
            name.starts_with("streamscope-engine-") && name.ends_with(".log")
        })
        .filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.file_name(), e.path())))
        // A live run's log is spared — but only while recent: a pid is reused,
        // and an unrelated process must not shield an old log forever.
        .filter(|(modified, name, _)| {
            let recent = modified.elapsed().is_ok_and(|age| age < LIVE_LOG_GRACE);
            !(recent && log_owner_alive(&name.to_string_lossy()))
        })
        .map(|(modified, _, path)| (modified, path))
        .collect();
    logs.sort_by_key(|l| std::cmp::Reverse(l.0));
    for (_, old) in logs.into_iter().skip(keep) {
        let _ = std::fs::remove_file(old);
    }
}

/// Whether the `ssai run` that named an engine log is still running.
fn log_owner_alive(name: &str) -> bool {
    let Some(pid) = name
        .strip_prefix("streamscope-engine-")
        .and_then(|rest| rest.split('-').next())
        .and_then(|p| p.parse::<i32>().ok())
    else {
        return false;
    };
    // This process's own log is the one just kept: it counts toward the cap.
    if u32::try_from(pid).is_ok_and(|p| p == std::process::id()) {
        return false;
    }
    #[cfg(unix)]
    {
        // SAFETY: signal 0 only checks that the pid exists; nothing is sent.
        let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
        rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
    #[cfg(not(unix))]
    {
        // Engine logs come from confined runs, which only Unix has.
        let _ = pid;
        false
    }
}

/// The learn records of one run (one per confined process). Dropping removes
/// the files, so an early error leaves no list of `$HOME` paths behind.
#[derive(Default)]
struct LearnRecords(Vec<PathBuf>);

impl LearnRecords {
    /// A fresh record for `role` when this is a learn pass, else `None`.
    fn next(&mut self, learn: bool, role: &str) -> Option<PathBuf> {
        let record = learn.then(|| learn_record_path(role))?;
        self.0.push(record.clone());
        Some(record)
    }

    /// Fold what was observed into the global profile, dropping anything
    /// already allowed by the built-in policy. Never fatal — a learn pass that
    /// can't persist still ran the client.
    #[cfg(target_os = "linux")]
    fn apply(&self, spec: &LaunchSpec, scratch: &scratch::ScratchDir) {
        for record in &self.0 {
            if let Err(e) = linux::apply_learned(spec, scratch, record) {
                eprintln!("ssai: learn — could not update the sandbox profile: {e}");
            }
        }
    }
}

impl Drop for LearnRecords {
    fn drop(&mut self) {
        for record in &self.0 {
            let _ = std::fs::remove_file(record);
        }
    }
}

/// The signals the run parent takes instead of dying of them. One the run
/// inherited as ignored (`nohup`) stays ignored and is not taken.
#[cfg(unix)]
struct RunSignals {
    interrupt: Option<tokio::signal::unix::Signal>,
    terminate: Option<tokio::signal::unix::Signal>,
    hangup: Option<tokio::signal::unix::Signal>,
    taken: Vec<libc::c_int>,
}

#[cfg(unix)]
impl RunSignals {
    fn take() -> Result<Self> {
        use tokio::signal::unix::{signal, SignalKind};
        let mut taken = Vec::new();
        let mut one = |sig: libc::c_int, kind: SignalKind, name: &str| -> Result<_> {
            if inherited_as_ignored(sig) {
                return Ok(None);
            }
            let stream = signal(kind).with_context(|| format!("take {name} for the run"))?;
            taken.push(sig);
            Ok(Some(stream))
        };
        let interrupt = one(libc::SIGINT, SignalKind::interrupt(), "SIGINT")?;
        let terminate = one(libc::SIGTERM, SignalKind::terminate(), "SIGTERM")?;
        let hangup = one(libc::SIGHUP, SignalKind::hangup(), "SIGHUP")?;
        Ok(Self { interrupt, terminate, hangup, taken })
    }

    /// Hand the signals taken back to their default action — tokio never
    /// removes a handler it installed, and a signal not ignored on entry had
    /// its default one. Idempotent.
    fn restore_defaults(&mut self) {
        for sig in self.taken.drain(..) {
            // SAFETY: resets a disposition; no handler state is shared.
            unsafe { libc::signal(sig, libc::SIG_DFL) };
        }
    }

    /// The next signal taken to arrive, by name — for a wait with no client
    /// yet to pass it to, which it ends.
    async fn next(&mut self) -> &'static str {
        tokio::select! {
            Some(_) = recv(&mut self.interrupt) => "SIGINT",
            Some(_) = recv(&mut self.terminate) => "SIGTERM",
            Some(_) = recv(&mut self.hangup) => "SIGHUP",
        }
    }
}

/// The next delivery on `signal`; pending forever for a signal not taken.
#[cfg(unix)]
async fn recv(signal: &mut Option<tokio::signal::unix::Signal>) -> Option<()> {
    match signal {
        Some(s) => s.recv().await,
        None => std::future::pending().await,
    }
}

/// Whether `sig` reached this process ignored (`nohup`, `trap '' HUP`).
#[cfg(unix)]
fn inherited_as_ignored(sig: libc::c_int) -> bool {
    // SAFETY: a null new action only reads the current disposition.
    unsafe {
        let mut old: libc::sigaction = std::mem::zeroed();
        libc::sigaction(sig, std::ptr::null(), &mut old) == 0 && old.sa_sigaction == libc::SIG_IGN
    }
}

/// Run the client to its exit. A SIGTERM or SIGHUP sent to this process is
/// passed on to the client (a second copy of either still means stop), SIGINT
/// is only kept from ending this process, and the wait goes on, so the
/// teardown after it still runs.
#[cfg(unix)]
async fn wait_client(
    client: &mut tokio::process::Command,
    signals: &mut RunSignals,
) -> std::io::Result<std::process::ExitStatus> {
    let mut child = client.spawn()?;
    loop {
        let sig = tokio::select! {
            status = child.wait() => return status,
            Some(_) = recv(&mut signals.interrupt) => continue,
            Some(_) = recv(&mut signals.terminate) => libc::SIGTERM,
            Some(_) = recv(&mut signals.hangup) => libc::SIGHUP,
        };
        if let Some(pid) = child.id() {
            // SAFETY: kill(2) on our own unreaped child.
            unsafe { libc::kill(pid as libc::pid_t, sig) };
        }
    }
}

/// This user's own directory for engine logs, `<cache>/engine-logs`
/// ([`crate::state::cache_dir`], mode 0700): the user's own, so no other user
/// can create or own it, and on disk rather than a RAM-backed temp dir. The
/// CLI opens each log itself and hands the engine the open file, so the
/// sandbox grants nothing for it.
fn engine_log_dir() -> Result<PathBuf> {
    let dir = crate::state::cache_dir()?.join("engine-logs");
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .with_context(|| format!("create {}", dir.display()))?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    Ok(dir)
}

/// A fresh engine log only this user can read (it holds tool output and
/// session content): a random name, created exclusively, mode 0600.
fn private_log_file() -> Result<(PathBuf, std::fs::File)> {
    let mut suffix = [0u8; 8];
    rand::rng().fill_bytes(&mut suffix);
    // A HOME that cannot hold the directory (read-only, a CI runner) falls back
    // to the temp dir: the file is still random, exclusive and 0600; kept logs
    // there are not pruned (`prune_own_kept_logs` works only in our own dir).
    let dir = engine_log_dir().unwrap_or_else(|_| std::env::temp_dir());
    let log = dir.join(format!("streamscope-engine-{}-{}.log", std::process::id(), hex::encode(suffix)));
    let file = crate::state::create_new_private_file(&log)?;
    Ok((log, file))
}

/// Where a learn pass's confined process records the paths it opens — one file
/// per process, read back by the parent after exit. Private per-pid files under
/// the temp dir.
fn learn_record_path(role: &str) -> PathBuf {
    let record = std::env::temp_dir()
        .join(format!("streamscope-learn-{}-{role}.paths", std::process::id()));
    let _ = std::fs::remove_file(&record);
    record
}

/// Kill and reap whatever the run left behind (Linux: every orphan reparented
/// to this process as its child subreaper), off the async runtime's threads —
/// it sleeps and waits. A no-op elsewhere.
async fn reap_leftovers() {
    #[cfg(target_os = "linux")]
    let _ = tokio::task::spawn_blocking(linux::reap_orphans).await;
}

/// The command that runs `args` of `spec.command` under the sandbox, with
/// `env` and the run's `grants`. `record` makes it a learn pass that records the
/// paths it opens there (Linux).
fn confined_command(
    spec: &LaunchSpec,
    grants: &RunGrants,
    record: Option<PathBuf>,
    args: &[String],
    env: &[(String, String)],
) -> Result<ConfinedCommand> {
    #[cfg(target_os = "linux")]
    {
        let mut policy = linux::build_policy(spec, &grants.scratch)?;
        // A linked worktree's git dirs, outside the project. Landlock cannot
        // hold anything inside a granted tree, so `grants.project.protected`
        // stays writable here: the banner names it.
        policy.fs_rw.extend(grants.project.extra_rw.iter().cloned());
        policy.net_connect = grants.connect.clone();
        policy.learn_record = record;
        let json = serde_json::to_string(&policy)?;
        let exe = std::env::current_exe().map_err(|e| anyhow::anyhow!("locate self: {e}"))?;
        let mut cmd = tokio::process::Command::new(exe);
        cmd.arg("__run-confined")
            .arg(json)
            .arg("--")
            .arg(&spec.command)
            .args(args)
            .current_dir(&spec.cwd);
        for (k, v) in env {
            cmd.env(k, v);
        }
        Ok(cmd)
    }
    #[cfg(target_os = "macos")]
    {
        let _ = record;
        macos::command(spec, &grants.connect, &grants.scratch, &grants.project, args, env)
    }
    #[cfg(windows)]
    {
        // Windows confines by the account, its access entries and its
        // firewall rule, all set before the launch: nothing per command.
        let _ = record;
        let mut cmd = windows::launch::Command::new(grants.account.clone(), &spec.command);
        cmd.args(args.iter().cloned()).current_dir(&spec.cwd);
        for (k, v) in env {
            cmd.env(k, v);
        }
        Ok(cmd)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = (spec, grants, record, args, env);
        bail!("the native sandbox is only implemented on Linux, macOS and Windows")
    }
}

/// Refuse an engine-backed client older than its engine shape: it would
/// ignore the attach arguments and start (or reuse) an engine of its own,
/// which the sandbox refuses or does not confine. `probe` runs
/// `<client> --version` (confined, like everything the run starts). A version
/// that cannot be read is let through — the launch then fails visibly if the
/// shape is wrong.
async fn check_client_version(
    command: &str,
    engine: &profiles::EngineSpec,
    mut probe: ConfinedCommand,
) -> Result<()> {
    let probe = probe
        .stdin(null_io())
        .stderr(null_io())
        .kill_on_drop(true)
        .output();
    let Ok(Ok(out)) = tokio::time::timeout(std::time::Duration::from_secs(10), probe).await else {
        return Ok(());
    };
    match major_version(&String::from_utf8_lossy(&out.stdout)) {
        // Major 0 is a development build's placeholder, not a release.
        Some(major) if major > 0 && major < engine.min_major => bail!(
            "`{command}` {major}.x can't run under the sandbox — `ssai run` needs version {}+ \
             (upgrade: {}), or pass --sandbox off to launch it unconfined",
            engine.min_major,
            engine.upgrade_hint,
        ),
        _ => Ok(()),
    }
}

/// The major version in a `--version` line: the integer before the first `.`
/// of the first token that looks like `N.N…` (`2.0.25`, `opencode 1.18.3`).
fn major_version(output: &str) -> Option<u32> {
    output
        .split(|c: char| c.is_whitespace() || c == 'v')
        .find_map(|tok| {
            let (major, rest) = tok.split_once('.')?;
            rest.starts_with(|c: char| c.is_ascii_digit()).then(|| major.parse().ok()).flatten()
        })
}

/// Trampoline entrypoint (Linux): confine this process to `policy_json`, then
/// `execvp` the client. A fresh, effectively single-threaded process, so
/// applying Landlock+seccomp here is fork-safe. Never returns on success.
#[cfg(target_os = "linux")]
pub fn exec_confined(policy_json: &str, command: &str, args: &[String]) -> Result<()> {
    let policy: SandboxPolicy = serde_json::from_str(policy_json)
        .map_err(|e| anyhow::anyhow!("internal: bad sandbox policy: {e}"))?;
    linux::apply_and_exec(&policy, command, args)
}

#[cfg(not(target_os = "linux"))]
pub fn exec_confined(_policy_json: &str, _command: &str, _args: &[String]) -> Result<()> {
    bail!("the confined trampoline is Linux-only")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn choice_parsing() {
        assert_eq!(SandboxChoice::parse("auto").unwrap(), SandboxChoice::Auto);
        assert_eq!(SandboxChoice::parse("NATIVE").unwrap(), SandboxChoice::Native);
        assert_eq!(SandboxChoice::parse("learn").unwrap(), SandboxChoice::Learn);
        assert_eq!(SandboxChoice::parse("off").unwrap(), SandboxChoice::Off);
        assert_eq!(SandboxChoice::parse("Docker").unwrap(), SandboxChoice::Docker);
        assert!(SandboxChoice::parse("podman").is_err());
        assert!(SandboxChoice::parse("tier0").is_err());
        assert!(SandboxChoice::parse("bogus").is_err());
        assert!(SandboxChoice::parse("greywall").is_err());
    }

    fn spec_env(env: &[(&str, &str)]) -> LaunchSpec {
        LaunchSpec {
            command: "opencode".into(),
            args: vec![],
            project_root: PathBuf::from("/p"),
            cwd: PathBuf::from("/p"),
            proxy_origins: vec![],
            destinations: Default::default(),
            env: env.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            ca_files: vec![],
            ca_bundle: None,
            home_files: vec![],
            client_files: vec![],
            allow_outside_profile: false,
        }
    }

    fn last<'a>(env: &'a [(String, String)], key: &str) -> Option<&'a str> {
        env.iter().rev().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    #[test]
    fn a_ca_bundle_answers_every_trust_store_variable_unless_the_user_set_one() {
        let mut spec = LaunchSpec {
            command: "claude".into(),
            args: vec![],
            project_root: PathBuf::from("/p"),
            cwd: PathBuf::from("/p"),
            proxy_origins: vec![],
            destinations: Default::default(),
            env: vec![("SSL_CERT_FILE".into(), "/mine.pem".into())],
            ca_files: vec![],
            ca_bundle: None,
            home_files: vec![],
            client_files: vec![],
            allow_outside_profile: false,
        };
        point_at_ca_bundle(&mut spec, Path::new("/root/run.pem"));
        // `Command::env` keeps the last value of a key.
        let last = |k: &str| spec.env.iter().rev().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        for k in ["REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS"] {
            assert_eq!(last(k).as_deref(), Some("/root/run.pem"), "{k}");
        }
        assert_eq!(last("SSL_CERT_FILE").as_deref(), Some("/mine.pem"), "a user's -e was overridden");
        assert_eq!(spec.ca_files, [PathBuf::from("/root/run.pem")]);
    }

    #[cfg(unix)]
    #[test]
    fn an_unconfined_runs_ca_bundle_is_private_and_removed_with_it() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("ss-temp-ca-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let b = TempCaBundle::write_in(&dir, b"PEM").unwrap();
        assert_eq!(std::fs::read(&b.0).unwrap(), b"PEM");
        assert_eq!(std::fs::metadata(&b.0).unwrap().permissions().mode() & 0o777, 0o600);
        let path = b.0.clone();
        drop(b);
        assert!(!path.exists(), "the bundle outlived the run");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Every client is pointed at the guard and keeps loopback off it; a
    /// `NO_PROXY` the user passed is extended, never replaced.
    #[test]
    fn the_sandbox_env_proxies_through_the_guard_except_loopback() {
        let env = sandbox_env(&spec_env(&[]), 4242, &|_| None);
        assert_eq!(last(&env, "HTTPS_PROXY"), Some("http://127.0.0.1:4242"));
        assert_eq!(last(&env, "NODE_USE_ENV_PROXY"), Some("1"));
        assert_eq!(last(&env, "NO_PROXY"), Some("127.0.0.1,localhost,::1"));
        assert_eq!(last(&env, "no_proxy"), Some("127.0.0.1,localhost,::1"));
        assert_eq!(last(&env, "PWD"), Some("/p"), "PWD names the launch directory");
        let env = sandbox_env(&spec_env(&[("NO_PROXY", "corp.example")]), 4242, &|_| None);
        assert_eq!(last(&env, "NO_PROXY"), Some("corp.example,127.0.0.1,localhost,::1"));
        // A gateway on a loopback name is reached through the guard: that name
        // is not exempt, the others still are.
        let mut spec = spec_env(&[]);
        spec.proxy_origins = vec!["https://localhost:8443".into()];
        assert_eq!(last(&sandbox_env(&spec, 4242, &|_| None), "NO_PROXY"), Some("127.0.0.1,::1"));
        spec.proxy_origins = vec!["https://[::1]:8443".into(), "https://gw.example".into()];
        assert_eq!(last(&sandbox_env(&spec, 4242, &|_| None), "NO_PROXY"), Some("127.0.0.1,localhost"));
        // A gateway on 127.0.0.1 keeps that name proxied; the engine's own
        // address is exempted by port.
        spec.proxy_origins = vec!["http://127.0.0.1:8080".into()];
        let mut env = sandbox_env(&spec, 4242, &|_| None);
        assert_eq!(last(&env, "NO_PROXY"), Some("localhost,::1"));
        exempt_engine_from_proxy(&mut env, 5555);
        assert_eq!(last(&env, "NO_PROXY"), Some("localhost,::1,127.0.0.1:5555"));
        assert_eq!(last(&env, "no_proxy"), Some("localhost,::1,127.0.0.1:5555"));
        // Already exempt as a whole: nothing added.
        let mut env = sandbox_env(&spec_env(&[]), 4242, &|_| None);
        exempt_engine_from_proxy(&mut env, 5555);
        assert_eq!(last(&env, "NO_PROXY"), Some("127.0.0.1,localhost,::1"));
        // The user's lowercase variable is read as theirs.
        let env = sandbox_env(&spec_env(&[("no_proxy", "corp.example")]), 4242, &|_| None);
        assert_eq!(last(&env, "NO_PROXY"), Some("corp.example,127.0.0.1,localhost,::1"));
    }

    /// The JVM is pointed at the guard through its properties, after the
    /// user's own options (passed or inherited); `ssh` goes through
    /// `ssai __connect` unless the user has an ssh command of their own, which
    /// is left as it is.
    #[test]
    fn java_and_ssh_are_pointed_at_the_guard_too() {
        let none = |_: &str| None;
        let env = sandbox_env(&spec_env(&[]), 4242, &none);
        let java = last(&env, "JAVA_TOOL_OPTIONS").unwrap();
        assert!(java.starts_with("-Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=4242 "), "{java}");
        assert!(java.contains("-Dhttp.proxyPort=4242"), "{java}");
        assert!(java.ends_with("-Dhttp.nonProxyHosts=127.0.0.1|localhost|[::1]"), "{java}");
        let env = sandbox_env(&spec_env(&[("JAVA_TOOL_OPTIONS", "-Xmx1g")]), 4242, &none);
        assert!(last(&env, "JAVA_TOOL_OPTIONS").unwrap().starts_with("-Xmx1g -Dhttps.proxyHost="));
        let inherited = sandbox_env(&spec_env(&[]), 4242, &|k: &str| {
            (k == "JAVA_TOOL_OPTIONS").then(|| "-Djavax.net.ssl.trustStore=/corp.jks".to_string())
        });
        assert!(last(&inherited, "JAVA_TOOL_OPTIONS").unwrap().starts_with("-Djavax.net.ssl.trustStore=/corp.jks -D"));

        // The running test binary's path names the command (on Windows with
        // forward slashes).
        {
            let ssh = last(&env, "GIT_SSH_COMMAND").unwrap().to_string();
            assert!(ssh.starts_with("ssh -o ProxyCommand=\"'") && ssh.ends_with("' __connect %h %p\""), "{ssh}");
        }
        assert_eq!(
            git_ssh_command("/opt/my tools/ssai").as_deref(),
            Some("ssh -o ProxyCommand=\"'/opt/my tools/ssai' __connect %h %p\""),
            "a space is quoted"
        );
        for bad in ["/o'q/ssai", "/a\"b/ssai", "/$HOME/ssai", "/a`b`/ssai", "/100%/ssai"] {
            assert_eq!(git_ssh_command(bad), None, "{bad}");
        }
        // A Windows path is routed, written with forward slashes; elsewhere a
        // backslash still gets none.
        assert_eq!(
            git_ssh_command_on(r"C:\Users\me\ssai\ssai.exe", true).as_deref(),
            Some("ssh -o ProxyCommand=\"'C:/Users/me/ssai/ssai.exe' __connect %h %p\"")
        );
        assert_eq!(git_ssh_command_on(r"C:\Users\me\ssai.exe", false), None);
        // The user's own ssh setting, passed or inherited, is left as it is.
        let passed = sandbox_env(&spec_env(&[("GIT_SSH_COMMAND", "ssh -i key")]), 4242, &none);
        assert_eq!(last(&passed, "GIT_SSH_COMMAND"), Some("ssh -i key"));
        let passed_program = sandbox_env(&spec_env(&[("GIT_SSH", "/opt/my tools/plink")]), 4242, &none);
        assert_eq!(last(&passed_program, "GIT_SSH_COMMAND"), None);
        for key in ["GIT_SSH_COMMAND", "GIT_SSH", GIT_CORE_SSH_COMMAND] {
            let theirs = sandbox_env(&spec_env(&[]), 4242, &|k: &str| (k == key).then(|| "ssh -J bastion".to_string()));
            assert_eq!(last(&theirs, "GIT_SSH_COMMAND"), None, "{key}");
        }
    }

    #[test]
    fn the_banner_names_the_destination_lists_only_when_some_apply() {
        use streamscope_client_templates::destination::{DestinationSet, Policy};
        assert_eq!(destinations_note(&Policy::default()), "");
        let p = Policy {
            allow: DestinationSet::parse(&["a.lan", "b.lan"]).unwrap(),
            block: DestinationSet::parse(&["c.lan"]).unwrap(),
        };
        assert_eq!(destinations_note(&p), " and 2 allowed destination(s), 1 blocked");
    }

    /// The engine plan puts the attach arguments where the profile says, with
    /// the picked port, and hands both processes the same fresh password.
    #[test]
    fn an_engine_plan_attaches_the_client_to_its_own_port() {
        let mut spec = spec_env(&[]);
        spec.args = vec!["run".into(), "hi".into()];
        let plan = EnginePlan::for_launch(&spec).unwrap().expect("opencode run uses its engine");
        let url = format!("http://127.0.0.1:{}", plan.port);
        assert_eq!(plan.client_args(&spec.args), ["run", "--server", url.as_str(), "hi"]);
        // Asking for a private engine gets this one: the flag would clash with `--server`.
        let standalone = ["run".to_string(), "--standalone".into(), "hi".into()];
        assert_eq!(plan.client_args(&standalone), ["run", "--server", url.as_str(), "hi"]);
        // After `--` an argument is the client's message, never a flag of ours.
        let valued = ["run".to_string(), "--standalone=true".into(), "hi".into()];
        assert_eq!(plan.client_args(&valued), ["run", "--server", url.as_str(), "hi"]);
        let quoted = ["run".to_string(), "--".into(), "--standalone".into()];
        assert_eq!(plan.client_args(&quoted), ["run", "--server", url.as_str(), "--", "--standalone"]);
        assert_eq!(
            plan.serve_args(),
            ["serve", "--hostname", "127.0.0.1", "--port", plan.port.to_string().as_str()]
        );
        assert_eq!(plan.env(), [("OPENCODE_PASSWORD".to_string(), plan.secret.clone())]);
        assert_eq!(plan.secret.len(), 48);
        let other = EnginePlan::for_launch(&spec).unwrap().unwrap();
        assert_ne!(plan.secret, other.secret, "the password is fresh per run");

        // A plain client, and an engine client's engine-less subcommand: no plan.
        spec.command = "claude".into();
        assert!(EnginePlan::for_launch(&spec).unwrap().is_none());
        spec.command = "opencode".into();
        spec.args = vec!["mcp".into(), "list".into()];
        assert!(EnginePlan::for_launch(&spec).unwrap().is_none());
    }

    #[test]
    fn the_status_is_read_from_an_http_status_line() {
        assert_eq!(status_of(b"HTTP/1.1 200 OK\r\n"), Some(200));
        assert_eq!(status_of(b"HTTP/1.0 401 Unauthorized"), Some(401));
        assert_eq!(status_of(b"HTTP/1.1 20"), None, "a truncated line is no answer");
        assert_eq!(status_of(b"SSH-2.0-OpenSSH"), None);
    }

    #[test]
    fn the_major_version_is_read_from_a_version_line() {
        assert_eq!(major_version("2.0.25\n"), Some(2));
        assert_eq!(major_version("1.18.35"), Some(1));
        assert_eq!(major_version("opencode v1.2.3"), Some(1));
        assert_eq!(major_version("opencode 10.0.0-beta"), Some(10));
        assert_eq!(major_version("dev build"), None);
        assert_eq!(major_version(""), None);
    }

    #[test]
    fn allow_targets_default_ports_and_empty() {
        let t = allow_targets(&["https://gw.acme.io".to_string()]).unwrap();
        assert_eq!(t, vec![("gw.acme.io".to_string(), 443)]);
        let t = allow_targets(&["http://localhost:8081".to_string()]).unwrap();
        assert_eq!(t, vec![("localhost".to_string(), 8081)]);
        assert!(allow_targets(&[]).is_err());
    }
}

#[cfg(all(test, unix))]
mod engine_log_tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn a_crash_keeps_the_log_and_a_users_stop_does_not() {
        use std::os::unix::process::ExitStatusExt;
        let signalled = |sig: i32| std::process::ExitStatus::from_raw(sig);
        let exited = |code: i32| std::process::ExitStatus::from_raw(code << 8);
        assert!(interrupted_by_user(&signalled(libc::SIGINT)));
        assert!(interrupted_by_user(&signalled(libc::SIGTERM)));
        assert!(interrupted_by_user(&exited(130)));
        assert!(!interrupted_by_user(&signalled(libc::SIGSEGV)));
        assert!(!interrupted_by_user(&signalled(libc::SIGKILL)));
        assert!(!interrupted_by_user(&exited(1)));
    }

    /// A pid that always names a running process.
    const ALWAYS_ALIVE: u32 = 1;

    #[test]
    fn only_the_newest_kept_engine_logs_stay_and_other_files_are_untouched() {
        let dir = std::env::temp_dir().join(format!("ss-enginelogs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let base = std::time::SystemTime::now() - std::time::Duration::from_secs(1000);
        for i in 0..5u64 {
            let p = dir.join(format!("streamscope-engine-{i}.log"));
            let f = std::fs::File::create(&p).unwrap();
            f.set_modified(base + std::time::Duration::from_secs(i * 10)).unwrap();
        }
        std::fs::write(dir.join("unrelated.log"), "x").unwrap();
        // The oldest of all, but its run is still going (pid 1 always exists;
        // this process's own log is the one just kept and counts).
        let live = dir.join(format!("streamscope-engine-{ALWAYS_ALIVE}-live.log"));
        std::fs::File::create(&live).unwrap().set_modified(base - std::time::Duration::from_secs(500)).unwrap();
        // A live pid on a log two days old is a reused pid, not that run: pruned.
        let stale = dir.join(format!("streamscope-engine-{ALWAYS_ALIVE}-stale.log"));
        std::fs::File::create(&stale)
            .unwrap()
            .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(2 * 24 * 3600))
            .unwrap();
        prune_kept_engine_logs(&dir, 3);
        let mut left: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        let mut want = vec![
            "streamscope-engine-2.log".to_string(),
            "streamscope-engine-3.log".to_string(),
            "streamscope-engine-4.log".to_string(),
            format!("streamscope-engine-{ALWAYS_ALIVE}-live.log"),
            "unrelated.log".to_string(),
        ];
        want.sort();
        assert_eq!(left, want);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
