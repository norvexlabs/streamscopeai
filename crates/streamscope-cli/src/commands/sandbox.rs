//! `ssai sandbox` — the Windows sandbox account and the FreeBSD jail daemon
//! (`ssai run --sandbox native` there), and the docker sandbox's images and volumes
//! (`ssai run --sandbox docker`).

use anyhow::{bail, Result};
use clap::Subcommand;

#[derive(Subcommand)]
pub enum SandboxCommand {
    /// Windows: create the sandbox account the native sandbox runs clients as,
    /// and the firewall rule that confines its network to loopback — once per
    /// computer and user, as an administrator (one prompt). FreeBSD: install
    /// the daemon that builds each run's jail — once per machine, as root
    /// (`sudo`). Re-run to repair, or after an update.
    Setup {
        /// Only check that the sandbox is set up and sound; change nothing.
        #[arg(long)]
        check: bool,
    },
    /// Windows: take the sandbox account's access back from this project (or
    /// `dir`'s, or every project's with `--all`). The next sandboxed run
    /// grants it again.
    Revoke {
        /// The project folder (default: the project of the current folder).
        dir: Option<std::path::PathBuf>,
        /// Every project the sandbox account was granted.
        #[arg(long, conflicts_with = "dir")]
        all: bool,
    },
    /// Windows: take back every grant, then remove the sandbox account, its
    /// profile and its firewall rule. FreeBSD: remove the jail daemon (as root).
    Uninstall,
    /// (Re)build this project's image and the agent layer for `client` — after
    /// a change to the image, its Dockerfile's context, or to pick up the
    /// client's latest release. A first `ssai run --sandbox docker` prepares
    /// them on its own.
    Prepare {
        /// The client — its id or launch command (e.g. `claude`), as
        /// provisioned here.
        client: String,
        /// The gateway, when several are provisioned (origin or origin#slug),
        /// as for `ssai run`.
        #[arg(long)]
        host: Option<String>,
    },
    /// The docker sandbox's images and volumes on this machine, per project,
    /// with their sizes.
    Status,
    /// Remove every docker-sandbox image and volume of yours (the agents'
    /// homes and the engines' caches go with them), or with `--project` one
    /// project's only.
    Prune {
        /// Only this project's: the one at or above DIR (default: the current
        /// folder), else that folder itself.
        #[arg(long, value_name = "DIR", num_args = 0..=1)]
        project: Option<Option<std::path::PathBuf>>,
    },
}

pub async fn run(command: SandboxCommand) -> Result<()> {
    match command {
        SandboxCommand::Prepare { client, host } => {
            if !cfg!(target_os = "linux") {
                bail!("the docker sandbox runs on Linux only");
            }
            // The root, the client and the default image `run` would use.
            let (root, command, default_image) = super::run::sandbox_target(&client, host.as_deref()).await?;
            tokio::task::spawn_blocking(move || crate::sandbox::podman_prepare(&root, &command, default_image.as_ref())).await?
        }
        SandboxCommand::Status => tokio::task::spawn_blocking(crate::sandbox::podman_status).await?,
        SandboxCommand::Prune { project: None } => tokio::task::spawn_blocking(|| crate::sandbox::podman_prune(None)).await?,
        SandboxCommand::Prune { project: Some(dir) } => {
            // The root a run there confines to: the provisioned project at or
            // above the folder (DIR, else this one), else the folder itself
            // (a home-scoped client's run).
            let start = dunce::canonicalize(match dir {
                Some(dir) => dir,
                None => std::env::current_dir()?,
            })?;
            let root = start.ancestors().find(|d| d.join(".streamscopeai").is_dir()).unwrap_or(&start).to_path_buf();
            tokio::task::spawn_blocking(move || crate::sandbox::podman_prune(Some(&root))).await?
        }
        #[cfg(windows)]
        SandboxCommand::Setup { check } => {
            use crate::sandbox::windows::setup;
            tokio::task::spawn_blocking(move || if check { setup::check() } else { setup::setup() }).await?
        }
        #[cfg(windows)]
        SandboxCommand::Revoke { dir, all } => {
            let root = if all {
                None
            } else {
                match crate::state::resolve_scope(dir.as_deref(), false, false)? {
                    crate::state::ManifestScope::Project(root) => Some(root),
                    _ => bail!("not inside a provisioned project (no `.streamscopeai/` above here) — name one, or pass --all"),
                }
            };
            tokio::task::spawn_blocking(move || crate::sandbox::windows::setup::revoke(root.as_deref())).await?
        }
        #[cfg(windows)]
        SandboxCommand::Uninstall => tokio::task::spawn_blocking(crate::sandbox::windows::setup::uninstall).await?,
        #[cfg(target_os = "freebsd")]
        SandboxCommand::Setup { check } => {
            use crate::sandbox::freebsd::setup;
            tokio::task::spawn_blocking(move || if check { setup::check() } else { setup::setup() }).await?
        }
        #[cfg(target_os = "freebsd")]
        SandboxCommand::Revoke { .. } => crate::sandbox::freebsd::setup::revoke(),
        #[cfg(target_os = "freebsd")]
        SandboxCommand::Uninstall => tokio::task::spawn_blocking(crate::sandbox::freebsd::setup::uninstall).await?,
        #[cfg(not(any(windows, target_os = "freebsd")))]
        SandboxCommand::Setup { .. } | SandboxCommand::Revoke { .. } | SandboxCommand::Uninstall => bail!(
            "this command is for Windows and FreeBSD only — on Linux and macOS the native sandbox needs no setup"
        ),
    }
}
