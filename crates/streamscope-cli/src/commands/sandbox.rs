//! `ssai sandbox` — the Windows sandbox account (`ssai run --sandbox native`
//! on Windows), and the docker sandbox's images and volumes
//! (`ssai run --sandbox docker`).

use anyhow::{bail, Result};
use clap::Subcommand;

#[derive(Subcommand)]
pub enum SandboxCommand {
    /// Windows: create the sandbox account the native sandbox runs clients as,
    /// and the firewall rule that confines its network to loopback — once per
    /// computer and user, as an administrator (one prompt). Re-run to repair.
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
    /// profile and its firewall rule.
    Uninstall,
    /// (Re)build this project's image and the agent layer for `client` — after
    /// a change to the image, its Dockerfile's context, or to pick up the
    /// client's latest release. A first `ssai run --sandbox docker` prepares
    /// them on its own.
    Prepare {
        /// The client — its id or launch command (e.g. `claude`).
        client: String,
    },
    /// Remove every docker-sandbox image and volume of yours (the agents'
    /// homes and the engines' caches go with them).
    Prune,
}

pub async fn run(command: SandboxCommand) -> Result<()> {
    match command {
        SandboxCommand::Prepare { client } => {
            let crate::state::ManifestScope::Project(root) = crate::state::resolve_scope(None, false, false)? else {
                bail!("`ssai sandbox prepare` runs inside a provisioned project (no `.streamscopeai/` above here)");
            };
            let command = crate::sandbox::profiles::agent_for(&client)
                .and_then(|a| a.names.first().copied())
                .unwrap_or(client.as_str())
                .to_string();
            tokio::task::spawn_blocking(move || crate::sandbox::podman_prepare(&root, &command)).await?
        }
        SandboxCommand::Prune => tokio::task::spawn_blocking(crate::sandbox::podman_prune).await?,
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
        #[cfg(not(windows))]
        SandboxCommand::Setup { .. } | SandboxCommand::Revoke { .. } | SandboxCommand::Uninstall => bail!(
            "this command is for Windows only — on Linux and macOS the native sandbox needs no setup"
        ),
    }
}
