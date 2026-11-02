//! `ssai sandbox` — the docker sandbox's images and volumes
//! (`ssai run --sandbox docker`).

use anyhow::{bail, Result};
use clap::Subcommand;

#[derive(Subcommand)]
pub enum SandboxCommand {
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
    }
}
