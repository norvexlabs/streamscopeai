//! `ssai` — client provisioning CLI.
//!
//! Logs into a Streamscope gateway (OAuth 2.1 loopback-PKCE against the
//! gateway's CLI OAuth surface, or a portal `ak-` automation key in CI),
//! pulls a provisioning bundle, renders the client-config templates locally
//! with the shared `streamscope-client-templates` engine, and
//! structured-merges the result into each AI client's live config file —
//! preserving every key the user already has there.
//!
//! Exit codes: 0 success · 1 generic failure · 2 authentication required
//! (run `ssai login`) · 3 partial write (some files written, see
//! stderr).

mod api;
mod commands;
mod oauth;
mod opencode_global;
mod program;
mod sandbox;
mod state;
mod ui;
#[cfg(windows)]
mod win_acl;
mod writer;

use clap::{Parser, Subcommand};

/// Authentication-required failures map to exit code 2 so scripts can
/// distinguish "re-login" from hard errors.
#[derive(Debug)]
pub struct AuthRequired(pub String);

impl std::fmt::Display for AuthRequired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for AuthRequired {}

/// Partial-write failures map to exit code 3.
#[derive(Debug)]
pub struct PartialWrite(pub String);

impl std::fmt::Display for PartialWrite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for PartialWrite {}

/// The user cancelled a prompt (Esc / Ctrl-C). Every prompt runs before its
/// command writes a tool config, mints a key or replaces a file, so that pass
/// did none of those; `sync --watch` stops on it instead of retrying.
#[derive(Debug)]
pub struct Cancelled;

impl std::fmt::Display for Cancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "cancelled")
    }
}
impl std::error::Error for Cancelled {}

/// Application version, extracted from `CHANGELOG.md` at compile time by
/// `build.rs` — the same source of truth the gateway reports, so `update`
/// compares like against like.
pub const VERSION: &str = env!("STREAMSCOPE_VERSION");

#[derive(Parser)]
#[command(
    name = "ssai",
    about = "Provision AI coding tools against your Streamscope gateway",
    version = VERSION,
    // The licence and the offer of the source, on the help screen. `--version`
    // stays the bare version: the installer and `update` read its last word.
    after_help = concat!(
        "Streamscope AI is free software under the GNU Affero General Public License v3.0.\n",
        "Source: ",
        env!("CARGO_PKG_REPOSITORY"),
        "\n`ssai licenses` prints the licences of the software it bundles."
    )
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Log in to a gateway (opens your browser). Pass any URL of your
    /// tenant's portal — e.g. the Quickstart page you're looking at — or
    /// leave it out to be asked for it.
    Login {
        /// Portal URL, e.g. https://gw.example.com/portal/t/acme
        portal_url: Option<String>,
        /// Don't open a browser — print the authorize URL instead.
        #[arg(long)]
        no_browser: bool,
        /// Log in with a device code you enter on the portal from any other
        /// machine (for SSH sessions; also the automatic fallback when no
        /// local browser can open).
        #[arg(long)]
        device: bool,
        /// Device label shown on the consent page and in token listings
        /// (defaults to this machine's hostname).
        #[arg(long)]
        device_name: Option<String>,
    },
    /// Provision AI clients: mint/reuse one gateway key and write each
    /// tool's config (structured merge — your other settings are kept).
    Provision(commands::provision::ProvisionArgs),
    /// Re-converge provisioned configs with the gateway (no-op when nothing
    /// changed; re-mints + rewrites if the gateway key was revoked).
    Sync(commands::sync::SyncArgs),
    /// Self-update from the gateway's distribution surface (sha256-verified).
    Update {
        /// Gateway to update from (origin or any portal URL).
        #[arg(long)]
        host: Option<String>,
        /// Don't ask for confirmation.
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Show login state and provisioned-file status.
    Status {
        /// Gateway to inspect when logged into several (origin or origin#slug).
        #[arg(long)]
        host: Option<String>,
    },
    /// Stop managing client(s): drop them from the local manifest so `sync`
    /// no longer rewrites their config (the files are left untouched).
    Forget {
        /// Client id(s) to forget, e.g. claude-code.
        #[arg(required = true)]
        clients: Vec<String>,
        /// Gateway to forget them for when several are provisioned.
        #[arg(long)]
        host: Option<String>,
    },
    /// Roll provisioned tool configs back to a pre-write backup (the most
    /// recent run by default; `--list` shows them).
    Restore(commands::restore::RestoreArgs),
    /// Print this program's licence notice and the licences of the
    /// third-party software it bundles.
    Licenses,
    /// Revoke this device's tokens server-side and forget them locally.
    Logout {
        /// Gateway to log out of when logged into several (origin or origin#slug).
        #[arg(long)]
        host: Option<String>,
    },
    /// Launch a provisioned agent CLI confined to the project, with network
    /// egress allowed only to the gateway proxy. Requires the current dir to be
    /// provisioned (run `ssai provision` first).
    Run(commands::run::RunArgs),
    /// Manage the docker sandbox's images and volumes (`ssai run --sandbox docker`).
    #[command(subcommand)]
    Sandbox(commands::sandbox::SandboxCommand),
    /// PID 1 of a docker-sandbox container. Not for direct use.
    #[command(name = "__sandbox-init", hide = true)]
    SandboxInit { start_file: std::path::PathBuf },
    /// Give back to the developer the files a docker-sandbox container wrote
    /// under `root` (run under `podman unshare`). Not for direct use.
    #[command(name = "__sandbox-sweep", hide = true)]
    SandboxSweep {
        root: std::path::PathBuf,
        /// The container's root uid and gid, as ids of the `podman unshare`
        /// namespace; each absent when it is the developer's.
        #[arg(long)]
        container_root_uid: Option<u32>,
        #[arg(long)]
        container_root_gid: Option<u32>,
    },
    /// Tunnel stdin/stdout to `host:port` through the sandbox guard — the
    /// `ssh` ProxyCommand inside `ssai run`.
    #[command(name = "__connect", hide = true)]
    Connect { host: String, port: u16 },
    /// Internal re-exec trampoline: confine this process to the serialized
    /// policy, then exec the client. Not for direct use.
    #[command(name = "__run-confined", hide = true)]
    RunConfined {
        /// Serialized `SandboxPolicy` (JSON).
        policy: String,
        /// The client command + args (everything after `--`).
        #[arg(last = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
}

fn main() {
    // First, before parsing: `--version` and `--help` exit inside the parser.
    #[cfg(windows)]
    commands::update::remove_replaced_exe();
    let cli = Cli::parse();

    // The confined re-exec trampoline forks a seccomp supervisor (the connect()
    // address interposer), so it MUST run while the process is single-threaded.
    // Handle it here, before the tokio runtime spins up worker threads —
    // forking a multithreaded process and then allocating in the child is the
    // classic fork-with-threads hazard.
    if let Command::RunConfined { policy, command } = &cli.command {
        let result = match command.split_first() {
            Some((cmd, rest)) => sandbox::exec_confined(policy, cmd, rest),
            None => Err(anyhow::Error::msg("__run-confined: no command given")),
        };
        finish(result);
    }
    // A container's init reaps every child with `waitpid(-1)`, which a
    // runtime's own reaper would race; the sweep needs none.
    match &cli.command {
        Command::SandboxInit { start_file } => finish(sandbox::podman_init(start_file)),
        Command::SandboxSweep { root, container_root_uid, container_root_gid } => {
            finish(sandbox::podman_sweep(root, *container_root_uid, *container_root_gid))
        }
        _ => {}
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");
    let result = runtime.block_on(dispatch(cli.command));
    finish(result);
}

/// Run an async subcommand. `RunConfined`, `SandboxInit` and `SandboxSweep`
/// are handled in `main` before the runtime starts, so they never reach here.
async fn dispatch(command: Command) -> anyhow::Result<()> {
    match command {
        Command::Login {
            portal_url,
            no_browser,
            device,
            device_name,
        } => commands::login::run(portal_url, no_browser, device, device_name).await,
        Command::Provision(args) => commands::provision::run(args).await,
        Command::Sync(args) => commands::sync::run(args).await,
        Command::Update { host, yes } => commands::update::run(host.as_deref(), yes).await,
        Command::Status { host } => commands::status::run(host.as_deref()).await,
        Command::Forget { clients, host } => commands::forget::run(&clients, host.as_deref()).await,
        Command::Restore(args) => commands::restore::run(args).await,
        Command::Logout { host } => commands::logout::run(host.as_deref()).await,
        Command::Licenses => {
            use std::io::Write as _;
            let text = format!(
                "ssai {VERSION}, part of Streamscope AI: free software under the GNU Affero General \
                 Public License v3.0. Source: {}\n\n{}",
                env!("CARGO_PKG_REPOSITORY"),
                include_str!(concat!(env!("OUT_DIR"), "/THIRD_PARTY_LICENSES"))
            );
            // Read through a pager or `head`, the reader may close the pipe early.
            match std::io::stdout().write_all(text.as_bytes()) {
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
                result => result.map_err(Into::into),
            }
        }
        Command::Run(args) => commands::run::run(args).await,
        Command::Sandbox(command) => commands::sandbox::run(command).await,
        Command::Connect { host, port } => sandbox::guard::connect_through(&host, port).await,
        Command::RunConfined { .. } | Command::SandboxInit { .. } | Command::SandboxSweep { .. } => {
            unreachable!("handled in main before the runtime starts")
        }
    }
}

/// Print any error and exit with the matching code (0 success · 1 generic ·
/// 2 auth required · 3 partial write). Never returns.
fn finish(result: anyhow::Result<()>) -> ! {
    if let Err(e) = result {
        eprintln!("{} {e:#}", ui::error_mark());
        if let Some(hint) = api::untrusted_certificate_hint(&e) {
            ui::note("", hint);
        }
        let code = if e.downcast_ref::<AuthRequired>().is_some() {
            2
        } else if e.downcast_ref::<PartialWrite>().is_some() {
            3
        } else {
            1
        };
        std::process::exit(code);
    }
    std::process::exit(0);
}
