//! `ssai run <client>` — launch a provisioned agent CLI confined to the
//! project, with network egress allowed only to the gateway proxy. Requires the
//! current directory to be a provisioned project (`.streamscopeai/`).

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::Args;

use crate::api::ClientAccess;
use crate::sandbox::{self, LaunchSpec, SandboxChoice};
use crate::state::{
    gateway_bundle_file, gateway_ca_file, resolve_scope, ClientAccessRecord, ManagedClient, Manifest,
    ManifestScope, Paths, WorkspaceManifest,
};
use streamscope_client_templates::destination::{DestinationSet, Policy};

/// How old the record of what the workspace offers may be before `ssai run`
/// asks the gateway again.
const ACCESS_MAX_AGE_MINUTES: i64 = 60;
/// How long that question may take: a gateway that does not answer leaves the
/// run on its record.
const ACCESS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Args)]
pub struct RunArgs {
    /// The client to launch — its id (e.g. `claude-code`) or launch command
    /// (e.g. `claude`), as provisioned in this project.
    pub client: String,
    /// Gateway to use when several are provisioned in this project (origin or origin#slug).
    #[arg(long)]
    pub host: Option<String>,
    /// Sandbox backend: auto (default), native (in-process), docker (a rootless
    /// Podman container, Linux), learn, off.
    #[arg(long, default_value = "auto")]
    pub sandbox: String,
    /// Surface the egress guard's per-connection denial lines (blocked domains,
    /// etc.). Off by default so they can't corrupt the client's terminal UI.
    #[arg(long, short = 'v')]
    pub verbose: bool,
    /// Extra CA file to trust inside the sandbox (added read-only; preferred for
    /// the CA env vars). Repeatable.
    #[arg(long = "ca-file")]
    pub ca_file: Vec<PathBuf>,
    /// Extra environment for the client, `KEY=VALUE` (repeatable). A path-valued
    /// entry is also exposed read-only inside the sandbox.
    #[arg(long = "env", short = 'e')]
    pub env: Vec<String>,
    /// Windows: run the native sandbox in a project outside your profile,
    /// where every account on the computer may write (a folder under a
    /// drive's root inherits that). Warned about on every run.
    #[arg(long)]
    pub allow_outside_profile: bool,
    /// Arguments forwarded verbatim to the client (everything after `--`).
    #[arg(last = true)]
    pub client_args: Vec<String>,
}

pub async fn run(args: RunArgs) -> Result<()> {
    let choice = SandboxChoice::parse(&args.sandbox)?;

    // Resolve which client to launch, its egress allowlist, and the directory
    // to confine read-write. Looks in the project manifest first, then the
    // global one — so a home-scoped client provisioned globally (the CLI tells
    // you to "provision it globally instead") is runnable from any project.
    let resolved = resolve_client(&args.client, args.host.as_deref())?;

    // What the administrator offers this workspace: the client must be one of
    // its clients, `--sandbox off` may be refused, and the sandbox reaches
    // the attached destination lists beside the gateway. Unknown (never
    // recorded, gateway unreachable): the gateway alone.
    let access = current_access(&resolved).await;
    if let Some(a) = &access
        && !a.clients.contains(&resolved.client_id)
    {
        bail!(
            "{} is disabled by your administrator — it is not offered to this workspace",
            resolved.client_id
        );
    }
    // `learn` leaves the filesystem unconfined, so a required sandbox refuses
    // it with `off`.
    if matches!(choice, SandboxChoice::Off | SandboxChoice::Learn)
        && access.as_ref().is_some_and(|a| a.sandbox.settings.require_sandbox)
    {
        bail!(
            "your administrator requires the sandbox for this workspace — run without `--sandbox off` or \
             `--sandbox learn`"
        );
    }
    if choice == SandboxChoice::Docker && access.as_ref().is_some_and(|a| !a.sandbox.settings.docker_tier) {
        bail!(
            "your administrator does not allow the docker sandbox for this workspace — run with \
             `--sandbox native`"
        );
    }
    // Only a confined run reads the lists: `--sandbox off` applies none, so a
    // block entry this build cannot read does not refuse it.
    let destinations = match choice {
        SandboxChoice::Off => Policy::default(),
        _ => access.as_ref().map(destinations_of).transpose()?.unwrap_or_default(),
    };

    let command = resolved.command;
    let proxy_origins = resolved.proxy_origins;
    let project_root = resolved.confine_root;

    // For a client whose user config outranks a project's, the project config
    // dir as its user config dir. First in the list, so the CA, profile and
    // `--env` entries below win over it.
    let mut env: Vec<(String, String)> = Vec::new();
    if let Some(dir) = resolved.project_config_dir
        && let Some(var) = sandbox::profiles::agent_for(&command).and_then(|a| a.config_dir_env)
    {
        env.push((var.to_string(), dir.to_string_lossy().into_owned()));
    }

    // CA trust + env. `SSL_CERT_FILE`/`REQUESTS_CA_BUNDLE`/`CURL_CA_BUNDLE`
    // REPLACE the trust store, so they must point at a COMPLETE bundle (system +
    // gateway [+ any --ca-file]); `NODE_EXTRA_CA_CERTS` is additive.
    let mut ca_files: Vec<PathBuf> = Vec::new();
    let bundle = gateway_bundle_file();
    let gw_ca = gateway_ca_file();

    // With `--ca-file`, a complete replace-store bundle: the gateway bundle
    // (already system+gateway) or the system store, then each --ca-file, so
    // adding a CA never drops system/gateway trust. The launch writes it where
    // no other run can change it and points every trust-store variable at it
    // (`sandbox::launch`). Without, the gateway bundle is the store.
    let ca_bundle = if args.ca_file.is_empty() {
        None
    } else {
        Some(combined_ca_pem(bundle.as_deref(), &args.ca_file)?)
    };
    if ca_bundle.is_none() {
        if let Some(store) = &bundle {
            ca_files.push(store.clone());
            for k in ["SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"] {
                env.push((k.to_string(), store.to_string_lossy().into_owned()));
            }
        }
        // Node reads ONE additive file: the complete store, else the
        // gateway-only chain.
        if let Some(node_ca) = bundle.as_ref().or(gw_ca.as_ref()) {
            env.push(("NODE_EXTRA_CA_CERTS".to_string(), node_ca.to_string_lossy().into_owned()));
        }
    }
    if let Some(ca) = &gw_ca {
        ca_files.push(ca.clone());
    }
    ca_files.extend(args.ca_file.iter().cloned());

    // Per-agent env quirks (keyring/warning toggles).
    if let Some(agent) = sandbox::profiles::agent_for(&command) {
        for (k, v) in agent.env {
            env.push((k.to_string(), v.to_string()));
        }
    }

    // User-supplied env; a path value is also exposed read-only.
    for kv in &args.env {
        let (k, v) = kv
            .split_once('=')
            .with_context(|| format!("--env wants KEY=VALUE, got {kv:?}"))?;
        let p = PathBuf::from(v);
        if p.is_absolute() && p.exists() {
            ca_files.push(p.clone());
        }
        env.push((k.to_string(), v.to_string()));
    }

    // Seatbelt matches `(subpath …)` against the canonical resolved path
    // (`/private/var/folders/…`, not `/var/folders/…`); Landlock-net likewise
    // resolves before matching. Canonicalize cwd so a `cd` through a symlinked
    // directory before `ssai run` doesn't silently misenforce.
    let cwd = cwd_or_friendly_error().and_then(resolve_real_root)?;
    let spec = LaunchSpec {
        command,
        args: args.client_args.clone(),
        project_root,
        cwd,
        proxy_origins,
        destinations,
        env,
        ca_files,
        ca_bundle,
        home_files: resolved.home_files,
        client_files: resolved.client_files,
        allow_outside_profile: args.allow_outside_profile,
    };

    let tier = sandbox::select_tier(choice)?;

    // A hub-dependent client (e.g. the Continue CLI) contacts its vendor hub
    // before any LLM call; the gateway-only sandbox egress guard blocks that, so
    // it exits without producing a turn. Warn up front instead of failing opaquely.
    if !matches!(tier, sandbox::Tier::Off)
        && sandbox::profiles::agent_for(&spec.command).is_some_and(|a| a.hub_dependent)
    {
        crate::ui::warn("", format_args!("`{}` needs egress to its vendor hub, which the sandbox blocks — it will \
             exit without producing a turn. Run it with `--sandbox off`, or outside \
             `ssai run`.", spec.command));
    }

    let code = sandbox::launch(spec, tier, args.verbose).await?;
    std::process::exit(code);
}

/// A resolved client to launch: the binary, its egress allowlist, the
/// directory confined read-write, and what its provisioned config hands it.
struct ResolvedClient {
    client_id: String,
    command: String,
    proxy_origins: Vec<String>,
    /// The gateway (`origin#slug`) and workspace the client is provisioned
    /// for, the manifest recording it, and what that record says the
    /// workspace offers.
    host_key: String,
    workspace_id: Option<uuid::Uuid>,
    manifest_scope: ManifestScope,
    client_access: Option<ClientAccessRecord>,
    /// The project root inside a provisioned project, else the current dir.
    confine_root: PathBuf,
    /// The directory holding the client's main config, when the client was
    /// provisioned into this project.
    project_config_dir: Option<PathBuf>,
    /// A globally provisioned client's files (under the home).
    home_files: Vec<PathBuf>,
    /// Every file the client was provisioned with, either scope.
    client_files: Vec<PathBuf>,
}

/// Resolve `client` against the project manifest first, then the GLOBAL manifest.
///
/// Home-scoped clients (codex, goose, …) have no project-local config form, so
/// `provision --local` skips them unless they are named, and they are then
/// written globally — they only ever appear in the global manifest. Falling
/// back to it here is what makes `ssai run` work for them. A
/// project-provisioned client keeps the project as its confinement root; a
/// global one confines to the current directory.
fn resolve_client(client: &str, host: Option<&str>) -> Result<ResolvedClient> {
    let scope = resolve_scope(None, false, false)?;
    // Both manifest scopes feed `confine_root` into the sandbox's `(subpath …)`
    // / Landlock allowlist, which match on the resolved real path — see
    // `resolve_real_root`. Apply to BOTH project (local) and global (home)
    // modes so a manifest `root` recorded through a symlink, or a cwd reached
    // via one, lands on the same canonical path the kernel sees.
    let confine_root = match &scope {
        ManifestScope::Project(root) => resolve_real_root(root.clone())
            .with_context(|| format!(
                "the project root `{}` no longer resolves on disk — re-cd into the project from its \
                 current location, or run `ssai provision --local` to re-record it",
                root.display(),
            ))?,
        ManifestScope::Global => cwd_or_friendly_error().and_then(resolve_real_root)?,
    };

    // Project manifest first (when inside a provisioned project), then global
    // — read only when the project does not resolve the client, so a global
    // record this version cannot read stops only a run that needs it.
    let mut scopes: Vec<(bool, ManifestScope)> = Vec::new();
    if matches!(scope, ManifestScope::Project(_)) {
        scopes.push((true, scope.clone()));
    }
    scopes.push((false, ManifestScope::Global));
    let mut manifests: Vec<(bool, crate::state::Manifest)> = Vec::new();

    let mut provisioned: Vec<String> = Vec::new();
    for (is_project, manifest_scope) in scopes {
        manifests.push((is_project, crate::state::Manifest::load(&Paths::for_scope(&manifest_scope)?)?));
        let (is_project, manifest) = manifests.last().expect("just pushed");
        provisioned.extend(provisioned_ids(manifest, host));
        let Some((host_key, ws, managed)) = select_client(manifest, host, client)? else {
            continue;
        };
        let Some(command) = managed.launch_command.clone() else {
            bail!(
                "{} has no launch command (it's a GUI/editor client) — open it normally; \
                 its config already points at the gateway",
                managed.client_id
            );
        };
        if ws.proxy_origins.is_empty() {
            bail!(
                "{} has no gateway proxy origin recorded — re-run: ssai sync",
                managed.client_id
            );
        }
        let project_config_dir = if *is_project {
            config_dir_of(managed, &confine_root)
        } else {
            None
        };
        let files = provisioned_files(managed, is_project.then_some(confine_root.as_path()));
        return Ok(ResolvedClient {
            client_id: managed.client_id.clone(),
            command,
            proxy_origins: ws.proxy_origins.clone(),
            host_key: host_key.clone(),
            workspace_id: ws.workspace_id,
            manifest_scope: if *is_project { scope.clone() } else { ManifestScope::Global },
            client_access: ws.client_access.clone(),
            confine_root,
            project_config_dir,
            // A global client's config lives under the home, which the
            // docker tier does not mount: it mounts these files instead.
            home_files: if *is_project { Vec::new() } else { files.clone() },
            client_files: files,
        });
    }
    // A `--host` naming no provisioned gateway at all is the thing to fix.
    if let Some(sel) = host
        && manifests.iter().all(|(_, m)| host_entries(m, Some(sel)).is_empty())
    {
        bail!("no provisioned gateway matches --host {sel:?} — `ssai status` lists them");
    }
    bail!(
        "{client:?} isn't provisioned here (checked this project and your global config) — \
         provisioned: {}.\n\
         Provision it first: ssai provision [--local] --client {client}",
        if provisioned.is_empty() { "none".to_string() } else { provisioned.join(", ") }
    )
}

/// What the client's workspace offers: the record, asked again when it is
/// older than [`ACCESS_MAX_AGE_MINUTES`] (and recorded); the record as it is
/// when the gateway cannot be asked, with a warning. `None`: never recorded
/// and not answered.
async fn current_access(resolved: &ResolvedClient) -> Option<ClientAccess> {
    let recorded = resolved.client_access.as_ref();
    let fresh = recorded.is_some_and(|r| record_is_fresh(r.fetched_at, chrono::Utc::now()));
    if fresh {
        return recorded.map(|r| r.access.clone());
    }
    match refresh_access(resolved).await {
        Ok(access) => Some(access),
        Err(e) => {
            match recorded {
                Some(r) => crate::ui::warn("", format_args!(
                    "could not ask the gateway what this workspace offers ({e:#}) — using the answer of {}",
                    r.fetched_at.format("%Y-%m-%d %H:%M UTC")
                )),
                None => crate::ui::warn("", format_args!(
                    "could not ask the gateway what this workspace offers ({e:#}) — the sandbox reaches the \
                     gateway only"
                )),
            }
            recorded.map(|r| r.access.clone())
        }
    }
}

/// True when a record fetched at `fetched_at` is younger than
/// [`ACCESS_MAX_AGE_MINUTES`]. A time ahead of the clock is never fresh: it
/// would never age.
fn record_is_fresh(fetched_at: chrono::DateTime<chrono::Utc>, now: chrono::DateTime<chrono::Utc>) -> bool {
    let age = now - fetched_at;
    age >= chrono::Duration::zero() && age < chrono::Duration::minutes(ACCESS_MAX_AGE_MINUTES)
}

/// Ask the gateway what the workspace offers, and record the answer.
async fn refresh_access(resolved: &ResolvedClient) -> Result<ClientAccess> {
    let workspace_id = resolved.workspace_id.context("no workspace is recorded — re-run: ssai sync")?;
    // The session opens outside the timeout: it may rotate the refresh token,
    // and an answer dropped after the rotation would retire the login.
    let session = super::session::open(Some(&resolved.host_key)).await?;
    let access = tokio::time::timeout(ACCESS_TIMEOUT, session.api.client_access(workspace_id))
        .await
        .context("the gateway did not answer")??;
    let paths = Paths::for_scope(&resolved.manifest_scope)?;
    let mut manifest = Manifest::load(&paths)?;
    if let Some(ws) = manifest.hosts.get_mut(&resolved.host_key) {
        ws.client_access = Some(ClientAccessRecord::now(access.clone()));
        manifest.save(&paths)?;
    }
    Ok(access)
}

/// The sandbox's destination policy from what the workspace offers. Entries
/// come canonical from the gateway. An allowed entry this build cannot read is
/// left out with a warning (it allows less); a blocked one refuses the run —
/// leaving it out would allow what the administrator blocked.
fn destinations_of(access: &ClientAccess) -> Result<Policy> {
    let (allow, skipped) = DestinationSet::parse_allowed(&access.sandbox.allow);
    for (e, err) in skipped {
        crate::ui::warn("", format_args!("ignoring the allowed destination {e:?} ({err})"));
    }
    let block = DestinationSet::parse_union(&access.sandbox.block).map_err(|err| {
        anyhow::anyhow!(
            "your administrator blocks a destination this ssai cannot read ({err}) — update it: ssai update"
        )
    })?;
    Ok(Policy { allow, block })
}

/// The files `managed` was provisioned with, as canonical paths on disk (a
/// file not there yet as written): a record's `~/…` expanded as every reader
/// of it expands it. A project's record (`project_root`, canonical) keeps only
/// files inside the project: a project's manifest can come with the
/// repository, and a sandbox grants these files to the client.
fn provisioned_files(managed: &ManagedClient, project_root: Option<&Path>) -> Vec<PathBuf> {
    managed
        .files
        .iter()
        .filter_map(|f| {
            let path = crate::state::expand_tilde(&f.path).ok()?;
            let Some(root) = project_root else { return Some(dunce::canonicalize(&path).unwrap_or(path)) };
            let real = dunce::canonicalize(&path).ok()?;
            (real != root && real.starts_with(root)).then_some(real)
        })
        .collect()
}

/// The directory holding `managed`'s main config, when it is a directory of
/// its own inside the project (`<root>/.opencode`). Never the project root
/// itself: a client that read the root as its user-config directory would
/// load the repository's `plugins/`, `agents/`, … as its own (a project still
/// on a root-level config gets no override).
/// `project_root` is the canonical root; the recorded path is resolved the same
/// way, so a project reached through a symlink still compares equal.
fn config_dir_of(managed: &ManagedClient, project_root: &Path) -> Option<PathBuf> {
    let dir = dunce::canonicalize(Path::new(&managed.files.first()?.path).parent()?).ok()?;
    (dir != project_root && dir.starts_with(project_root)).then_some(dir)
}

/// Resolve `p` to its canonical real path. Load-bearing on macOS: Seatbelt's
/// `(subpath …)` matches the resolved path (`/private/var/folders/…`, not the
/// `/var/folders/…` alias), so a project under `/tmp` or a symlinked checkout
/// would silently misenforce without this. Free win on Linux: Landlock
/// likewise resolves before matching.
fn resolve_real_root(p: PathBuf) -> Result<PathBuf> {
    let p_ref: &Path = &p;
    dunce::canonicalize(p_ref)
        .with_context(|| format!("resolve real path for {}", p.display()))
}

/// Read the current working directory, attaching the same actionable hint the
/// resolve-real-root call sites use. `std::env::current_dir()` fails when the
/// shell's cwd has been deleted/renamed underneath the process — surface that
/// as the same recoverable error a stale canonicalize produces, not a bare
/// `No such file or directory`.
fn cwd_or_friendly_error() -> Result<PathBuf> {
    std::env::current_dir().context(
        "the current directory can't be read — `cd` into a real path, or pass `--sandbox off` to launch unconfined",
    )
}

/// A COMPLETE trust bundle — (the gateway bundle, or the system store) + each
/// `--ca-file` — so adding a CA augments rather than replaces system/gateway
/// trust (the `SSL_CERT_FILE` footgun).
fn combined_ca_pem(base: Option<&std::path::Path>, extra: &[PathBuf]) -> Result<Vec<u8>> {
    let mut pem = Vec::new();
    // Without a base the bundle would hold the --ca-file roots alone, and every
    // variable pointed at it would drop all other trust: refuse instead.
    let base_pem = match base {
        Some(bp) => std::fs::read(bp).with_context(|| format!("read CA base {}", bp.display()))?,
        None => system_ca_pem()?.context(
            "--ca-file adds to a certificate bundle, and this machine has none the clients read (no system \
             CA bundle, no gateway bundle) — pass the roots another way, e.g. -e NODE_EXTRA_CA_CERTS=<file>",
        )?,
    };
    pem.extend(base_pem);
    pem.push(b'\n');
    for f in extra {
        pem.extend(std::fs::read(f).with_context(|| format!("read --ca-file {}", f.display()))?);
        pem.push(b'\n');
    }
    Ok(pem)
}

/// The OS trust store as PEM: the bundle file, by convention across distros
/// (`None` when there is none); on Windows, the user's and machine's root
/// stores, written out.
#[cfg(not(windows))]
fn system_ca_pem() -> Result<Option<Vec<u8>>> {
    let Some(file) = [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/cert.pem",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|p| p.is_file()) else {
        return Ok(None);
    };
    Ok(Some(std::fs::read(&file).with_context(|| format!("read CA base {}", file.display()))?))
}

#[cfg(windows)]
fn system_ca_pem() -> Result<Option<Vec<u8>>> {
    use base64::Engine;
    let found = rustls_native_certs::load_native_certs();
    if found.certs.is_empty() {
        return Ok(None);
    }
    let mut pem = String::new();
    for cert in &found.certs {
        let b64 = base64::engine::general_purpose::STANDARD.encode(cert.as_ref());
        pem.push_str("-----BEGIN CERTIFICATE-----\n");
        for line in b64.as_bytes().chunks(64) {
            pem.push_str(&String::from_utf8_lossy(line));
            pem.push('\n');
        }
        pem.push_str("-----END CERTIFICATE-----\n");
    }
    Ok(Some(pem.into_bytes()))
}

/// The provisioned gateways of `manifest` that `--host` (when given) names.
fn host_entries<'a>(
    manifest: &'a crate::state::Manifest,
    host: Option<&str>,
) -> Vec<(&'a String, &'a WorkspaceManifest)> {
    manifest
        .hosts
        .iter()
        .filter(|(_, w)| !w.clients.is_empty())
        .filter(|(k, _)| host.is_none_or(|sel| k.as_str() == sel || k.split('#').next() == Some(sel)))
        .collect()
}

/// Every client id provisioned in `manifest` under the gateways `--host` names.
fn provisioned_ids(manifest: &crate::state::Manifest, host: Option<&str>) -> Vec<String> {
    host_entries(manifest, host)
        .iter()
        .flat_map(|(_, ws)| ws.clients.iter().map(|c| c.client_id.clone()))
        .collect()
}

/// Find `client` (its id or launch command) among the gateways of `manifest`
/// that `--host` names. `Ok(None)` when none of them provisions it, so the
/// caller can look in the next manifest. Provisioned for several, it is an
/// error naming them — never a guess, and never a fall-through to another
/// manifest that would report the client as not provisioned at all.
fn select_client<'a>(
    manifest: &'a crate::state::Manifest,
    host: Option<&str>,
    client: &str,
) -> Result<Option<(&'a String, &'a WorkspaceManifest, &'a ManagedClient)>> {
    let found: Vec<(&String, &WorkspaceManifest, &ManagedClient)> = host_entries(manifest, host)
        .into_iter()
        .filter_map(|(k, ws)| {
            ws.clients
                .iter()
                .find(|c| c.client_id == client || c.launch_command.as_deref() == Some(client))
                .map(|c| (k, ws, c))
        })
        .collect();
    match found.as_slice() {
        [] => Ok(None),
        [(k, ws, c)] => Ok(Some((*k, *ws, *c))),
        several => bail!(
            "{client:?} is provisioned for several gateways here — pick one with --host{}: {}",
            if host.is_some() { " origin#slug" } else { "" },
            several.iter().map(|(k, _, _)| k.as_str()).collect::<Vec<_>>().join(", ")
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(json: serde_json::Value) -> crate::state::Manifest {
        serde_json::from_value(json).unwrap()
    }

    fn client(id: &str) -> serde_json::Value {
        serde_json::json!({
            "client_id": id, "template_index": 0, "mode": "gateway", "provider_id": null, "key_id": null,
            "mcp_server_ids": [], "files": [],
            "last_provisioned": "2026-10-09T12:00:00Z", "launch_command": id
        })
    }

    fn ws(clients: Vec<serde_json::Value>) -> serde_json::Value {
        serde_json::json!({ "keys": {}, "group_etags": {}, "proxy_origins": [], "clients": clients })
    }

    fn with_files(paths: &[&str]) -> ManagedClient {
        let mut c = client("codex");
        c["files"] = paths
            .iter()
            .map(|p| serde_json::json!({ "path": p, "format": "toml", "owned": [], "file_hash": "" }))
            .collect();
        serde_json::from_value(c).unwrap()
    }

    /// A global record names its files `~/…`: each is the file under the
    /// home, as provision wrote it — what the docker tier mounts and the
    /// Windows sandbox grants.
    #[test]
    fn a_global_records_files_are_found_under_the_home() {
        let home = crate::state::home_dir().unwrap();
        let files = provisioned_files(&with_files(&["~/.codex/config.toml"]), None);
        let want = home.join(".codex").join("config.toml");
        assert_eq!(files, vec![dunce::canonicalize(&want).unwrap_or(want)]);
    }

    /// A project's manifest can come with the repository: it names files of
    /// that project alone, never one elsewhere — the project's own (positive
    /// control) is kept.
    #[test]
    fn a_projects_record_names_only_files_inside_the_project() {
        let base = std::env::temp_dir().join(format!("ssai-run-files-{}", std::process::id()));
        let root = base.join("proj");
        std::fs::create_dir_all(root.join(".claude")).unwrap();
        let root = dunce::canonicalize(&root).unwrap();
        let own = root.join(".claude").join("settings.json");
        let outside = dunce::canonicalize(&base).unwrap().join("secret");
        std::fs::write(&own, "{}").unwrap();
        std::fs::write(&outside, "x").unwrap();
        let named = [own.to_str().unwrap(), outside.to_str().unwrap(), "~/.ssh/id_ed25519", root.to_str().unwrap()];
        assert_eq!(provisioned_files(&with_files(&named), Some(&root)), vec![own]);
        let _ = std::fs::remove_dir_all(&base);
    }

    fn two_gateways() -> crate::state::Manifest {
        manifest(serde_json::json!({ "hosts": {
            "https://a.example#t1": ws(vec![client("opencode"), client("claude")]),
            "https://b.example#t2": ws(vec![client("opencode")]),
        }}))
    }

    #[test]
    fn a_ca_bundle_keeps_the_base_trust_and_adds_each_ca_file() {
        let dir = std::env::temp_dir().join(format!("ss-run-ca-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (base, extra) = (dir.join("base.pem"), dir.join("extra.pem"));
        std::fs::write(&base, "BASE").unwrap();
        std::fs::write(&extra, "EXTRA").unwrap();
        let pem = String::from_utf8(combined_ca_pem(Some(&base), &[extra]).unwrap()).unwrap();
        assert!(pem.contains("BASE") && pem.contains("EXTRA"), "{pem}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_config_dir_is_never_the_project_root() {
        let managed = |path: &str| -> ManagedClient {
            serde_json::from_value(serde_json::json!({
                "client_id": "opencode", "template_index": 0, "last_provisioned": "2026-10-09T12:00:00Z",
                "mode": "gateway", "provider_id": null, "key_id": null, "mcp_server_ids": [],
                "launch_command": null,
                "files": [{ "path": path, "format": "json", "owned": [], "file_hash": "" }]
            }))
            .unwrap()
        };
        let base = std::env::temp_dir().join(format!("ss-cfgdir-{}", std::process::id()));
        let root = base.join("proj");
        std::fs::create_dir_all(root.join(".opencode")).unwrap();
        std::fs::create_dir_all(base.join("elsewhere")).unwrap();
        let root = dunce::canonicalize(&root).unwrap();
        let at = |rel: &str| managed(&root.join(rel).to_string_lossy());
        assert_eq!(config_dir_of(&at(".opencode/opencode.json"), &root), Some(root.join(".opencode")));
        // A root-level config gets no override.
        assert_eq!(config_dir_of(&at("opencode.json"), &root), None);
        let outside = managed(&base.join("elsewhere/opencode.json").to_string_lossy());
        assert_eq!(config_dir_of(&outside, &root), None);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_client_on_two_gateways_is_an_error_naming_them_not_a_fall_through() {
        let m = two_gateways();
        let err = select_client(&m, None, "opencode").unwrap_err().to_string();
        assert!(err.contains("several gateways"), "{err}");
        assert!(err.contains("https://a.example#t1") && err.contains("https://b.example#t2"), "{err}");
    }

    #[test]
    fn a_client_on_one_of_two_gateways_needs_no_host() {
        let m = two_gateways();
        let (_, _, c) = select_client(&m, None, "claude").unwrap().expect("claude is provisioned");
        assert_eq!(c.client_id, "claude");
    }

    #[test]
    fn host_picks_one_gateway_by_key_or_origin() {
        let m = two_gateways();
        let by_key = select_client(&m, Some("https://b.example#t2"), "opencode").unwrap();
        assert!(by_key.is_some());
        let by_origin = select_client(&m, Some("https://a.example"), "opencode").unwrap();
        assert!(by_origin.is_some());
    }

    #[test]
    fn a_client_absent_from_the_manifest_lets_the_caller_look_further() {
        let m = two_gateways();
        assert!(select_client(&m, None, "goose").unwrap().is_none());
        assert!(select_client(&m, Some("https://b.example"), "claude").unwrap().is_none());
        let empty = manifest(serde_json::json!({ "hosts": {} }));
        assert!(select_client(&empty, None, "opencode").unwrap().is_none());
    }

    /// On Windows `--ca-file` adds to the Windows root store, written out as
    /// PEM — never to nothing.
    #[cfg(windows)]
    #[test]
    fn the_windows_root_store_is_the_base_a_ca_file_adds_to() {
        let pem = String::from_utf8(system_ca_pem().unwrap().expect("a Windows machine has roots")).unwrap();
        assert!(pem.matches("-----BEGIN CERTIFICATE-----").count() > 5, "{} bytes", pem.len());
        assert_eq!(pem.matches("-----BEGIN CERTIFICATE-----").count(), pem.matches("-----END CERTIFICATE-----").count());
    }
}
