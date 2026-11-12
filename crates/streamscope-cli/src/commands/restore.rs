//! `ssai restore` — roll provisioned tool configs back to a pre-write
//! backup. Every provision/sync run snapshots each file it is about to
//! overwrite under `~/.config/streamscopeai/backups/<run>/`; restore copies a
//! run's snapshots back over the live files, first snapshotting the current
//! state so the restore is itself undoable.

use std::path::Path;

use anyhow::{bail, Context, Result};
use clap::Args;

use super::session::confirm;
use crate::state::{self, resolve_scope, BackupRun, ManagedClient, Manifest, ManifestScope, Paths};

#[derive(Args)]
pub struct RestoreArgs {
    /// Restore a specific run by its timestamp (see --list). Defaults to the
    /// most recent run.
    #[arg(long)]
    pub run: Option<String>,
    /// List the available backup runs and exit.
    #[arg(long)]
    pub list: bool,
    /// Don't ask for confirmation.
    #[arg(long, short = 'y')]
    pub yes: bool,
    /// Act on the home-directory backups even inside a provisioned project
    /// (where a project run wrote a global-only client's config).
    #[arg(long)]
    pub global: bool,
}

pub async fn run(args: RestoreArgs) -> Result<()> {
    // Inside a provisioned project, restore that project's backups.
    let scope = resolve_scope(None, false, args.global)?;
    let paths = Paths::for_scope(&scope)?;
    let runs = state::list_backup_runs(paths.base())?;
    // A project run that wrote a global-only client backed that file up in the
    // home-directory scope; say where, so an empty project list is not the end.
    let global_hint = || -> Result<()> {
        if matches!(scope, ManifestScope::Project(_)) {
            let global = state::list_backup_runs(Paths::for_scope(&ManifestScope::Global)?.base())?;
            if !global.is_empty() {
                println!(
                    "{} home-directory backup run(s) also exist — list them with: ssai restore --global --list",
                    global.len()
                );
            }
        }
        Ok(())
    };
    if args.list {
        print_runs(&runs, &paths.manifest());
        global_hint()?;
        return Ok(());
    }
    if runs.is_empty() {
        println!("No backups yet — provision and sync each save one before changing a file.");
        global_hint()?;
        return Ok(());
    }

    let run = match &args.run {
        Some(stamp) => runs.into_iter().find(|r| &r.stamp == stamp).ok_or_else(|| {
            anyhow::anyhow!("no backup run {stamp:?} — list them with: ssai restore --list")
        })?,
        None => runs.into_iter().next().expect("non-empty checked above"),
    };

    // Read the snapshot fully into memory before touching anything — taking a
    // pre-restore backup below can evict the oldest run (possibly this one).
    // The manifest is not a file to copy back: the clients whose files this
    // run restores take their record from it, every other client is left as
    // it is now (a later run's clients stay managed).
    let manifest_path = paths.manifest();
    let (manifest_snapshot, snapshot): (Vec<_>, Vec<_>) = state::load_backup_run_contents(&run)?
        .into_iter()
        .partition(|(p, _)| state::same_file(p, &manifest_path));
    let before: Option<Manifest> = manifest_snapshot
        .first()
        .map(|(_, bytes)| bytes.as_deref().map(serde_json::from_slice).transpose())
        .transpose()
        .with_context(|| format!("backup {} holds an unreadable manifest", run.stamp))?
        .map(Option::unwrap_or_default);
    if snapshot.is_empty() {
        bail!("backup {} holds no tool config to restore", run.stamp);
    }

    println!(
        "Restoring {} file(s) from backup {}:",
        snapshot.len(),
        run.stamp
    );
    for (path, contents) in &snapshot {
        match contents {
            Some(_) => println!("  {}", path.display()),
            None => println!("  {} (created by that run — removed)", path.display()),
        }
    }
    if !args.yes && !confirm("Put these files back as they were before that run?")? {
        bail!("aborted");
    }

    // Snapshot the current state first so this restore can itself be undone.
    let undo_stamp = state::new_run_stamp("-pre-restore");
    for (path, _) in &snapshot {
        state::backup_file(paths.base(), &undo_stamp, path)?;
    }
    state::backup_manifest_into_run(&paths, &undo_stamp, &Manifest::load(&paths)?)?;

    for (path, contents) in &snapshot {
        match contents {
            Some(bytes) => state::restore_file(path, bytes)?,
            None => {
                match std::fs::remove_file(path) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e).with_context(|| format!("remove {}", path.display())),
                }
                // The directory the run made for it, when nothing else is in it.
                if let Some(dir) = path.parent() {
                    let _ = std::fs::remove_dir(dir);
                }
            }
        }
    }
    let restored: Vec<&Path> = snapshot.iter().map(|(p, _)| p.as_path()).collect();
    match &before {
        Some(before) => {
            let mut manifest = Manifest::load(&paths)?;
            for line in reconcile_manifest(&mut manifest, before, &restored) {
                println!("  {line}");
            }
            manifest.save(&paths)?;
        }
        None => println!(
            "  This backup holds no record of what was managed then — run `ssai status` \
             and re-provision a tool whose file no longer matches."
        ),
    }
    println!(
        "Restored {} file(s). The pre-restore state was saved as backup {undo_stamp}.",
        snapshot.len()
    );
    Ok(())
}

/// Bring `live`'s record of every client owning a `restored` file (now, or in
/// `before`) back to its
/// record in `before` (the manifest as that backup run found it): its files'
/// hashes, its template, its key and its group's etag. A client `before` does
/// not know was provisioned by that run, so restoring the run's files stops
/// managing it. Clients owning no restored file are not touched. Returns a
/// line per client changed.
fn reconcile_manifest(live: &mut Manifest, before: &Manifest, restored: &[&Path]) -> Vec<String> {
    let owns = |c: &ManagedClient| {
        c.files
            .iter()
            .any(|f| state::expand_tilde(&f.path).is_ok_and(|p| restored.iter().any(|r| state::same_file(r, &p))))
    };
    let mut lines = Vec::new();
    for (host, ws) in &mut live.hosts {
        let then = before.hosts.get(host);
        // A client is affected by a restored file it owns now OR owned then —
        // a run that moved a client's file (retiring the old one) is undone
        // through the old record.
        let owned_then = |id: &str| {
            then.and_then(|t| t.clients.iter().find(|c| c.client_id == id)).is_some_and(owns)
        };
        let mut affected: Vec<String> = ws
            .clients
            .iter()
            .filter(|c| owns(c) || owned_then(&c.client_id))
            .map(|c| c.client_id.clone())
            .collect();
        // A client the run knew whose file comes back, though this gateway's
        // live entry no longer has it (forgotten since): managed again.
        if let Some(t) = then {
            for c in t.clients.iter().filter(|c| owns(c)) {
                if !affected.contains(&c.client_id) {
                    affected.push(c.client_id.clone());
                }
            }
        }
        let touched = !affected.is_empty();
        for client_id in affected {
            let suffix = format!(":client={client_id}");
            ws.clients.retain(|c| c.client_id != client_id);
            ws.group_etags.retain(|sig, _| !sig.ends_with(&suffix));
            match then.and_then(|t| t.clients.iter().find(|c| c.client_id == client_id)) {
                Some(prev) => {
                    let then = then.expect("found in it");
                    if let Some(id) = prev.key_id
                        && let Some(k) = then.keys.get(&id)
                    {
                        ws.keys.insert(id, k.clone());
                    }
                    for (sig, etag) in then.group_etags.iter().filter(|(s, _)| s.ends_with(&suffix)) {
                        ws.group_etags.insert(sig.clone(), etag.clone());
                    }
                    ws.clients.push(prev.clone());
                    lines.push(format!("{client_id}: managed as it was then"));
                }
                None => lines.push(format!(
                    "{client_id}: no longer managed (that run provisioned it) — provision it again to manage it"
                )),
            }
        }
        // Only a gateway this restore touched: another may hold a key a failed
        // run kept unpruned on purpose.
        if touched {
            super::provision::note_unused_keys(&super::provision::prune_unused_keys(ws));
        }
    }
    // A gateway the run knew but the live manifest has lost: its clients whose
    // files come back are managed again, as they were then.
    for (host, then) in &before.hosts {
        if live.hosts.contains_key(host) {
            continue;
        }
        let mut ws = then.clone();
        ws.clients.retain(|c| owns(c));
        if ws.clients.is_empty() {
            continue;
        }
        let names: Vec<String> = ws.clients.iter().map(|c| c.client_id.clone()).collect();
        let used: Vec<uuid::Uuid> = ws.clients.iter().filter_map(|c| c.key_id).collect();
        ws.keys.retain(|id, _| used.contains(id));
        lines.push(format!("{}: managed again for {host}, as it was then", names.join(", ")));
        live.hosts.insert(host.clone(), ws);
    }
    lines
}

/// The runs and the tool configs each puts back — not the manifest, which a
/// restore reconciles rather than copies.
fn print_runs(runs: &[BackupRun], manifest: &Path) {
    if runs.is_empty() {
        println!("No backups yet — provision and sync each save one before changing a file.");
        return;
    }
    println!("Available backups (newest first):");
    for r in runs {
        let files: Vec<_> =
            r.files.iter().filter(|f| !state::same_file(Path::new(&f.original), manifest)).collect();
        println!("  {} — {} file(s)", r.stamp, files.len());
        for f in files {
            match f.stored {
                Some(_) => println!("      {}", f.original),
                None => println!("      {} (created by that run)", f.original),
            }
        }
    }
    println!();
    println!("Restore the latest with:   ssai restore");
    println!("Or a specific one with:    ssai restore --run <timestamp>");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(id: &str, path: &str, key: Option<&str>, hash: &str) -> serde_json::Value {
        serde_json::json!({
            "client_id": id, "template_index": 0, "last_provisioned": "2026-10-09T12:00:00Z",
            "mode": "gateway", "provider_id": null, "key_id": key, "mcp_server_ids": [], "mcp_local_servers": [], "mcp_local_commands": {},
            "launch_command": null,
            "files": [{ "path": path, "format": "json", "owned": [], "file_hash": hash }]
        })
    }

    fn manifest(clients: Vec<serde_json::Value>, keys: &[&str]) -> Manifest {
        let keys: serde_json::Map<String, serde_json::Value> = keys
            .iter()
            .map(|k| {
                (k.to_string(), serde_json::json!({
                    "id": k, "name": format!("key-{}", &k[..4]), "plaintext": "sk-x", "forward_auth": false
                }))
            })
            .collect();
        serde_json::from_value(serde_json::json!({
            "hosts": { "https://gw#t": {
                "clients": clients, "keys": keys, "group_etags": {}, "proxy_origins": []
            } }
        }))
        .unwrap()
    }

    const K1: &str = "11111111-1111-1111-1111-111111111111";
    const K2: &str = "22222222-2222-2222-2222-222222222222";

    #[test]
    fn restoring_a_run_that_moved_a_file_brings_back_the_old_record() {
        // That run moved opencode from `opencode.json` to `.opencode/opencode.json`;
        // the restore puts the old file back (and removes the new one), so the
        // record must be the old one even though no live file matches it.
        let before = manifest(vec![client("opencode", "/p/opencode.json", Some(K1), "old")], &[K1]);
        let mut live = manifest(vec![client("opencode", "/p/.opencode/opencode.json", Some(K1), "new")], &[K1]);
        reconcile_manifest(&mut live, &before, &[Path::new("/p/opencode.json")]);
        let ws = &live.hosts["https://gw#t"];
        assert_eq!(ws.clients.len(), 1);
        assert_eq!(ws.clients[0].files[0].path, "/p/opencode.json");
    }

    #[test]
    fn a_client_forgotten_since_is_managed_again_when_its_file_comes_back() {
        let before = manifest(
            vec![
                client("codex", "/h/.codex/config.toml", Some(K1), "old"),
                client("claude-code", "/h/.claude/settings.json", Some(K2), "c"),
            ],
            &[K1, K2],
        );
        let mut live = manifest(vec![client("claude-code", "/h/.claude/settings.json", Some(K2), "c")], &[K2]);
        reconcile_manifest(&mut live, &before, &[Path::new("/h/.codex/config.toml")]);
        let ws = &live.hosts["https://gw#t"];
        assert!(ws.clients.iter().any(|c| c.client_id == "codex"), "codex is managed again");
        assert!(ws.keys.contains_key(&K1.parse().unwrap()));
    }

    #[test]
    fn a_gateway_the_live_manifest_lost_is_put_back_for_its_restored_files() {
        let before = manifest(vec![client("codex", "/h/.codex/config.toml", Some(K1), "old")], &[K1]);
        let mut live = Manifest::default();
        reconcile_manifest(&mut live, &before, &[Path::new("/h/.codex/config.toml")]);
        let ws = &live.hosts["https://gw#t"];
        assert_eq!(ws.clients.len(), 1);
        assert!(ws.keys.contains_key(&K1.parse().unwrap()));
    }

    #[test]
    fn restoring_the_first_provisioning_stops_managing_its_client() {
        let mut live = manifest(vec![client("gemini-cli", "/h/.gemini/settings.json", Some(K1), "new")], &[K1]);
        let before = Manifest::default();
        let lines = reconcile_manifest(&mut live, &before, &[Path::new("/h/.gemini/settings.json")]);
        let ws = &live.hosts["https://gw#t"];
        assert!(ws.clients.is_empty(), "{lines:?}");
        assert!(ws.keys.is_empty(), "its key is no longer recorded");
    }

    #[test]
    fn restoring_an_older_run_keeps_a_later_runs_client() {
        // R1 provisioned claude (key K1); R2 later provisioned codex (key K2).
        // Restoring R1's backup of an earlier claude file brings claude's record
        // back to R1's and leaves codex alone.
        let before = manifest(vec![client("claude-code", "/h/.claude/settings.json", Some(K1), "old")], &[K1]);
        let mut live = manifest(
            vec![
                client("claude-code", "/h/.claude/settings.json", Some(K1), "new"),
                client("codex", "/h/.codex/config.toml", Some(K2), "c"),
            ],
            &[K1, K2],
        );
        reconcile_manifest(&mut live, &before, &[Path::new("/h/.claude/settings.json")]);
        let ws = &live.hosts["https://gw#t"];
        let claude = ws.clients.iter().find(|c| c.client_id == "claude-code").expect("still managed");
        assert_eq!(claude.files[0].file_hash, "old");
        assert!(ws.clients.iter().any(|c| c.client_id == "codex"), "a later run's client survives");
        assert!(ws.keys.contains_key(&K2.parse().unwrap()), "and so does its key");
    }
}
