//! `ssai status` — login state per gateway plus the health of every
//! file we provisioned (present / edited since provisioning / missing).

use anyhow::Result;

use crate::state::{expand_tilde, resolve_scope, sha256_hex, HostsFile, Manifest, Paths};

pub async fn run(selector: Option<&str>) -> Result<()> {
    let hosts = HostsFile::load()?;
    // Inside a provisioned project (a `.streamscopeai/`) report that project's
    // files; otherwise the global set. Login state stays global.
    let paths = Paths::for_scope(&resolve_scope(None, false, false)?)?;
    let manifest = Manifest::load(&paths)?;

    // Every gateway this scope knows: the ones logged in AND the ones its
    // manifest provisions — a provisioned gateway you are logged out of still
    // has files on disk to report.
    // A manifest entry whose key spells a logged-in gateway differently (a bare
    // origin for `origin#slug`) is that gateway's, matched as `sync` matches
    // it: the exact key, else the one manifest entry of the same origin.
    let manifest_of = |login: &str| -> Option<&String> {
        if let Some((k, _)) = manifest.hosts.get_key_value(login) {
            return Some(k);
        }
        // Only a bare origin on one side matches a slugged key on the other —
        // two different slugs are two tenants.
        let origin = login.split('#').next().unwrap_or(login);
        let login_bare = !login.contains('#');
        let same: Vec<&String> = manifest
            .hosts
            .keys()
            .filter(|k| k.split('#').next() == Some(origin) && (login_bare || !k.contains('#')))
            .collect();
        (same.len() == 1).then(|| same[0])
    };
    let claimed: Vec<&String> = hosts.hosts.keys().filter_map(|k| manifest_of(k)).collect();
    let mut keys: Vec<&String> = hosts
        .hosts
        .keys()
        .chain(manifest.hosts.keys().filter(|k| !claimed.contains(k)))
        .collect();
    keys.sort();
    keys.dedup();
    if keys.is_empty() {
        println!("Not logged in. Run: ssai login <portal-url>");
        return Ok(());
    }

    let selected_key = match selector {
        None => None,
        Some(s) => Some(match hosts.select(Some(s)) {
            Ok((k, _)) => k,
            Err(e) => {
                // A gateway provisioned here but not logged in to — only when
                // exactly one matches and no login does (an ambiguous selector
                // keeps its error, never a guess).
                let matches = |k: &&String| k.as_str() == s || k.split('#').next() == Some(s);
                let in_manifest: Vec<&String> = manifest.hosts.keys().filter(matches).collect();
                let logged_in = hosts.hosts.keys().any(|k| matches(&k));
                match in_manifest.as_slice() {
                    [only] if !logged_in => (*only).clone(),
                    _ => return Err(e),
                }
            }
        }),
    };

    for key in keys {
        if let Some(sel) = &selected_key
            && sel != key
        {
            continue;
        }
        match hosts.hosts.get(key) {
            Some(entry) => {
                let who = entry.user_email.as_deref().unwrap_or("(unknown user)");
                let expiry = entry.access_expires_at - chrono::Utc::now();
                let token_state = if expiry > chrono::Duration::zero() {
                    format!("access token valid {}m", expiry.num_minutes().max(0))
                } else {
                    "access token expired (auto-refreshes on next use)".to_string()
                };
                println!("{} (tenant {})", entry.origin, entry.tenant_slug);
                println!("  logged in as {who} — {token_state}");
            }
            None => {
                println!("{key}");
                println!("  not logged in — sync needs: ssai login <portal-url>");
            }
        }

        let manifest_key = if hosts.hosts.contains_key(key.as_str()) { manifest_of(key) } else { Some(key) };
        match manifest_key.and_then(|k| manifest.hosts.get(k)) {
            None => println!("  nothing provisioned yet — run: ssai provision"),
            Some(ws) => {
                for k in ws.keys.values() {
                    let kind = if k.forward_auth { "BYOK vk-" } else { "gateway sk-" };
                    println!("  {kind} key: {} ({})", k.name, k.id);
                }
                for client in &ws.clients {
                    let mode = if client.mode == "byok" { "BYOK" } else { "gateway" };
                    println!(
                        "  {} [{mode}] (provisioned {})",
                        client.client_id,
                        client.last_provisioned.format("%Y-%m-%d %H:%M UTC")
                    );
                    // A config the client's own user config overrides is not
                    // `ok`, however intact the file is.
                    // The warnings are about the client's main config (its first file).
                    let warnings = crate::opencode_global::for_managed(client);
                    for (i, file) in client.files.iter().enumerate() {
                        let path = expand_tilde(&file.path)?;
                        let overridden = i == 0 && warnings.iter().any(|w| w.overrides);
                        let marker = match std::fs::read(&path) {
                            Err(_) => "MISSING — re-run: ssai provision",
                            Ok(bytes) if sha256_hex(&bytes) == file.file_hash => {
                                if overridden { "overridden by your user config — see below" } else { "ok" }
                            }
                            Ok(_) if overridden => {
                                "edited since provisioning, and overridden by your user config — see below"
                            }
                            Ok(_) => "edited since provisioning (your edits are kept on re-runs)",
                        };
                        println!("    {} — {marker}", file.path);
                    }
                    for warning in &warnings {
                        crate::ui::warn_out("    ", &warning.text);
                    }
                }
            }
        }
        println!();
    }
    Ok(())
}
