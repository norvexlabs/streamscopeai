//! `ssai forget <client>...` — stop managing one or more clients for a
//! gateway: drop them from the local manifest so `sync` no longer rewrites
//! their config. The config files are left exactly as they are — you take them
//! over by hand. Pure-local: no network, no server-side change.

use anyhow::{bail, Result};

use crate::commands::provision::prune_unused_keys;
use crate::state::{resolve_scope, HostKey, Manifest, Paths};

pub async fn run(clients: &[String], selector: Option<&str>) -> Result<()> {
    if clients.is_empty() {
        bail!("name at least one client to forget, e.g.: ssai forget claude-code");
    }
    // Inside a provisioned project, forget acts on that project's manifest.
    let paths = Paths::for_scope(&resolve_scope(None, false, false)?)?;
    let mut manifest = Manifest::load(&paths)?;
    let key = select_manifest_key(&manifest, selector)?;
    let ws = manifest.hosts.get_mut(&key).expect("selected key exists");

    let provisioned: Vec<String> = ws.clients.iter().map(|c| c.client_id.clone()).collect();
    for c in clients {
        if !provisioned.contains(c) {
            bail!(
                "{c:?} isn't provisioned for {key} — provisioned: {}",
                if provisioned.is_empty() {
                    "(none)".to_string()
                } else {
                    provisioned.join(", ")
                }
            );
        }
    }
    // The keys the forgotten clients embed, named before their records go:
    // `forget` revokes nothing (a tool's key may serve it in other projects,
    // and the files kept here still hold it), so the user is told which keys
    // stay live and where to revoke them.
    let mut kept_keys: Vec<String> = ws
        .clients
        .iter()
        .filter(|c| clients.contains(&c.client_id))
        .filter_map(|c| c.key_id)
        .filter_map(|id| ws.keys.get(&id).map(|k| format!("\"{}\"", k.name)))
        .collect();
    kept_keys.sort();
    kept_keys.dedup();
    ws.clients.retain(|c| !clients.contains(&c.client_id));
    // The stored group etags no longer describe the managed set; clear them so
    // the next sync re-evaluates from scratch rather than short-circuiting, and
    // drop keys no remaining client references.
    ws.group_etags.clear();
    prune_unused_keys(ws);
    manifest.save(&paths)?;

    println!(
        "Forgot {} for {key}. Their config files were left untouched — manage them yourself now; \
         sync will no longer rewrite them.",
        clients.join(", ")
    );
    if !kept_keys.is_empty() {
        println!(
            "Gateway key {} is not revoked by this (those files still hold it, and other projects may \
             use it) — revoke it on the portal's Keys page once nothing uses it.",
            kept_keys.join(", ")
        );
    }
    Ok(())
}

/// Resolve which provisioned gateway to act on, by the same grammar as the
/// other commands but reading the local manifest only (no login required).
fn select_manifest_key(manifest: &Manifest, selector: Option<&str>) -> Result<HostKey> {
    let selector = match selector {
        Some(s) => Some(s.to_string()),
        None => std::env::var("STREAMSCOPE_URL").ok().filter(|s| !s.is_empty()),
    };
    let all = || manifest.hosts.keys().cloned().collect::<Vec<_>>().join(", ");
    match selector {
        None => match manifest.hosts.len() {
            0 => bail!("nothing provisioned yet — run: ssai provision"),
            1 => Ok(manifest.hosts.keys().next().cloned().expect("len 1")),
            _ => bail!("several gateways provisioned — pick one with --host: {}", all()),
        },
        Some(sel) => {
            if manifest.hosts.contains_key(&sel) {
                return Ok(sel);
            }
            if let Ok((origin, Some(slug))) = crate::oauth::parse_portal_url(&sel) {
                let k = crate::state::host_key(&origin, &slug);
                if manifest.hosts.contains_key(&k) {
                    return Ok(k);
                }
            }
            let origin = crate::oauth::parse_portal_url(&sel)
                .map(|(o, _)| o)
                .unwrap_or_else(|_| sel.clone());
            let matches: Vec<HostKey> = manifest
                .hosts
                .keys()
                .filter(|k| k.split('#').next() == Some(origin.as_str()))
                .cloned()
                .collect();
            match matches.len() {
                1 => Ok(matches[0].clone()),
                0 => bail!("no provisioned gateway matches {sel:?} — provisioned: {}", all()),
                _ => bail!("selector {sel:?} matches several gateways — use origin#slug"),
            }
        }
    }
}
