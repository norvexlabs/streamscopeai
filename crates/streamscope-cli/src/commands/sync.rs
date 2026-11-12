//! `ssai sync [--watch]` — converge the provisioned tool configs with
//! the gateway: re-pull a bundle per manifest group (mode × provider), no-op
//! when nothing changed (per-group etag), re-render + structured-merge when
//! templates/placeholders moved, and re-mint + rewrite a group when its
//! gateway key was revoked.

use std::collections::{BTreeMap, BTreeSet};
use anyhow::{bail, Context, Result};
use clap::Args;

use crate::api::{BundleRequest, BundleSelection, KeySpec, McpSelection};
use super::provision::KeyChoice;
use crate::state::{
    expand_tilde, resolve_scope, sha256_hex, ManagedClient, Manifest, Paths,
    ToolKeys, UpdateCheckFile,
};
use crate::PartialWrite;

use super::provision::{
    external_gateway_key, group_plans, parse_ttl, prune_unused_keys, provision_one,
    record_group, resolve_bundle_plaintext, ClientPlan, Mode, WriteMode,
};
use super::session::{self, confirm};

#[derive(Args)]
pub struct SyncArgs {
    /// Keep running, re-syncing every interval.
    #[arg(long)]
    pub watch: bool,
    /// Watch interval, e.g. 5m, 30s, 1h (default: 5m, with jitter).
    #[arg(long)]
    pub interval: Option<String>,
    /// TTL for a re-minted replacement key, e.g. 2h, 7d (CI default: 2h).
    #[arg(long)]
    pub key_ttl: Option<String>,
    /// Don't prompt — re-mint a replacement key without confirmation.
    #[arg(long, short = 'y')]
    pub yes: bool,
    /// Sync only these client(s) this run (repeatable); the rest of the
    /// managed set is left as-is. Mutually exclusive with --skip.
    #[arg(long = "client")]
    pub clients: Vec<String>,
    /// Sync everything except these client(s) this run (repeatable).
    /// Mutually exclusive with --client.
    #[arg(long = "skip")]
    pub skip: Vec<String>,
    /// Gateway to sync when logged into several (origin or origin#slug).
    #[arg(long)]
    pub host: Option<String>,
}

pub async fn run(args: SyncArgs) -> Result<()> {
    if !args.watch {
        return sync_once(&args).await;
    }

    let interval = args
        .interval
        .as_deref()
        .map(parse_ttl)
        .transpose()
        .context("--interval")?
        .unwrap_or_else(|| chrono::Duration::minutes(5));
    let base_secs = interval.num_seconds().max(5) as u64;

    loop {
        match sync_once(&args).await {
            Ok(()) => {}
            // A dead session won't heal by looping — surface exit code 2 so a
            // supervisor can react (re-login / rotate the ak- key).
            Err(e) if e.downcast_ref::<crate::AuthRequired>().is_some() => return Err(e),
            // The user answered a prompt with Esc / Ctrl-C: they meant to stop.
            // Earlier passes may have written; only this one wrote nothing.
            Err(e) if e.downcast_ref::<crate::Cancelled>().is_some() => {
                anyhow::bail!("watch stopped — cancelled before this pass wrote anything (earlier passes' changes stay)")
            }
            Err(e) => crate::ui::warn("", format_args!("sync failed (will retry): {e:#}")),
        }
        // ±10% jitter so a fleet of watchers provisioned at the same moment
        // doesn't thunder against the gateway in lockstep.
        let jitter = {
            use rand::RngExt;
            rand::rng().random_range(0.9..1.1)
        };
        let sleep_secs = (base_secs as f64 * jitter).max(1.0);
        tokio::time::sleep(std::time::Duration::from_secs_f64(sleep_secs)).await;
    }
}

async fn sync_once(args: &SyncArgs) -> Result<()> {
    let session = session::open(args.host.as_deref()).await?;
    let api = &session.api;
    // First, so a sync this build can no longer make still names the fix.
    update_notice(&api.origin).await;
    let yes = args.yes || session.ci;

    // Auto-resolve the scope from the cwd: inside a provisioned project (one with
    // a `.streamscopeai/`) sync that project; otherwise the global set.
    let paths = Paths::for_scope(&resolve_scope(None, false, false)?)?;
    // Whether this manifest is a project's: its clients with a project form
    // are written at their project-local path.
    let in_project = paths.project_root().is_some();
    let mut manifest = Manifest::load(&paths)?;
    // What a backup run of this sync restores the manifest to.
    let manifest_before = manifest.clone();
    // Exact `origin#slug` key first; fall back to a unique same-origin entry
    // so a provision run keyed with a slugged portal URL still syncs when
    // this invocation got a bare origin (or vice versa) — only then: two
    // different slugs are two tenants, never one another's entry.
    let entry_key = if manifest.hosts.contains_key(&session.key) {
        session.key.clone()
    } else {
        let origin = session.key.split('#').next().unwrap_or(&session.key);
        let session_bare = !session.key.contains('#');
        let same_origin: Vec<&String> = manifest
            .hosts
            .keys()
            .filter(|k| k.split('#').next() == Some(origin) && (session_bare || !k.contains('#')))
            .collect();
        match same_origin.len() {
            1 => same_origin[0].clone(),
            _ => session.key.clone(),
        }
    };
    let ws = manifest
        .hosts
        .get(&entry_key)
        .cloned()
        .filter(|w| !w.clients.is_empty())
        .with_context(|| {
            format!(
                "nothing provisioned for {} yet — run: ssai provision",
                session.key
            )
        })?;
    let others = manifest.files_of_other_hosts(&entry_key);
    let workspace_id = ws
        .workspace_id
        .context("the local manifest records no workspace — run: ssai provision")?;

    // ----- Client filter (this run only — the manifest set is unchanged) -----
    if !args.clients.is_empty() && !args.skip.is_empty() {
        bail!("--client and --skip can't be combined");
    }
    let provisioned: Vec<String> = ws.clients.iter().map(|c| c.client_id.clone()).collect();
    for c in args.clients.iter().chain(args.skip.iter()) {
        if !provisioned.contains(c) {
            bail!(
                "{c:?} isn't provisioned for {} — provisioned: {}",
                entry_key,
                provisioned.join(", ")
            );
        }
    }
    let selected: std::collections::HashSet<String> = if !args.clients.is_empty() {
        args.clients.iter().cloned().collect()
    } else if !args.skip.is_empty() {
        provisioned
            .iter()
            .filter(|c| !args.skip.contains(*c))
            .cloned()
            .collect()
    } else {
        provisioned.iter().cloned().collect()
    };
    if selected.is_empty() {
        bail!("--skip leaves nothing to sync");
    }
    let partial = selected.len() < ws.clients.len();

    let run_stamp = crate::state::new_run_stamp("");

    // ----- Local MCP servers the workspace no longer offers -----
    // A server an administrator revoked, disabled or deleted is dropped from
    // each synced client's selection HERE, before any bundle is asked for:
    // the gateway refuses a bundle naming one. A list that cannot be read
    // leaves what is offered UNKNOWN: the recorded servers are kept, nothing
    // is withdrawn, and the sync goes on.
    let has_local = ws.clients.iter().any(|c| selected.contains(&c.client_id) && !c.mcp_local_servers.is_empty());
    let offered: Option<BTreeMap<uuid::Uuid, String>> = if !has_local {
        Some(BTreeMap::new())
    } else {
        match api.mcp_local_servers(workspace_id).await {
            Ok(list) => Some(list.into_iter().map(|s| (s.id, s.slug)).collect()),
            Err(e) => {
                crate::ui::warn(
                    "",
                    format_args!(
                        "the local MCP servers of this workspace could not be read ({e:#}) — keeping the ones your tools have"
                    ),
                );
                None
            }
        }
    };
    let kept_local = super::provision::split_offered_local(&ws.clients, &selected, offered.as_ref());
    // Slugs by id, for the lines and the record: what is offered, and what
    // was recorded.
    let mut local_slugs: BTreeMap<uuid::Uuid, String> = offered.clone().unwrap_or_default();
    local_slugs.extend(ws.clients.iter().flat_map(|c| c.mcp_local_servers.iter().map(|s| (s.id, s.slug.clone()))));

    // ----- Reconstruct the provision-time groups (mode × provider) -----
    let mut plans: Vec<ClientPlan> = ws
        .clients
        .iter()
        .map(|c| ClientPlan {
            client_id: c.client_id.clone(),
            template_index: c.template_index,
            mode: Mode::from_manifest(&c.mode),
            provider_id: c.provider_id,
            mcp_server_ids: c.mcp_server_ids.clone(),
            mcp_local_server_ids: kept_local.get(&c.client_id).cloned().unwrap_or_default(),
        })
        .collect();

    // ----- The synced clients' templates -----
    // Read once per run for a synced client that has a local server (does its
    // setup still write one?) or has no server and no provider at all (is it
    // a setup of MCP servers only, with nothing to write?). One whose
    // template cannot be read keeps its selection, and its bundle answers.
    let mut recorded_templates: BTreeMap<String, Vec<streamscope_client_templates::ClientProfileTemplate>> =
        BTreeMap::new();
    for c in ws.clients.iter().filter(|c| {
        selected.contains(&c.client_id)
            && (!c.mcp_local_servers.is_empty() || (c.mcp_server_ids.is_empty() && c.provider_id.is_none()))
    }) {
        if let Ok(profile) = api.client_profile(&c.client_id, workspace_id).await
            && profile.templates.get(c.template_index).is_some()
        {
            recorded_templates.insert(c.client_id.clone(), profile.templates);
        }
    }

    // ----- Local MCP servers that left a client's selection -----
    // The rule `provision` applies, through the same function: a local server
    // goes only to a template with a form for one. Each server that left —
    // no longer offered, or its client's setup no longer writing local
    // servers — is withdrawn from that client's files now, and the record
    // saved at once: its own entry, nothing else, whatever becomes of the
    // client's sync below.
    let offered_ids: Option<BTreeSet<uuid::Uuid>> = offered.as_ref().map(|o| o.keys().copied().collect());
    let mut withdraw_failed: Vec<String> = Vec::new();
    let mut withdrew = false;
    for plan in plans.iter_mut().filter(|p| selected.contains(&p.client_id)) {
        let asked = plan.mcp_local_server_ids.len();
        if recorded_templates.contains_key(&plan.client_id) {
            super::provision::keep_local_where_writable(std::slice::from_mut(plan), &local_slugs, |id| {
                recorded_templates.get(id).map(Vec::as_slice)
            });
        }
        let lost_form = plan.mcp_local_server_ids.len() < asked;
        let Some(client) = manifest
            .hosts
            .get_mut(&entry_key)
            .and_then(|entry| entry.clients.iter_mut().find(|c| c.client_id == plan.client_id))
        else {
            continue;
        };
        let gone = super::provision::local_withdrawals(
            &client.mcp_local_servers,
            &plan.mcp_local_server_ids,
            offered_ids.as_ref(),
            lost_form,
        );
        match super::provision::withdraw_local_servers(client, &gone, &others, &run_stamp, &paths, false) {
            Ok(changed) => withdrew |= changed,
            Err(e) => {
                eprintln!("{}: {e:#}", plan.client_id);
                withdraw_failed.push(plan.client_id.clone());
            }
        }
    }
    if withdrew {
        if let Err(e) = crate::state::backup_manifest_into_run(&paths, &run_stamp, &manifest_before) {
            crate::ui::warn("  ", format_args!("the manifest was not backed up with this run ({e:#}) — `restore` cannot reconcile it"));
        }
        manifest.save(&paths)?;
    }
    // The record as it now stands is what the writes below merge against.
    let ws = manifest.hosts.get(&entry_key).cloned().unwrap_or(ws);
    let records = crate::state::FileRecords { ws: &ws, others: &others };
    // A client on a setup of MCP servers only, left with none, has nothing to
    // write: it is left alone below — no key settled, no config asked for.
    let idle = |group: &super::provision::Group| {
        let kind = group.indices.first().and_then(|&i| {
            recorded_templates.get(&plans[i].client_id).and_then(|t| t.get(plans[i].template_index)).map(|t| t.kind)
        });
        super::provision::nothing_to_write(kind, group)
    };
    let groups = group_plans(&plans);

    // ----- Key strategy (mirrors provision's precedence, per group) -----
    let external_key = external_gateway_key()?;
    if external_key.is_some() && super::provision::distinct_key_scopes(&groups) > 1 {
        bail!(
            "STREAMSCOPE_GATEWAY_KEY can't serve mixed BYOK/gateway clients — \
             sync them in separate runs, or re-run ssai provision"
        );
    }
    let external_sha = external_key.as_deref().map(|k| sha256_hex(k.as_bytes()));
    let ttl = args
        .key_ttl
        .as_deref()
        .map(parse_ttl)
        .transpose()
        .context("--key-ttl")?
        .or_else(|| session.ci.then(|| chrono::Duration::hours(2)));
    let expires_at = ttl.map(|t| chrono::Utc::now() + t);
    // The device's per-tool keys: only a run that may reuse or record one reads
    // them (a CI runner may have no writable HOME).
    let device_keys = external_key.is_none() && !session.ci;
    let mut tool_keys = if device_keys { ToolKeys::load_or_warn() } else { ToolKeys::default() };
    let live_keys = if external_key.is_none()
        && (!ws.keys.is_empty() || tool_keys.hosts.get(&session.key).is_some_and(|l| !l.is_empty()))
    {
        Some(api.quickstart_keys(workspace_id).await?)
    } else {
        None
    };
    let is_live = |id: uuid::Uuid, fa: bool| {
        live_keys
            .as_ref()
            .is_some_and(|lk| lk.iter().any(|k| k.id == id && k.forward_auth == fa))
    };

    // ----- Per-group bundle + render -----
    let write_mode = WriteMode { dry_run: false, print: false, verbose: false };
    // A client whose withdrawal failed is a failed client, whatever follows.
    let mut failures: Vec<String> = withdraw_failed;
    // Written project configs (holding a key) that could not be git-ignored.
    let mut unignored: Vec<String> = Vec::new();
    let mut wrote_total = 0usize;
    let mut total_selected = 0usize;
    let mut any_change = withdrew;
    // Every selected tool's key, settled BEFORE anything is written, so one
    // prompt covers the run and declining it changes nothing.
    let mut choices: std::collections::HashMap<String, KeyChoice> = std::collections::HashMap::new();
    let mut dead: Vec<String> = Vec::new();
    let mut dead_ids: Vec<uuid::Uuid> = Vec::new();
    let mut splitting: Vec<String> = Vec::new();
    // The last run used an out-of-band key but the env var is gone now: no key
    // of ours — the tool's own or the device's — stands in for the operator's,
    // for the tools that run wrote (recorded with no key of ours). A tool with
    // its own key syncs as usual.
    let on_external_key = |id: &str| ws.clients.iter().any(|c| c.client_id == id && c.key_id.is_none());
    if external_key.is_none()
        && ws.external_key_sha256.is_some()
        && selected.iter().any(|id| on_external_key(id))
    {
        bail!(
            "the last provision used STREAMSCOPE_GATEWAY_KEY — set it again \
             (or re-run ssai provision to mint a gateway key)"
        );
    }
    if external_key.is_none() {
        for group in &groups {
            if !group.indices.iter().any(|&i| selected.contains(&plans[i].client_id)) || idle(group) {
                continue;
            }
            let forward_auth = matches!(group.mode, Mode::Byok);
            // `--key-ttl` asks for a key of its own: the device's would ignore it.
            let device = tool_keys
                .find(&session.key, workspace_id, &group.client_id, group.mode.as_str(), group.provider_id)
                .filter(|k| args.key_ttl.is_none() && is_live(k.id, forward_auth))
                .cloned();
            let choice = super::provision::choose_key(&ws, group, |id| is_live(id, forward_auth), device);
            // Each tool replaces its own key, so a filtered run is fine: a tool
            // left out keeps the dead key until its own sync replaces it.
            if let KeyChoice::Mint { replaces: Some(old), old_live: false, .. } = &choice
                && !dead.contains(&old.name)
            {
                dead.push(old.name.clone());
                dead_ids.push(old.id);
            }
            // A live key that is not the tool's own (shared with another tool,
            // or of the wrong kind for its mode): it gets its own, which rewrites
            // its config as much as a dead key's replacement does.
            if let KeyChoice::Mint { replaces: Some(old), old_live: true, .. } = &choice {
                splitting.push(format!("{} (off \"{}\")", group.client_id, old.name));
            }
            choices.insert(group.signature(), choice);
        }
    }
    if !dead.is_empty() {
        println!(
            "Key(s) {} are gone (revoked/expired) — each tool using one gets a replacement and \
             its config is rewritten.",
            dead.iter().map(|n| format!("\"{n}\"")).collect::<Vec<_>>().join(", ")
        );
    }
    if !splitting.is_empty() {
        println!(
            "Tools on a gateway key that is not their own get one of their own, and their configs are rewritten: {}.",
            splitting.join(", ")
        );
    }
    if !dead.is_empty() || !splitting.is_empty() {
        if !yes && !confirm("Mint the new key(s)?")? {
            bail!("aborted — nothing was changed");
        }
        // Tools this filtered run leaves out keep the dead key until their own sync.
        let left_out: Vec<&str> = ws
            .clients
            .iter()
            .filter(|c| !selected.contains(&c.client_id) && c.key_id.is_some_and(|id| dead_ids.contains(&id)))
            .map(|c| c.client_id.as_str())
            .collect();
        if !left_out.is_empty() {
            println!(
                "  {} also hold a dead key and are not in this run — `ssai sync` them too.",
                left_out.join(", ")
            );
        }
    }
    // Refresh the egress allowlist (`ssai run`) from this run's base URLs.
    let mut proxy_origins: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    // What the workspace offers, as the last bundle answered.
    let mut client_access: Option<crate::api::ClientAccess> = None;
    // Clients the administrator no longer offers: left as they are.
    let mut disabled: Vec<String> = Vec::new();

    for group in &groups {
        let forward_auth = matches!(group.mode, Mode::Byok);
        let group_sig = group.signature();
        let group_clients: Vec<&ClientPlan> = group.indices.iter().map(|&i| &plans[i]).collect();
        let selected_here: Vec<&ClientPlan> = group_clients
            .iter()
            .copied()
            .filter(|p| selected.contains(&p.client_id))
            .collect();
        if selected_here.is_empty() {
            continue;
        }
        total_selected += selected_here.len();
        if idle(group) {
            println!("{}", super::provision::nothing_to_write_line(&group.client_id));
            continue;
        }

        // Key for this group.
        let mut reused_plaintext: Option<String> = None;
        // The configs must be rewritten with another key (a replacement or the
        // device's), whatever the gateway-side etag says.
        let mut key_changed = false;
        // Minted by this run — the only key `sync` records as the tool's
        // device key: one it kept may be a `provision --key-name`/`--key-ttl`
        // key, which is not the tool's to share.
        let mut minted = false;
        let key_spec = if let Some(ext) = &external_key {
            Some(KeySpec::external(ext.starts_with("vk-")))
        } else {
            let choice = choices
                .remove(&group_sig)
                .ok_or_else(|| anyhow::anyhow!("no key was settled for {}", group.client_id))?;
            match choice {
                KeyChoice::Own(k) => {
                    reused_plaintext = Some(k.plaintext);
                    Some(KeySpec::reuse(k.id, forward_auth))
                }
                KeyChoice::Device { key, replaces } => {
                    println!(
                        "{}: using its key \"{}\" from this device{}.",
                        group.client_id,
                        key.name,
                        replaces.map(|r| format!(" in place of \"{}\"", r.name)).unwrap_or_default()
                    );
                    key_changed = true;
                    reused_plaintext = Some(key.plaintext);
                    Some(KeySpec::reuse(key.id, forward_auth))
                }
                KeyChoice::Mint { replaces, old_live, had_key } => {
                    minted = true;
                    // A replacement (a dead key was confirmed for the whole run
                    // above; a live one is shared with another tool, which keeps
                    // it) or a dangling record: the fresh key must reach the
                    // config, whatever the etag says.
                    if had_key {
                        if replaces.is_some() && old_live {
                            println!("{} gets a gateway key of its own.", group.client_id);
                        }
                        key_changed = true;
                    }
                    // A fresh key for the tool: a dead or shared one's
                    // replacement (above), or — nothing recorded, spec-OAuth
                    // MCP-only — one the server mints only if a template embeds
                    // a key, honouring the same TTL rules.
                    Some(KeySpec::mint(None, Some(super::provision::key_prefix(session.ci, group)), expires_at, forward_auth))
                }
            }
        };

        // Send the WHOLE group (so the etag matches provision time); write only
        // the selected subset.
        let bundle = api
            .provision_bundle(&BundleRequest {
                workspace_id,
                clients: group_clients
                    .iter()
                    .map(|p| BundleSelection {
                        client_id: p.client_id.clone(),
                        template_index: p.template_index,
                    })
                    .collect(),
                key: key_spec,
                llm_provider_id: group.provider_id,
                mcp_servers: group
                    .mcp_server_ids
                    .iter()
                    .map(|id| McpSelection { virtual_server_id: *id })
                    .collect(),
                mcp_local_servers: group
                    .mcp_local_server_ids
                    .iter()
                    .map(|id| crate::api::McpLocalSelection { local_server_id: *id })
                    .collect(),
            })
            .await;
        // One group's bundle is one gateway call, and a refusal is about that
        // group's clients — a client whose profile or MCP servers no longer
        // render must not take the others' convergence with it.
        let bundle = match bundle {
            Ok(b) => b,
            Err(e) if crate::api::error_code(&e) == Some(crate::api::CLIENT_DISABLED) => {
                disabled.extend(selected_here.iter().map(|p| p.client_id.clone()));
                continue;
            }
            Err(e) => {
                let names: Vec<String> =
                    selected_here.iter().map(|p| p.client_id.clone()).collect();
                eprintln!("{}: {e:#}", names.join(", "));
                failures.extend(names);
                continue;
            }
        };

        client_access = Some(bundle.client_access.clone());
        let plaintext = resolve_bundle_plaintext(
            &bundle,
            reused_plaintext,
            external_key.as_deref(),
            "re-run ssai provision to converge",
        )?;

        // A key this run minted becomes the tool's key for every project (see
        // `ToolKeys`); a CI or out-of-band key is not ours to hand on, and one
        // minted under `--key-ttl` expires on every project that would reuse it.
        if minted
            && device_keys
            && args.key_ttl.is_none()
            && let (Some(k), Some(plain)) = (&bundle.key, &plaintext)
        {
            super::provision::record_device_key(&mut tool_keys, &session.key, workspace_id, group, k, plain);
        }

        // No-op detection for this group.
        let unchanged = ws.group_etags.get(&group_sig).map(String::as_str)
            == Some(bundle.bundle_etag.as_str())
            && ws.external_key_sha256 == external_sha
            && !key_changed;
        let mut to_write: Vec<&ClientPlan> = selected_here.clone();
        if unchanged {
            // Even unchanged gateway-side, a provisioned file that vanished
            // locally is re-written — sync's contract is convergence.
            to_write.retain(|p| {
                ws.clients
                    .iter()
                    .find(|c| c.client_id == p.client_id)
                    .map(|c| {
                        c.files
                            .iter()
                            .any(|f| !expand_tilde(&f.path).map(|p| p.exists()).unwrap_or(true))
                    })
                    .unwrap_or(false)
            });
            if to_write.is_empty() {
                continue;
            }
            println!(
                "Up to date on the gateway, but file(s) are missing locally — rewriting {}.",
                to_write
                    .iter()
                    .map(|p| p.client_id.clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        any_change = true;

        let write_set: std::collections::HashSet<&str> =
            to_write.iter().map(|p| p.client_id.as_str()).collect();
        let key_id = bundle.key.as_ref().map(|k| k.id);
        let mut managed: Vec<ManagedClient> = Vec::new();
        let mut group_failed = false;
        for cb in &bundle.clients {
            if let Some(origin) = super::provision::proxy_origin_of(cb) {
                proxy_origins.insert(origin);
            }
            if !write_set.contains(cb.client_id.as_str()) {
                continue;
            }
            match provision_one(cb, plaintext.as_deref(), &write_mode, &run_stamp, &records, &paths, &mut unignored) {
                Ok(Some(mut m)) => {
                    m.mode = group.mode.as_str().to_string();
                    m.provider_id = group.provider_id;
                    m.key_id = key_id;
                    m.mcp_server_ids = group.mcp_server_ids.clone();
                    m.mcp_local_servers = super::provision::managed_local(
                        &group.mcp_local_server_ids,
                        &local_slugs,
                        std::mem::take(&mut m.mcp_local_servers),
                    );
                    m.mcp_local_commands = super::provision::local_commands_written(cb, in_project);
                    // The developer sees a launch an administrator added or
                    // changed, as it is applied.
                    let before = ws.clients.iter().find(|c| c.client_id == cb.client_id).map(|c| &c.mcp_local_commands);
                    for line in super::provision::changed_local_command_lines(before, &m.mcp_local_commands) {
                        println!("{}: {line}", cb.client_id);
                    }
                    managed.push(m);
                    wrote_total += 1;
                }
                Ok(None) => {}
                Err(e) => {
                    eprintln!("{}: {e:#}", cb.client_id);
                    failures.push(cb.client_id.clone());
                    group_failed = true;
                }
            }
            super::provision::print_mcp_warnings(cb, in_project);
        }

        // Record this group. The etag stamps only on a full, clean write of THIS
        // group (one tool) — a failure in it must keep the next sync
        // re-converging it. A filtered run that wrote the group whole stamps it;
        // an unrelated group's failure must not freeze a clean group's etag, so
        // gate on this group, not global state.
        let stamp_etag = !group_failed && write_set.len() == group_clients.len();
        let entry = manifest.hosts.entry(entry_key.clone()).or_default();
        record_group(
            entry,
            bundle.key.as_ref(),
            &bundle.bundle_etag,
            plaintext.as_deref(),
            external_key.as_deref(),
            &group_sig,
            stamp_etag,
            managed,
        );
    }

    {
        let entry = manifest.hosts.entry(entry_key.clone()).or_default();
        if !proxy_origins.is_empty() {
            entry.proxy_origins = proxy_origins.into_iter().collect();
        }
        if let Some(access) = client_access.take() {
            entry.client_access = Some(crate::state::ClientAccessRecord::now(access));
        }
        super::provision::prune_unused_etags(entry);
        // Only prune orphaned keys after a clean run — a failed group records a
        // (possibly re-minted) key whose client wasn't written, and pruning it
        // here would strand it.
        if failures.is_empty() {
            super::provision::note_unused_keys(&prune_unused_keys(entry));
        }
        // Best effort: the configs are written, and the manifest recording them
        // (with the keys they hold) must be saved even if its backup copy fails.
        if let Err(e) = crate::state::backup_manifest_into_run(&paths, &run_stamp, &manifest_before) {
            crate::ui::warn("  ", format_args!("the manifest was not backed up with this run ({e:#}) — `restore` cannot reconcile it"));
        }
        manifest.save(&paths)?;
    }

    if !disabled.is_empty() {
        crate::ui::warn("", format_args!(
            "{} {} disabled by your administrator — not offered to this workspace; their files are left as \
             they are (`ssai forget` removes them)",
            disabled.join(", "),
            if disabled.len() == 1 { "is" } else { "are" },
        ));
    }
    if !failures.is_empty() {
        if failures.len() < total_selected {
            bail!(PartialWrite(format!(
                "{}/{} clients failed: {}",
                failures.len(),
                total_selected,
                failures.join(", ")
            )));
        }
        bail!("sync failed for: {}", failures.join(", "));
    }
    super::provision::unignored_failure(&unignored)?;
    if !any_change {
        println!("Up to date — nothing to rewrite.");
    } else if partial {
        println!("Synced {wrote_total} of {} managed client(s).", ws.clients.len());
    } else {
        println!("Synced {wrote_total} client(s).");
    }
    Ok(())
}

/// The new-version notice, at most once a day per gateway — a `--watch`
/// would otherwise ask on every pass. Best effort, never fails the sync.
async fn update_notice(origin: &str) {
    let mut stamps = UpdateCheckFile::load();
    let now = chrono::Utc::now();
    if let Some(last) = stamps.last_checked.get(origin)
        && now - *last < chrono::Duration::hours(24)
    {
        return;
    }
    if super::update::newer_version_notice(origin).await {
        stamps.last_checked.insert(origin.to_string(), now);
        let _ = stamps.save();
    }
}

#[cfg(test)]
mod key_choice_tests {
    use super::*;
    use std::assert_matches;
    use crate::commands::provision::{choose_key, Group, KeyChoice};
    use crate::state::{ManifestKey, WorkspaceManifest};

    const A: &str = "aaaaaaaa-0000-0000-0000-000000000001";
    const B: &str = "bbbbbbbb-0000-0000-0000-000000000002";

    fn key(id: &str) -> ManifestKey {
        serde_json::from_value(serde_json::json!({
            "id": id, "name": format!("k-{}", &id[..4]), "plaintext": "sk-x", "forward_auth": false
        }))
        .unwrap()
    }

    /// `opencode` and `claude-code` both recorded on key `opencode_key`
    /// (`claude_key` for the second when given).
    fn ws(opencode_key: &str, claude_key: &str) -> WorkspaceManifest {
        let client = |id: &str, k: &str| serde_json::json!({
            "client_id": id, "template_index": 0, "last_provisioned": "2026-10-09T12:00:00Z",
            "mode": "gateway", "provider_id": null, "key_id": k, "mcp_server_ids": [], "mcp_local_servers": [], "mcp_local_commands": {}, "files": [],
            "launch_command": null
        });
        let mut keys = serde_json::Map::new();
        for k in [opencode_key, claude_key] {
            keys.insert(k.to_string(), serde_json::to_value(key(k)).unwrap());
        }
        serde_json::from_value(serde_json::json!({
            "clients": [client("opencode", opencode_key), client("claude-code", claude_key)],
            "keys": keys, "group_etags": {}, "proxy_origins": []
        }))
        .unwrap()
    }

    fn opencode() -> Group {
        Group {
            client_id: "opencode".into(),
            mode: Mode::Gateway,
            provider_id: None,
            mcp_server_ids: vec![],
            mcp_local_server_ids: vec![],
            indices: vec![0],
        }
    }

    #[test]
    fn the_tools_own_live_key_is_kept() {
        let c = choose_key(&ws(A, B), &opencode(), |_| true, Some(key(B)));
        assert_matches!(c, KeyChoice::Own(k) if k.id.to_string() == A);
    }

    #[test]
    fn a_shared_key_gives_way_to_the_devices_key_for_the_tool() {
        let c = choose_key(&ws(A, A), &opencode(), |_| true, Some(key(B)));
        assert_matches!(c, KeyChoice::Device { key, replaces: Some(r) } if key.id.to_string() == B && r.id.to_string() == A);
    }

    #[test]
    fn a_shared_key_without_a_device_key_is_replaced_by_a_mint_that_knows_it_was_live() {
        let c = choose_key(&ws(A, A), &opencode(), |_| true, None);
        assert_matches!(c, KeyChoice::Mint { replaces: Some(_), old_live: true, .. });
        let dead = choose_key(&ws(A, A), &opencode(), |_| false, None);
        assert_matches!(dead, KeyChoice::Mint { replaces: Some(_), old_live: false, .. });
    }

    #[test]
    fn a_tool_new_to_the_manifest_takes_the_devices_key() {
        let mut w = ws(A, B);
        w.clients.retain(|c| c.client_id != "opencode");
        let c = choose_key(&w, &opencode(), |_| true, Some(key(B)));
        assert_matches!(c, KeyChoice::Device { replaces: None, .. });
    }

    #[test]
    fn a_dangling_record_mints_and_rewrites() {
        let mut w = ws(A, B);
        w.keys.remove(&A.parse().unwrap());
        let c = choose_key(&w, &opencode(), |_| true, None);
        assert_matches!(c, KeyChoice::Mint { replaces: None, had_key: true, .. });
    }

    #[test]
    fn a_tool_recorded_without_a_key_ignores_the_device_key() {
        let mut w = ws(A, B);
        w.clients[0].key_id = None;
        let c = choose_key(&w, &opencode(), |_| true, Some(key(B)));
        assert_matches!(c, KeyChoice::Mint { replaces: None, had_key: false, .. });
    }

    #[test]
    fn a_dead_own_key_takes_the_devices_live_one() {
        let c = choose_key(&ws(A, B), &opencode(), |id| id.to_string() == B, Some(key(B)));
        assert_matches!(c, KeyChoice::Device { .. });
    }
}
