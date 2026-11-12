//! `ssai provision` — mint/reuse ONE workspace gateway key, pull a
//! provisioning bundle, render locally, and structured-merge each tool's
//! config into place.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::Args;

use streamscope_client_templates::{
    companion_files, companion_project_path, default_llm_template_index, render,
    ClientProfileTemplate, McpAuthMode, TemplateFormat, TemplateKind, Value, API_KEY_PLACEHOLDER,
    PROJECT_SCOPE,
};

use crate::api::{
    ApiClient, BundleKey, BundleRequest, BundleSelection, ClientBundle, ClientProfileWire, KeySpec,
    McpSelection, McpVirtualServer, PortalMe,
};
use crate::state::{
    ensure_gitignored, expand_tilde, gateway_bundle_file, gateway_ca_file, resolve_scope,
    LocalMcpEntry, ManagedClient, ManagedFile, ManagedLocalMcp, Manifest, ManifestKey, ManifestScope, Paths,
    ToolKeys, WorkspaceManifest,
};
use crate::writer;
use crate::PartialWrite;

use super::session::{self, confirm_no, pick, pick_many, pick_many_ticked, Choice};

#[derive(Args)]
pub struct ProvisionArgs {
    /// Client(s) to provision (e.g. --client claude-code --client opencode).
    /// Defaults to the installed tools the gateway has profiles for.
    #[arg(long = "client")]
    pub clients: Vec<String>,
    /// Workspace name or id (prompted when you're in several).
    #[arg(long)]
    pub workspace: Option<String>,
    /// LLM provider (name or id). A bare value (`--provider openai`) is the
    /// default for every client; `--provider claude-code=anthropic` sets it for
    /// one client. Repeatable. Prompted when omitted and several are granted.
    #[arg(long = "provider")]
    pub provider: Vec<String>,
    /// Integration mode per client: `--mode claude-code=byok` /
    /// `--mode opencode=gateway`. Repeatable. Overrides `--byok` for that
    /// client. `gateway` = a managed `sk-` key + curated models; `byok` = a
    /// `vk-` key bound to a BYOK provider, your native auth/model passed
    /// through.
    #[arg(long = "mode")]
    pub mode: Vec<String>,
    /// MCP virtual server slug(s) to wire into MCP-capable clients. Repeatable.
    /// When omitted, a client keeps the servers it was last provisioned with;
    /// an interactive run proposes the reachable ones, those ticked. A client
    /// provisioned for the first time with `--yes` and no `--mcp`/`--all-mcp`
    /// gets none.
    #[arg(long = "mcp", conflicts_with_all = ["all_mcp", "no_mcp"])]
    pub mcp: Vec<String>,
    /// Wire every MCP virtual server your workspace can reach (non-interactive
    /// equivalent of selecting all in the prompt).
    #[arg(long = "all-mcp", conflicts_with = "no_mcp")]
    pub all_mcp: bool,
    /// Wire no MCP servers, gateway or local — skip the proposals entirely.
    #[arg(long = "no-mcp")]
    pub no_mcp: bool,
    /// Local MCP server slug(s) to add to the clients that can start one: a
    /// server this machine runs, from a command line your administrator set.
    /// Repeatable. When omitted, a client keeps the local servers it was last
    /// provisioned with; an interactive run proposes the ones your workspace
    /// is handed, those ticked, when a selected client can be given one. A
    /// client provisioned for the first time with `--yes` gets none.
    #[arg(long = "local-mcp", conflicts_with_all = ["no_mcp", "no_local_mcp"])]
    pub local_mcp: Vec<String>,
    /// Add no local MCP server, and take out the ones a client was
    /// provisioned with. Its gateway MCP servers are kept.
    #[arg(long = "no-local-mcp")]
    pub no_local_mcp: bool,
    /// Override a client's template pick by variant name:
    /// --template opencode=anthropic (chat, responses, anthropic, gemini, mcp,
    /// instructions; `-oauth` for an MCP spec-OAuth variant)
    #[arg(long = "template")]
    pub template_overrides: Vec<String>,
    /// Name for the key this run mints (gateway or BYOK); in a run minting
    /// several, the prefix of each (`<name>-<tool>`). Default: the tool's name.
    #[arg(long)]
    pub key_name: Option<String>,
    /// Time-to-live for a freshly-minted gateway key, e.g. 2h, 30m, 7d
    /// (default: no expiry; CI mode defaults to 2h).
    #[arg(long)]
    pub key_ttl: Option<String>,
    /// Default EVERY LLM client to BYOK mode (you supply your own upstream
    /// credential). Override per client with `--mode <client>=gateway`.
    #[arg(long)]
    pub byok: bool,
    /// Show what would be written without touching any tool config. (A
    /// gateway key may still be minted by the dry run — it's remembered and
    /// reused by the next real run.)
    #[arg(long)]
    pub dry_run: bool,
    /// Don't prompt — fail instead when a choice is ambiguous.
    #[arg(long, short = 'y')]
    pub yes: bool,
    /// Print rendered configs to stdout instead of writing files.
    #[arg(long)]
    pub print: bool,
    /// Print each client's full setup notes after writing (off by default — the
    /// CLI already writes the files, so it just shows the path + launch command).
    #[arg(long)]
    pub verbose: bool,
    /// Write configs into THIS project (the current directory) and track them
    /// in `./.streamscopeai/`, instead of the global home-dir config. Clients
    /// with only a global config (e.g. Continue) are skipped unless named with
    /// `--client` (or ticked in the prompt and confirmed), which writes them to
    /// their global config.
    #[arg(long)]
    pub local: bool,
    /// Like --local but for the given project directory.
    #[arg(long, value_name = "DIR")]
    pub dir: Option<PathBuf>,
    /// Force the global home-dir config even when run inside a project that has
    /// a `./.streamscopeai/` dir (which otherwise auto-selects project scope).
    #[arg(long, conflicts_with_all = ["local", "dir"])]
    pub global: bool,
    /// Gateway to provision from when logged into several (origin or origin#slug).
    #[arg(long)]
    pub host: Option<String>,
}

pub async fn run(mut args: ProvisionArgs) -> Result<()> {
    let session = session::open(args.host.as_deref()).await?;
    let api = &session.api;
    // CI sessions (`STREAMSCOPE_AK`) never prompt — an ambiguous choice is an
    // error, exactly as if --yes had been passed.
    if session.ci {
        args.yes = true;
    }

    let me = api.me().await?;

    // ----- Workspace -----
    let workspace = match &args.workspace {
        Some(sel) => {
            let matches: Vec<_> = me
                .workspaces
                .iter()
                .filter(|w| w.id.to_string() == *sel || w.name.eq_ignore_ascii_case(sel))
                .collect();
            match matches.len() {
                1 => matches[0].clone(),
                0 => bail!(
                    "no workspace matches {sel:?} — yours: {}",
                    me.workspaces.iter().map(|w| w.name.clone()).collect::<Vec<_>>().join(", ")
                ),
                _ => bail!("workspace selector {sel:?} is ambiguous — use the id"),
            }
        }
        None => match me.workspaces.len() {
            0 => bail!("you are not a member of any workspace — ask your admin to add you"),
            1 => me.workspaces[0].clone(),
            _ if args.yes => bail!(
                "you are in several workspaces — pick one with --workspace: {}",
                me.workspaces.iter().map(|w| w.name.clone()).collect::<Vec<_>>().join(", ")
            ),
            _ => {
                let names: Vec<Choice> = me.workspaces.iter().map(|w| Choice::new(&w.name)).collect();
                let idx = pick("Which workspace should the key be billed to?", &names)?;
                me.workspaces[idx].clone()
            }
        },
    };

    // Re-fetch with providers scoped to the chosen workspace — the unscoped
    // `me` above lists every provider the user can reach across all workspaces;
    // the provider prompt must offer only the selected workspace's grants.
    let me = api.me_for_workspace(workspace.id).await?;

    // ----- Clients -----
    // What this workspace is offered: each workspace has its own client set.
    let catalog = api.quickstart_clients(workspace.id).await?;
    if catalog.clients.is_empty() {
        bail!(
            "the workspace {:?} is offered no client — ask your administrator to offer one on its Portal & clients profile",
            workspace.name
        );
    }
    // Clients ticked in the prompt (pre-ticked by detection). In a project run a
    // global-only client is written to its home config only when `--client`
    // names it, or — for one ticked here — when the user confirms it.
    let mut picked_ids: Vec<String> = Vec::new();
    let chosen_ids: Vec<String> = if args.clients.is_empty() {
        let detected = detect_installed_clients();
        let usable: Vec<String> = catalog
            .clients
            .iter()
            .filter(|c| c.compatible && detected.installed.contains(&c.id.as_str()))
            .map(|c| c.id.clone())
            .collect();
        let config_only: Vec<&str> = catalog
            .clients
            .iter()
            .filter(|c| c.compatible && detected.config_only.contains(&c.id.as_str()))
            .map(|c| c.id.as_str())
            .collect();
        if !config_only.is_empty() {
            println!(
                "Not installed (a config dir is left, skipped): {} — name one with --client to provision it anyway.",
                config_only.join(", ")
            );
        }
        if usable.is_empty() {
            let known: Vec<String> = catalog
                .clients
                .iter()
                .filter(|c| c.compatible)
                .map(|c| c.id.clone())
                .collect();
            bail!(
                "no installed AI clients detected — pick explicitly with --client. Available: {}",
                known.join(", ")
            );
        }
        if args.yes {
            println!("Detected installed clients: {}", usable.join(", "));
            usable
        } else {
            // One multi-select over the detected set (default: all) rather than
            // an all-or-nothing gate or a Y/n question per client.
            let choices: Vec<Choice> = usable.iter().map(Choice::new).collect();
            let picks = pick_many("Detected installed clients — which should I provision?", &choices, 1)?;
            if picks.is_empty() {
                bail!("nothing selected");
            }
            let picked: Vec<String> = picks.into_iter().map(|i| usable[i].clone()).collect();
            picked_ids = picked.clone();
            picked
        }
    } else {
        for c in &args.clients {
            let Some(summary) = catalog.clients.iter().find(|x| &x.id == c) else {
                bail!(
                    "the workspace {:?} is offered no client {c:?} — available: {}",
                    workspace.name,
                    catalog.clients.iter().map(|x| x.id.clone()).collect::<Vec<_>>().join(", ")
                );
            };
            if !summary.compatible {
                bail!(
                    "client {c:?} is not provisionable for you: {}",
                    summary.incompatibility_reason.as_deref().unwrap_or("not compatible")
                );
            }
        }
        args.clients.clone()
    };

    // Fetch each chosen client's profile once — reused for the MCP-capability
    // check below and the template pick further down.
    let mut profiles: BTreeMap<String, ClientProfileWire> = BTreeMap::new();
    for client_id in &chosen_ids {
        profiles.insert(client_id.clone(), api.client_profile(client_id, workspace.id).await?);
    }
    let any_client_supports_mcp = profiles
        .values()
        .any(|p| p.templates.iter().any(|t| matches!(t.kind, TemplateKind::Mcp | TemplateKind::Combined)));

    // What each chosen client was last provisioned with, read from the
    // manifests this run can land in before its scope is settled (the scope's
    // own first): a client keeps the template it is on, and the proposals
    // below open with what the clients already have.
    let recorded_before: BTreeMap<String, ManagedClient> = {
        let mut scopes: Vec<ManifestScope> =
            resolve_scope(args.dir.as_deref(), args.local, args.global).ok().into_iter().collect();
        scopes.push(ManifestScope::Global);
        let mut seen: BTreeMap<String, ManagedClient> = BTreeMap::new();
        for client in scopes
            .iter()
            .filter_map(|scope| Paths::for_scope(scope).ok())
            .filter_map(|paths| Manifest::load(&paths).ok())
            .flat_map(|manifest| manifest.hosts.get(&session.key).map(|ws| ws.clients.clone()).unwrap_or_default())
            .filter(|c| chosen_ids.contains(&c.client_id))
        {
            seen.entry(client.client_id.clone()).or_insert(client);
        }
        seen
    };

    // ----- Gateway MCP servers -----
    // Resolved before templates because, for a client provisioned for the
    // first time, it gates the MCP-only template choice. Web quickstart and
    // this CLI both propose which MCP servers to include and both surface the
    // per-user-OAuth "connect first" state — keep them in sync.
    let recorded_gateway: BTreeSet<uuid::Uuid> =
        recorded_before.values().flat_map(|c| c.mcp_server_ids.iter().copied()).collect();
    let mcp_choice =
        resolve_mcp_servers(api, workspace.id, &args, any_client_supports_mcp, &recorded_gateway).await?;

    // Whether this run names gateway MCP servers — gates the MCP-only template
    // choice of a client with no record. A local server never moves a client
    // onto an MCP-only template that cannot write it: it only breaks the tie
    // for a client with no LLM template at all, toward the MCP template that
    // has a form for one.
    let has_mcp = mcp_choice.chosen.as_ref().is_some_and(|ids| !ids.is_empty());
    let wants_local = !args.no_mcp && !args.no_local_mcp && !args.local_mcp.is_empty();

    // ----- Templates -----
    let overrides = parse_template_overrides(&args.template_overrides)?;
    let mut selections: Vec<(String, usize, ClientProfileTemplate)> = Vec::new();
    for client_id in &chosen_ids {
        let profile = &profiles[client_id];
        let index = match overrides.get(client_id) {
            Some(name) => template_index_by_name(client_id, &profile.templates, name)?,
            // A client stays on the template it was provisioned with — never
            // one of another kind — unless `--template` names another.
            None => match recorded_before
                .get(client_id)
                .map(|c| c.template_index)
                .filter(|i| *i < profile.templates.len())
                .or_else(|| default_template_index(&profile.templates, has_mcp, wants_local))
            {
                Some(i) => i,
                // A client with only MCP templates and no `--mcp` selected (e.g.
                // Cursor in an LLM-only run) has nothing to provision here —
                // skip it with a notice instead of aborting the whole run.
                None => {
                    println!(
                        "  skipping {client_id} — only provisionable with an MCP server (pass --mcp <slug>)"
                    );
                    continue;
                }
            },
        };
        let template = profile
            .templates
            .get(index)
            .with_context(|| format!("{client_id}: template index {index} out of range"))?
            .clone();
        selections.push((client_id.clone(), index, template));
    }
    if selections.is_empty() {
        bail!("no clients left to provision");
    }

    // ----- Provisioning scope: global home-dir config vs this project -----
    // `--global` forces global; `--dir`/`--local` or being inside an existing
    // `.streamscopeai/` forces a project; otherwise offer the choice
    // interactively, but only when at least one selected client actually has a
    // project-local config form. In a project run a client with only a global
    // config (no `project_filename`) is skipped unless `--client` names it or the
    // user ticks it in the prompt and confirms (detection under `--yes` never
    // does), and
    // is then written globally — see the scope-job split below.
    let mut scope = resolve_scope(args.dir.as_deref(), args.local, args.global)?;
    if matches!(scope, ManifestScope::Global)
        && !args.global
        && !args.yes
        && selections.iter().any(|(_, _, t)| t.project_filename.is_some())
    {
        let here = std::env::current_dir()?;
        let choice = pick(
            "Where should these configs be written?",
            &[
                Choice::new("Globally").hint("your home-dir config"),
                Choice::new("Into this project").hint(here.display().to_string()),
            ],
        )?;
        if choice == 1 {
            scope = ManifestScope::Project(here);
        }
    }

    // ----- Per-client integration plan (mode + provider) -----
    // Each LLM client is provisioned in `gateway` mode (a managed `sk-` key +
    // curated models) or `byok` mode (a `vk-` key bound to a BYOK downstream,
    // native auth/model passed through). One run can mix the two — e.g.
    // claude-code BYOK + opencode gateway.
    let mode_overrides = parse_mode_overrides(&args.mode)?;
    let (provider_default, provider_overrides) = parse_provider_args(&args.provider)?;
    let byok_available = me.downstream_providers.iter().any(|p| p.byok);

    let mut plans: Vec<ClientPlan> = Vec::with_capacity(selections.len());
    for (client_id, idx, template) in &mut selections {
        if !template.kind.needs_llm() {
            // MCP-only client — no provider; its own gateway key carries the MCP bearer.
            plans.push(ClientPlan {
                client_id: client_id.clone(),
                template_index: *idx,
                mode: Mode::Gateway,
                provider_id: None,
                // Both settled below, once the scope's manifest is read.
                mcp_server_ids: Vec::new(),
                mcp_local_server_ids: Vec::new(),
            });
            continue;
        }
        let mode = match mode_overrides.get(client_id) {
            Some(m) => *m,
            None if args.byok => Mode::Byok,
            None if !args.yes && byok_available => {
                let choice = pick(
                    &format!("Integration mode for {client_id}?"),
                    &[
                        Choice::new("Gateway").hint("managed key + curated models"),
                        Choice::new("BYOK").hint("your own key, native models pass through"),
                    ],
                )?;
                if choice == 1 { Mode::Byok } else { Mode::Gateway }
            }
            None => Mode::Gateway,
        };
        let sel = provider_overrides
            .get(client_id)
            .map(String::as_str)
            .or(provider_default.as_deref());
        let provider_id = resolve_provider(sel, mode, &me, args.yes, client_id)?;
        // A pass-through forwards the client's own credential, which works
        // on its server's protocol: unless `--template` named one, the client
        // speaks that protocol when it has a template for it.
        if mode == Mode::Byok && !overrides.contains_key(client_id.as_str()) {
            let native = me.downstream_providers.iter().find(|p| p.id == provider_id).and_then(|p| p.upstream_protocol.as_deref());
            let templates = &profiles[client_id.as_str()].templates;
            if let Some(i) = default_llm_template_index(templates, native) {
                *idx = i;
                *template = templates[i].clone();
            }
        }
        plans.push(ClientPlan {
            client_id: client_id.clone(),
            template_index: *idx,
            mode,
            provider_id: Some(provider_id),
            mcp_server_ids: Vec::new(),
            mcp_local_server_ids: Vec::new(),
        });
    }

    // ----- Provisioning-scope split: global-only clients -----
    // A client whose profile has a global config but no project-local form
    // (e.g. Continue's `~/.continue/config.yaml`, which the editor extension
    // and the `cn` CLI both read) can only be written to its global config — a
    // "project copy" would be meaningless since the tool reads only the one
    // global file. A project run therefore writes one only when the user NAMED
    // it (`--client`): a project run must not rewrite home-directory configs,
    // and with them every other project, as a side effect of detection.
    // Project-capable clients follow the resolved scope. Each scope keeps its
    // own manifest so `sync`/`status`/`restore` stay coherent.
    let global_only: std::collections::HashMap<&str, bool> = selections
        .iter()
        .map(|(id, _, t)| (id.as_str(), is_global_only_template(t)))
        .collect();

    // Whether this invocation resolved to a project — used to explain why a
    // global-only client's config still lands in the home directory.
    let run_is_project = matches!(scope, ManifestScope::Project(_));
    struct ScopeJob {
        paths: Paths,
        manifest: Manifest,
        /// The manifest as loaded — what a backup run of this job restores.
        manifest_before: Manifest,
        plans: Vec<ClientPlan>,
        is_project: bool,
        /// The local MCP servers this run withdraws, per client, each with
        /// why ([`withdraw_local_servers`]).
        withdrawing: Vec<(String, Vec<(uuid::Uuid, WithdrawReason)>)>,
    }
    // A preview run records keys but never replaces an unreadable manifest.
    let writes = !args.dry_run && !args.print;
    let mut scope_jobs: Vec<ScopeJob> = match &scope {
        ManifestScope::Global => {
            let paths = Paths::for_scope(&scope)?;
            let manifest = Manifest::load_for_provision(&paths, writes)?;
            vec![ScopeJob { paths, manifest_before: manifest.clone(), manifest, plans, is_project: false, withdrawing: Vec::new() }]
        }
        ManifestScope::Project(_) => {
            let (global_plans, project_plans): (Vec<ClientPlan>, Vec<ClientPlan>) = plans
                .into_iter()
                .partition(|p| *global_only.get(p.client_id.as_str()).unwrap_or(&false));
            let (named, rest): (Vec<ClientPlan>, Vec<ClientPlan>) =
                global_plans.into_iter().partition(|p| args.clients.contains(&p.client_id));
            let picked_global: Vec<&str> = rest
                .iter()
                .filter(|p| picked_ids.contains(&p.client_id))
                .map(|p| p.client_id.as_str())
                .collect();
            // A print or dry run writes nothing anywhere: show them, ask nothing.
            let write_picked = !picked_global.is_empty()
                && (args.print
                    || args.dry_run
                    || confirm_no(&format!(
                    "{} have only a global config — also write it to your home directory?",
                    picked_global.join(", ")
                ))?);
            let (picked, skipped): (Vec<ClientPlan>, Vec<ClientPlan>) =
                rest.into_iter().partition(|p| write_picked && picked_ids.contains(&p.client_id));
            let global_plans: Vec<ClientPlan> = named.into_iter().chain(picked).collect();
            if !skipped.is_empty() {
                let ids: Vec<&str> = skipped.iter().map(|p| p.client_id.as_str()).collect();
                println!(
                    "  skipping {} — no project-local config form; provision globally with: \
                     ssai provision --global --client {}",
                    ids.join(", "),
                    ids.join(" --client ")
                );
            }
            if project_plans.is_empty() && global_plans.is_empty() {
                bail!("no clients left to provision in this project");
            }
            let mut jobs = Vec::new();
            if !project_plans.is_empty() {
                let paths = Paths::for_scope(&scope)?;
                let manifest = Manifest::load_for_provision(&paths, writes)?;
                jobs.push(ScopeJob { paths, manifest_before: manifest.clone(), manifest, plans: project_plans, is_project: true, withdrawing: Vec::new() });
            }
            if !global_plans.is_empty() {
                let paths = Paths::for_scope(&ManifestScope::Global)?;
                let manifest = Manifest::load_for_provision(&paths, writes)?;
                jobs.push(ScopeJob { paths, manifest_before: manifest.clone(), manifest, plans: global_plans, is_project: false, withdrawing: Vec::new() });
            }
            jobs
        }
    };

    // ----- Variants: an installation keeps the one it was provisioned with -----
    // Re-provisioning a managed client without `--template` keeps its recorded
    // template (same mode only — a mode change re-picks); a new client gets the
    // default. Then name the pick and how to switch it.
    for job in &mut scope_jobs {
        if let Some(ws) = job.manifest.hosts.get(&session.key) {
            keep_recorded_variants(&mut job.plans, &ws.clients, &overrides, |id| {
                profiles.get(id).map(|p| p.templates.as_slice())
            });
        }
    }

    // ----- MCP servers, per client -----
    // Settled after the scope's manifest is read: what a client was
    // provisioned with — gateway servers and local ones alike — is what it
    // keeps unless this run says otherwise, so provisioning again never takes
    // a server out by omission.
    let recorded_client = |job: &ScopeJob, client_id: &str| -> Option<ManagedClient> {
        job.manifest
            .hosts
            .get(&session.key)
            .and_then(|ws| ws.clients.iter().find(|c| c.client_id == client_id))
            .cloned()
    };
    let recorded_ids: BTreeSet<uuid::Uuid> = scope_jobs
        .iter()
        .flat_map(|j| j.plans.iter().filter_map(|p| recorded_client(j, &p.client_id)))
        .flat_map(|c| c.mcp_local_servers.into_iter().map(|s| s.id))
        .collect();
    // The clients a picked selection is written to: one pick serves the run.
    let local_targets: Vec<String> = scope_jobs
        .iter()
        .flat_map(|j| &j.plans)
        .filter(|p| {
            profiles
                .get(p.client_id.as_str())
                .and_then(|profile| profile.templates.get(p.template_index))
                .is_some_and(|t| !t.local_mcp.is_none())
        })
        .map(|p| p.client_id.clone())
        .collect();
    let local_choice = resolve_local_mcp_servers(api, &args, workspace.id, &local_targets, &recorded_ids).await?;
    let mut local_slugs: BTreeMap<uuid::Uuid, String> =
        local_choice.offered.iter().map(|s| (s.id, s.slug.clone())).collect();
    let offered_local: Option<BTreeSet<uuid::Uuid>> =
        local_choice.offered_read.then(|| local_choice.offered.iter().map(|s| s.id).collect());
    for job in &mut scope_jobs {
        for i in 0..job.plans.len() {
            let recorded = recorded_client(job, &job.plans[i].client_id);
            let recorded_local = recorded.as_ref().map(|c| c.mcp_local_servers.as_slice()).unwrap_or(&[]);
            let recorded_gateway = recorded.as_ref().map(|c| c.mcp_server_ids.as_slice()).unwrap_or(&[]);
            let plan = &mut job.plans[i];
            let (gateway, gone) = mcp_choice.for_client(recorded_gateway);
            if gone > 0 {
                println!(
                    "{}: {gone} MCP server(s) it was provisioned with are no longer offered to this workspace — left out",
                    plan.client_id
                );
            }
            plan.mcp_server_ids = gateway;
            plan.mcp_local_server_ids = local_choice.for_client(&plan.client_id, recorded_local);
            // A local server goes only to a client whose template — the one
            // it ends up with — has a form for one. A client asked for one it
            // cannot be given is told so; one that HAD it has it withdrawn
            // below, which says why.
            let asked = plan.mcp_local_server_ids.len();
            let lines = keep_local_where_writable(std::slice::from_mut(plan), &local_slugs, |id| {
                profiles.get(id).map(|p| p.templates.as_slice())
            });
            let lost_form = plan.mcp_local_server_ids.len() < asked;
            if recorded_local.is_empty() {
                for line in lines {
                    eprintln!("{line}");
                }
            }
            let gone = local_withdrawals(recorded_local, &plan.mcp_local_server_ids, offered_local.as_ref(), lost_form);
            if !gone.is_empty() {
                job.withdrawing.push((plan.client_id.clone(), gone));
            }
            local_slugs.extend(recorded_local.iter().map(|s| (s.id, s.slug.clone())));
        }
    }

    // Run-level grouping over the plans this run WRITES (a project run's skipped
    // global-only clients are gone by now) validates an out-of-band key and
    // decides whether `--key-name` names the one key; each scope job re-groups
    // its own subset below.
    let all_groups: Vec<Group> = scope_jobs.iter().flat_map(|j| group_plans(&j.plans)).collect();

    for job in &scope_jobs {
        for plan in &job.plans {
            let templates = &profiles[plan.client_id.as_str()].templates;
            // stderr: `--print` output on stdout is a config a user redirects.
            if let Some(chosen) = templates.get(plan.template_index)
                && let Some(hint) = variant_hint(&plan.client_id, templates, chosen)
            {
                eprintln!("{hint}");
            }
        }
    }
    // The developer sees what will run on this machine before anything is written.
    let added: Vec<crate::api::McpLocalServer> = local_choice
        .offered
        .iter()
        .filter(|s| scope_jobs.iter().flat_map(|j| &j.plans).any(|p| p.mcp_local_server_ids.contains(&s.id)))
        .cloned()
        .collect();
    for line in local_server_notice_lines(&added, cfg!(windows)) {
        println!("{line}");
    }

    // ----- Key strategy -----
    // Precedence per group (one client each): out-of-band key
    // (`STREAMSCOPE_GATEWAY_KEY`, render-only) > CI per-run short-TTL mint > the
    // key this manifest records for the tool > the key the tool holds on this
    // device (`ToolKeys`, shared by every project) > a fresh mint named for the
    // tool.
    let external_key = external_gateway_key()?;
    if external_key.is_some() && distinct_key_scopes(&all_groups) > 1 {
        bail!(
            "STREAMSCOPE_GATEWAY_KEY can't serve mixed BYOK/gateway clients — \
             provision them in separate runs (one mode per run)"
        );
    }
    if let Some(ext) = external_key.as_ref().filter(|_| !all_groups.is_empty()) {
        // The supplied key's kind must match the (single) group's mode — an
        // sk- can't drive a BYOK group and a vk- can't drive a gateway group.
        let want_vk = all_groups.iter().any(|g| matches!(g.mode, Mode::Byok));
        if ext.starts_with("vk-") != want_vk {
            bail!(
                "STREAMSCOPE_GATEWAY_KEY is a {} key but the selected client(s) need a {} key",
                if ext.starts_with("vk-") { "BYOK (vk-)" } else { "gateway (sk-)" },
                if want_vk { "BYOK (vk-)" } else { "gateway (sk-)" },
            );
        }
        println!("Using the gateway key from STREAMSCOPE_GATEWAY_KEY (nothing is minted).");
    }
    let key_ttl = args
        .key_ttl
        .as_deref()
        .map(parse_ttl)
        .transpose()?
        .or_else(|| session.ci.then(|| chrono::Duration::hours(2)));
    let expires_at = key_ttl.map(|ttl| chrono::Utc::now() + ttl);
    // Liveness of the manifests' keys (for reuse) — fetched once, shared across
    // scope jobs (gateway keys are workspace-scoped, not manifest-scoped).
    // The device's per-tool keys: only a run that may reuse or record one reads
    // them. A CI or out-of-band-key run never touches the home directory for it
    // (its runner may have no writable HOME).
    let device_keys = external_key.is_none() && !session.ci;
    let mut tool_keys = if device_keys { ToolKeys::load_or_warn() } else { ToolKeys::default() };
    let any_prev_keys = tool_keys.hosts.get(&session.key).is_some_and(|l| !l.is_empty())
        || scope_jobs.iter().any(|j| {
            j.manifest
                .hosts
                .get(&session.key)
                .map(|w| !w.keys.is_empty())
                .unwrap_or(false)
        });
    let live_keys = if external_key.is_none() && !session.ci && any_prev_keys {
        Some(api.quickstart_keys(workspace.id).await?)
    } else {
        None
    };
    let is_live = |id: uuid::Uuid, fa: bool| {
        live_keys
            .as_ref()
            .is_some_and(|lk| lk.iter().any(|k| k.id == id && k.forward_auth == fa))
    };

    // ----- Per-scope-job bundle + render -----
    let run_stamp = crate::state::new_run_stamp("");
    let write_mode = WriteMode { dry_run: args.dry_run, print: args.print, verbose: args.verbose };
    let mut wrote_any = false;
    let mut failures: Vec<String> = Vec::new();
    // Written project configs (holding a key) that could not be git-ignored.
    let mut unignored: Vec<String> = Vec::new();
    // `--key-name` names THE key a run mints; a run minting several (one per
    // tool) uses it as their name prefix instead.
    let single_key_run = all_groups.len() == 1;

    for job in &mut scope_jobs {
        // Create the state dir (+ project `.gitignore`) before any write/backup.
        if !args.dry_run && !args.print {
            job.paths.ensure()?;
        }
        if job.is_project {
            println!(
                "Provisioning into this project — state tracked in {}",
                job.paths.base().display()
            );
        } else if run_is_project {
            // The run resolved to a project, but these clients have only a
            // global config — write them to the home directory and say so, so
            // a `--local`/project run doesn't look like it silently dropped them.
            println!(
                "Writing global-only tools to your home directory (no project-local config form)."
            );
        }
        // Withdrawals first, and recorded at once: a local server that left a
        // client's selection is taken out of that client's files — its own
        // entry, nothing else — whatever happens to the client afterwards.
        let others = job.manifest.files_of_other_hosts(&session.key);
        let mut withdrew = false;
        for (client_id, gone) in std::mem::take(&mut job.withdrawing) {
            let Some(client) = job
                .manifest
                .hosts
                .get_mut(&session.key)
                .and_then(|ws| ws.clients.iter_mut().find(|c| c.client_id == client_id))
            else {
                continue;
            };
            let preview = args.dry_run || args.print;
            match withdraw_local_servers(client, &gone, &others, &run_stamp, &job.paths, preview) {
                Ok(changed) => withdrew |= changed,
                Err(e) => {
                    eprintln!("{client_id}: {e:#}");
                    failures.push(client_id);
                }
            }
        }
        if withdrew {
            wrote_any = true;
            if let Err(e) = crate::state::backup_manifest_into_run(&job.paths, &run_stamp, &job.manifest_before) {
                crate::ui::warn("  ", format_args!("the manifest was not backed up with this run ({e:#}) — `restore` cannot reconcile it"));
            }
            job.manifest.save(&job.paths)?;
        }
        let prev_ws = job.manifest.hosts.get(&session.key).cloned().unwrap_or_default();
        let records = crate::state::FileRecords { ws: &prev_ws, others: &others };
        let groups = group_plans(&job.plans);
        let mut group_results: Vec<GroupResult> = Vec::new();
        // Gateway-proxy origins the rendered configs point at — the egress
        // allowlist `ssai run` permits (normally one, `proxy_public_url`).
        let mut proxy_origins: BTreeSet<String> = BTreeSet::new();
        // What the workspace offers, as the last bundle answered.
        let mut client_access: Option<crate::api::ClientAccess> = None;

        for group in &groups {
            let forward_auth = matches!(group.mode, Mode::Byok);
            let group_clients: Vec<&ClientPlan> = group.indices.iter().map(|&i| &job.plans[i]).collect();
            let group_sig = group.signature();
            // A client with nothing to render is left alone: no config is
            // asked for, nothing is written, and it is not a failure.
            let kind = group_clients.first().and_then(|p| {
                profiles.get(p.client_id.as_str()).and_then(|profile| profile.templates.get(p.template_index)).map(|t| t.kind)
            });
            if nothing_to_write(kind, group) {
                println!("{}", nothing_to_write_line(&group.client_id));
                continue;
            }

            let mut reused_plaintext: Option<String> = None;
            // Minted by this run: the only key recorded as the tool's device key
            // (a reused one may be a `--key-name` / `--key-ttl` key of its own).
            let mut minted = false;
            // `--key-name` / `--key-ttl` ask for a key of their own: the device's
            // shared one would silently ignore both.
            let device = if args.key_name.is_none() && args.key_ttl.is_none() {
                tool_keys
                    .find(&session.key, workspace.id, &group.client_id, group.mode.as_str(), group.provider_id)
                    .filter(|k| is_live(k.id, forward_auth))
                    .cloned()
            } else {
                None
            };
            let key_spec = if let Some(ext) = &external_key {
                Some(KeySpec::external(ext.starts_with("vk-")))
            } else if session.ci {
                let (name, prefix) = key_name_and_prefix(args.key_name.as_deref(), single_key_run, true, group);
                Some(KeySpec::mint(name, prefix, expires_at, forward_auth))
            } else {
                match choose_key(&prev_ws, group, |id| is_live(id, forward_auth), device) {
                    KeyChoice::Own(k) | KeyChoice::Device { key: k, .. } => {
                        let kind = if forward_auth { "BYOK" } else { "gateway" };
                        println!("Reusing {kind} key \"{}\" for {}.", k.name, group.client_id);
                        reused_plaintext = Some(k.plaintext.clone());
                        Some(KeySpec::reuse(k.id, forward_auth))
                    }
                    KeyChoice::Mint { .. } => {
                        minted = true;
                        let (name, prefix) =
                            key_name_and_prefix(args.key_name.as_deref(), single_key_run, false, group);
                        Some(KeySpec::mint(name, prefix, expires_at, forward_auth))
                    }
                }
            };

            let bundle = api
                .provision_bundle(&BundleRequest {
                    workspace_id: workspace.id,
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
            // One group's bundle is one gateway call, and a refusal is about
            // that group's client: it fails alone, its files untouched, and
            // the groups already written are recorded below.
            let bundle = match bundle {
                Ok(bundle) => bundle,
                Err(e) => {
                    eprintln!("{}: {:#}", group.client_id, disabled_by_admin(e, &group.client_id));
                    failures.push(group.client_id.clone());
                    continue;
                }
            };
            client_access = Some(bundle.client_access.clone());

            let plaintext = resolve_bundle_plaintext(
                &bundle,
                reused_plaintext,
                external_key.as_deref(),
                "delete the stale entry by re-running with --key-name to mint a fresh key",
            )?;

            // A key this run minted for the tool, for the next project that
            // provisions it — not a CI or out-of-band key (per run / not ours to
            // hand on), nor one minted for `--key-name` / `--key-ttl`, which
            // asked for a key of its own.
            if minted
                && device_keys
                && args.key_name.is_none()
                && args.key_ttl.is_none()
                && let (Some(k), Some(plain)) = (&bundle.key, &plaintext)
            {
                record_device_key(&mut tool_keys, &session.key, workspace.id, group, k, plain);
            }

            let key_id = bundle.key.as_ref().map(|k| k.id);
            let mut managed: Vec<ManagedClient> = Vec::new();
            for cb in &bundle.clients {
                if let Some(origin) = proxy_origin_of(cb) {
                    proxy_origins.insert(origin);
                }
                match provision_one(cb, plaintext.as_deref(), &write_mode, &run_stamp, &records, &job.paths, &mut unignored)
                {
                    Ok(Some(mut m)) => {
                        wrote_any = true;
                        m.mode = group.mode.as_str().to_string();
                        m.provider_id = group.provider_id;
                        m.key_id = key_id;
                        m.mcp_server_ids = group.mcp_server_ids.clone();
                        m.mcp_local_servers = managed_local(
                            &group.mcp_local_server_ids,
                            &local_slugs,
                            std::mem::take(&mut m.mcp_local_servers),
                        );
                        m.mcp_local_commands = local_commands_written(cb, job.is_project);
                        managed.push(m);
                    }
                    Ok(None) => {}
                    Err(e) => {
                        eprintln!("{}: {e:#}", cb.client_id);
                        failures.push(cb.client_id.clone());
                    }
                }
                print_mcp_warnings(cb, job.is_project);
            }

            group_results.push(GroupResult {
                key: bundle.key.clone(),
                plaintext,
                group_sig,
                etag: bundle.bundle_etag.clone(),
                managed,
            });
        }

        // ----- Manifest (this scope job) -----
        // Keys are recorded in EVERY mode: a `--dry-run` / `--print` bundle can
        // still have minted a real key (the server mints in the same call that
        // renders), and dropping its plaintext would strand it. File records only
        // track real writes. Etags stamp only when every client landed — a partial
        // failure keeps the next sync rewriting instead of no-opping.
        {
            let ws = job.manifest.hosts.entry(session.key.clone()).or_default();
            ws.workspace_id = Some(workspace.id);
            // Refresh the egress allowlist from this run's rendered base URLs. All
            // clients under one host#slug share one gateway, so this set is stable
            // (normally one origin); replacing is correct.
            if !proxy_origins.is_empty() {
                ws.proxy_origins = proxy_origins.into_iter().collect();
            }
            if let Some(access) = client_access.take() {
                ws.client_access = Some(crate::state::ClientAccessRecord::now(access));
            }
            ws.external_key_sha256 = None;
            let stamp_etag = !args.dry_run && !args.print && failures.is_empty();
            for gr in &group_results {
                record_group(
                    ws,
                    gr.key.as_ref(),
                    &gr.etag,
                    gr.plaintext.as_deref(),
                    external_key.as_deref(),
                    &gr.group_sig,
                    stamp_etag,
                    gr.managed.clone(),
                );
            }
            // Prune orphaned keys only after a fully-successful real run — a
            // dry-run/print/failed run records a (possibly freshly-minted) key whose
            // client wasn't written yet, and pruning it here would strand it.
            if !args.dry_run && !args.print && failures.is_empty() {
                note_unused_keys(&prune_unused_keys(ws));
                prune_unused_etags(ws);
            }
            // Best effort: the configs are written, and the manifest recording
            // them (with the keys they hold) must be saved even if its backup fails.
            if let Err(e) = crate::state::backup_manifest_into_run(&job.paths, &run_stamp, &job.manifest_before) {
                crate::ui::warn("  ", format_args!("the manifest was not backed up with this run ({e:#}) — `restore` cannot reconcile it"));
            }
            job.manifest.save(&job.paths)?;
        }

        // A tool whose other configs outrank what was just written says so
        // now, not when it silently runs on another provider.
        if !args.dry_run && !args.print {
            for m in group_results.iter().flat_map(|gr| &gr.managed) {
                for warning in crate::opencode_global::for_managed(m) {
                    crate::ui::warn_out("  ", &warning.text);
                }
            }
        }
    }

    if !failures.is_empty() {
        if wrote_any {
            bail!(PartialWrite(format!(
                "{}/{} clients failed: {}",
                failures.len(),
                scope_jobs.iter().map(|j| j.plans.len()).sum::<usize>(),
                failures.join(", ")
            )));
        }
        bail!("provisioning failed for: {}", failures.join(", "));
    }
    unignored_failure(&unignored)?;
    if !args.dry_run && !args.print {
        println!(
            "\n{} Done. Your tools now talk to the gateway — try one, then check usage in the portal.",
            crate::ui::check()
        );
    }
    Ok(())
}

/// Fail a run that wrote key-bearing project configs it could not git-ignore —
/// after everything is recorded, so the run is consistent, but never as a
/// success a script would read past.
pub(crate) fn unignored_failure(unignored: &[String]) -> Result<()> {
    if unignored.is_empty() {
        return Ok(());
    }
    bail!(PartialWrite(format!(
        "not git-ignored (they hold your gateway key — add them to .gitignore before committing): {}",
        unignored.join(", ")
    )))
}

/// The single substitution that turns the gateway-key sentinel
/// (`API_KEY_PLACEHOLDER`) into the minted plaintext. EVERY file the
/// provisioner writes — the template body and every quirk companion file —
/// goes through here, so there is exactly one place placeholders become
/// values. `UPSTREAM_API_KEY_PLACEHOLDER` and the MCP client-header sentinels
/// (`mcp_client_header_placeholder`) are deliberately left intact: the user
/// supplies those values themselves, so they survive into the written file by
/// design.
fn splice_key(content: &str, plaintext: Option<&str>) -> String {
    match plaintext {
        Some(p) => content.replace(API_KEY_PLACEHOLDER, p),
        None => content.to_string(),
    }
}

/// Guard against a write path that bypassed [`splice_key`]: the gateway-key
/// sentinel must never reach disk (a survivor writes the literal
/// `<paste-your-api-key-here>` into a tool's config — the bug the gemini
/// `.env` quirk shipped once). Only enforced when a key was available to
/// splice; with no key (a print-only curl/SDK snippet) the body legitimately
/// keeps the sentinel for the user to paste in.
fn ensure_key_spliced(content: &str, plaintext: Option<&str>, what: &str) -> Result<()> {
    if plaintext.is_some() && content.contains(API_KEY_PLACEHOLDER) {
        bail!(
            "internal: {what} still carries the gateway-key placeholder after \
             splice — a write path bypassed the substitution"
        );
    }
    Ok(())
}

/// How [`provision_one`] disposes of the rendered config.
pub(crate) struct WriteMode {
    pub dry_run: bool,
    pub print: bool,
    /// Print each client's full setup notes after writing. Off by default — the
    /// CLI already wrote the file, so the default output is just the path + the
    /// launch command; the verbose notes are portal copy-paste guidance.
    pub verbose: bool,
}

/// Render + write one client's config. Returns the manifest entry, or `None`
/// for print/dry-run modes. Shared by `provision` and `sync`.
pub(crate) fn provision_one(
    cb: &ClientBundle,
    plaintext: Option<&str>,
    mode: &WriteMode,
    run_stamp: &str,
    records: &crate::state::FileRecords,
    paths: &Paths,
    unignored: &mut Vec<String>,
) -> Result<Option<ManagedClient>> {
    let others = records.others;
    // Local render parity check — the bundle ships the raw template + typed
    // placeholders precisely so the CLI can re-render offline; a mismatch
    // against the server's render means CLI/server version skew.
    let local = render(&cb.template.body, cb.template.format, &cb.placeholders)
        .context("local render failed")?;
    if local != cb.rendered_body {
        bail!(
            "local render differs from the server's — your CLI is out of step with the gateway; update it"
        );
    }

    // A config written at its project-local path renders the template's
    // project-only content too (`{{#if project_scope}}`) — body and companion
    // files alike. The parity check above stays on the global form, the one the
    // server renders.
    let mut placeholders = std::borrow::Cow::Borrowed(&cb.placeholders);
    let local = if paths.project_root().is_some() && cb.template.project_filename.is_some() {
        placeholders.to_mut().insert(PROJECT_SCOPE.to_string(), Value::Bool(true));
        render(&cb.template.body, cb.template.format, &placeholders).context("local render failed")?
    } else {
        local
    };

    let spliced = splice_key(&local, plaintext);
    ensure_key_spliced(&spliced, plaintext, &cb.label)?;

    // No filename (curl / SDK env snippets) → print.
    let Some(display_name) = cb.template.filename.clone() else {
        print_config(&format!("--- {} ---", cb.label), &spliced, cb, &placeholders, plaintext, paths)?;
        return Ok(None);
    };
    if mode.print {
        // Name the file this scope would write, not the global display name.
        let target = match (paths.project_root(), cb.template.project_filename.as_deref()) {
            (Some(root), Some(rel)) => crate::state::join_relative(root, rel).to_string_lossy().into_owned(),
            _ => resolve_target_path(&cb.client_id, &display_name).unwrap_or(display_name),
        };
        print_config(&format!("--- {} ({target}) ---", cb.label), &spliced, cb, &placeholders, plaintext, paths)?;
        return Ok(None);
    }
    // Project scope writes into the project root using the template's
    // project-local path; a client without one has no project-local form and is
    // skipped (provision it globally instead).
    let filename: String = if let Some(root) = paths.project_root() {
        match cb.template.project_filename.as_deref() {
            Some(rel) => crate::state::join_relative(root, rel).to_string_lossy().into_owned(),
            None => {
                println!("  skipping {} — no project-local config; provision it globally instead", cb.label);
                return Ok(None);
            }
        }
    } else {
        // Global scope: a profile's filename is either a literal `~/`-path or a
        // human-readable display name the web quickstart shows (e.g. "VS Code
        // settings.json") that resolves through the per-client path table. An
        // unresolvable name prints instead of silently writing a relative path
        // into the current directory.
        let Some(resolved) = resolve_target_path(&cb.client_id, &display_name) else {
            let header = format!(
                "--- {} — couldn't locate \"{display_name}\" on this platform; merge this yourself ---",
                cb.label
            );
            print_config(&header, &spliced, cb, &placeholders, plaintext, paths)?;
            return Ok(None);
        };
        resolved
    };

    let prev_client = records.ws.clients.iter().find(|c| c.client_id == cb.client_id);
    let prev_files: &[ManagedFile] = prev_client.map(|c| c.files.as_slice()).unwrap_or(&[]);
    let prev_local: &[ManagedLocalMcp] = prev_client.map(|c| c.mcp_local_servers.as_slice()).unwrap_or(&[]);
    let written_local = local_commands_written(cb, paths.project_root().is_some());

    // Every file is merged before any is written, so a merge the writer
    // refuses (a user config that is not valid JSON, say) leaves all of the
    // tool's files as they were. A failed WRITE part-way still leaves the
    // earlier files written; this ordering does not cover I/O errors.
    let mut pending = vec![plan_managed(
        &filename,
        cb.template.format,
        &spliced,
        &cb.template.keyed_arrays,
        prev_files,
        others,
    )?];

    // A companion with no path is a step for the user to run, shown once the
    // files are written.
    let mut steps = Vec::new();
    for extra in spliced_companions(cb, &placeholders, plaintext, paths)? {
        match &extra.path {
            Some(path) => pending.push(plan_managed(
                path,
                extra.format,
                &extra.contents,
                &BTreeMap::new(),
                prev_files,
                others,
            )?),
            None => steps.push(extra),
        }
    }

    // Each file is merged against what is on disk now, so two entries naming
    // one file would each overwrite the other's merge.
    for (i, p) in pending.iter().enumerate() {
        if pending[..i].iter().any(|q| crate::state::same_file(&q.path, &p.path)) {
            bail!("{} writes {} twice — fix the client profile's companion paths", cb.label, p.filename);
        }
    }
    // A file git tracks would commit the key with it — in a project, or in a
    // home directory that is a git repository: a `.gitignore` line cannot
    // untrack it, so the client is refused before any of its files is written.
    if let Some(key) = plaintext.filter(|k| !k.is_empty())
        && let Some(p) = pending
            .iter()
            .find(|p| p.outcome.contents.contains(key) && crate::state::git_tracks(&p.path))
    {
        bail!(
            "{} is tracked by git, so your gateway key \
             would reach its next commit — keep the file out of git, or provision {} in the other \
             scope (`--global` or `--dir`)",
            p.filename,
            cb.label
        );
    }
    if mode.dry_run {
        for p in &pending {
            p.print_notes();
            println!("would write {} ({} managed entries)", p.filename, p.outcome.owned.len());
        }
        print_steps(&steps);
        return Ok(None);
    }
    let local_entries =
        local_entries_written(cb, &placeholders, plaintext, paths, &pending, prev_local, &written_local)?;
    let mut files: Vec<ManagedFile> = Vec::new();
    for p in pending {
        files.push(p.write(run_stamp, paths.base())?);
    }
    // A provisioned project config can hold the gateway key, so it is
    // git-ignored as it is written — by `provision` and `sync` alike.
    // Best effort: the files are written and must be recorded either way.
    if let Some(root) = paths.project_root() {
        match ensure_gitignored(root, &project_relative(root, files.iter().map(|f| f.path.as_str()))) {
            Ok(added) if !added.is_empty() => {
                println!("Added to .gitignore (these hold your key): {}", added.join(", "));
            }
            Ok(_) => {}
            // Recorded either way; the run then fails once its manifest is
            // saved, so a script never reads success over an unignored key.
            Err(e) => {
                crate::ui::error("  ", format_args!("could not add {}'s config to .gitignore ({e:#})", cb.label));
                unignored.extend(files.iter().map(|f| f.path.clone()));
            }
        }
    }
    // A file this client managed that the template no longer writes (its path
    // moved, e.g. a project config into a directory of its own) must not keep
    // our entries — the key above all — untracked.
    for prev in prev_files.iter().filter(|p| {
        let old = expand_tilde(&p.path);
        !files.iter().any(|f| {
            f.path == p.path
                || matches!((&old, expand_tilde(&f.path)), (Ok(o), Ok(n)) if crate::state::same_file(o, &n))
        })
    }) {
        // Best effort: a file the template no longer writes must not fail the
        // client whose new files are already written.
        // Its `.gitignore` line stays: what is left may still hold a secret
        // (the user's own provider key, a BYOK key they pasted).
        if let Err(e) = retire_file(prev, others, run_stamp, paths.base()) {
            crate::ui::warn("  ", format_args!("{} is no longer used, but our entries could not be removed: {e:#}", prev.path));
        }
    }
    // Blank line separates each client's block so a multi-client run is scannable.
    println!();
    let shown: Vec<String> = files.iter().map(|f| crate::ui::accent(&f.path).to_string()).collect();
    println!("{} {} provisioned → {}", crate::ui::check(), console::style(&cb.label).bold(), shown.join(", "));
    // The one thing the user needs next: how to launch the tool. Show the direct
    // launch, then the recommended sandboxed launch — `ssai run` confines
    // the tool's egress to the gateway (audited, no vendor-direct calls) — on
    // the platforms that have the sandbox.
    match &cb.launch_command {
        Some(cmd) => {
            println!("  {}       {}", crate::ui::muted("Run:"), crate::ui::accent(cmd));
            if cfg!(any(target_os = "linux", target_os = "macos")) {
                println!(
                    "  {} {}",
                    crate::ui::muted("Sandboxed:"),
                    crate::ui::accent(format!("ssai run {}", cb.client_id))
                );
            }
        }
        None => println!("  Restart {} to pick up the gateway.", cb.label),
    }
    print_steps(&steps);
    // Surface the resolved default model for gateway LLM clients — the route the
    // client uses with no explicit `--model`. Skipped for BYOK (the model is a
    // fill-in sentinel, not a real route the client will call).
    let forward_auth = matches!(cb.placeholders.get("forward_auth"), Some(Value::Bool(true)));
    if cb.template.kind.needs_llm()
        && !forward_auth
        && let Some(Value::String(model)) = cb.placeholders.get("model_slot_default")
    {
        println!("  {} {model}", crate::ui::muted("default model:"));
        // A slot no route fills names the default model: only a different one
        // is worth a line, and only for a template that uses the slot.
        for (slot, label) in [("model_slot_fast", "fast model:"), ("model_slot_plan", "plan model:")] {
            if let Some(Value::String(other)) = cb.placeholders.get(slot)
                && other != model
                && cb.template.body.contains(slot)
            {
                println!("  {} {other}", crate::ui::muted(label));
            }
        }
    }
    // Full provider/setup notes are portal copy-paste guidance — verbose only;
    // the CLI already wrote the file, so they're not part of the next step.
    if mode.verbose
        && let Some(instr) = &cb.rendered_instructions
    {
        println!("  {}", splice_key(instr, plaintext).replace('\n', "\n  "));
    }
    Ok(Some(ManagedClient {
        client_id: cb.client_id.clone(),
        template_index: cb.template_index,
        // The orchestrator stamps the real mode/provider/key/MCP set after this
        // returns (it owns the per-group context); these are placeholders.
        mode: "gateway".to_string(),
        provider_id: None,
        key_id: None,
        mcp_server_ids: Vec::new(),
        // Each written local server's entries, by slug; the orchestrator
        // stamps the ids ([`managed_local`]).
        mcp_local_servers: local_entries,
        mcp_local_commands: BTreeMap::new(),
        files,
        last_provisioned: chrono::Utc::now(),
        launch_command: cb.launch_command.clone(),
    }))
}

/// A slug no local MCP server is stored under (a slug holds no uppercase
/// letter), standing in for one server while its entry is located.
const ENTRY_PROBE_SLUG: &str = "SSAI-ENTRY-PROBE";

/// `placeholders` with the local MCP server `slug` renamed to
/// [`ENTRY_PROBE_SLUG`]: the same render, less that server's entry, with
/// every container the entry sits in still held by another one.
fn with_probe_in_place_of(placeholders: &BTreeMap<String, Value>, slug: &str) -> Option<BTreeMap<String, Value>> {
    let mut base = placeholders.clone();
    let Some(Value::List(servers)) = base.get_mut("mcp_servers") else { return None };
    let item = servers.iter_mut().find(|item| {
        matches!(item.get("local"), Some(Value::Bool(true)))
            && matches!(item.get("slug"), Some(Value::String(s)) if s == slug)
    })?;
    for field in ["slug", "name"] {
        item.insert(field.to_string(), Value::String(ENTRY_PROBE_SLUG.to_string()));
    }
    Some(base)
}

/// Where each local MCP server of `written` stands in the files about to be
/// written (`pending`): for each server, the entries its render holds that
/// the same render with another server in its place does not
/// ([`writer::entry_roots`]). Located again on every write, so a record always
/// names the entry the ownership records of the same write describe.
///
/// `created` is decided once, when a server's entry first appears at a root:
/// from the file as it stands before this write. A later write keeps what
/// `prev_local` recorded for the same file and root.
fn local_entries_written(
    cb: &ClientBundle,
    placeholders: &BTreeMap<String, Value>,
    plaintext: Option<&str>,
    paths: &Paths,
    pending: &[PendingWrite],
    prev_local: &[ManagedLocalMcp],
    written: &BTreeMap<String, String>,
) -> Result<Vec<ManagedLocalMcp>> {
    let mut out = Vec::new();
    for slug in written.keys() {
        let mut entries = Vec::new();
        if let Some(base) = with_probe_in_place_of(placeholders, slug) {
            let body = render(&cb.template.body, cb.template.format, &base).context("local render failed")?;
            let mut base_files: Vec<(String, String)> = Vec::new();
            if let Some(first) = pending.first() {
                base_files.push((first.filename.clone(), splice_key(&body, plaintext)));
            }
            for extra in spliced_companions(cb, &base, plaintext, paths)? {
                if let Some(path) = extra.path {
                    base_files.push((path, extra.contents));
                }
            }
            let recorded = prev_local.iter().find(|s| s.slug == *slug);
            for p in pending {
                let Some((_, base_contents)) = base_files.iter().find(|(name, _)| *name == p.filename) else {
                    continue;
                };
                if !matches!(p.format, TemplateFormat::Json | TemplateFormat::Toml | TemplateFormat::Yaml) {
                    continue;
                }
                let base_owned = writer::merge(p.format, None, base_contents, &[], &p.keyed_arrays)
                    .with_context(|| format!("locate the entry of local MCP server '{slug}' in {}", p.filename))?
                    .owned;
                for root in writer::entry_roots(p.format, &p.outcome.owned, &base_owned) {
                    let created = match recorded
                        .and_then(|s| s.entries.iter().find(|e| p.is_file(&e.file) && e.root == root))
                    {
                        Some(e) => e.created,
                        None => !writer::holds(p.format, p.existing.as_deref(), &root)?,
                    };
                    entries.push(LocalMcpEntry { file: p.filename.clone(), root, created });
                }
            }
        }
        out.push(ManagedLocalMcp { id: uuid::Uuid::nil(), slug: slug.clone(), entries });
    }
    Ok(out)
}

/// One stderr line per MCP server the gateway left out of a client's config,
/// in the gateway's own words.
///
/// `project_write`: this client's config is written at its project-local
/// path. The gateway renders the config outside a project, so it reports a
/// local server a template writes only in a project's own file as left out
/// every time; a project write carries it, and that line is dropped.
pub(crate) fn mcp_warning_lines(
    client_id: &str,
    warnings: &[crate::api::McpServerWarning],
    project_write: bool,
) -> Vec<String> {
    warnings
        .iter()
        .filter(|w| !(project_write && w.reason == crate::api::LOCAL_SERVER_PROJECT_ONLY))
        .map(|w| format!("warning: {client_id}: {}", w.message))
        .collect()
}

/// Whether `cb`'s config lands at its project-local path under a job of this
/// scope — the condition [`provision_one`] renders the project form on.
fn is_project_write(cb: &ClientBundle, in_project: bool) -> bool {
    in_project && cb.template.project_filename.is_some()
}

/// Print a bundle client's [`mcp_warning_lines`] on stderr.
pub(crate) fn print_mcp_warnings(cb: &ClientBundle, in_project: bool) {
    for line in mcp_warning_lines(&cb.client_id, &cb.warnings, is_project_write(cb, in_project)) {
        eprintln!("{line}");
    }
}

/// The local MCP servers `cb`'s written config carries, slug → whole launch
/// line, read from the bundle's own `mcp_servers` items (the ones marked
/// `local`, each carrying the gateway's `command_line`): what the template was
/// rendered with is what is recorded. Empty when the template writes a local
/// server only in a project's own file and this write is not one.
pub(crate) fn local_commands_written(cb: &ClientBundle, in_project: bool) -> BTreeMap<String, String> {
    use streamscope_client_templates::LocalMcpForm;
    let written = match cb.template.local_mcp {
        LocalMcpForm::None => false,
        LocalMcpForm::Config => true,
        LocalMcpForm::Project => is_project_write(cb, in_project),
    };
    let mut out = BTreeMap::new();
    let Some(Value::List(servers)) = cb.placeholders.get("mcp_servers") else {
        return out;
    };
    if !written {
        return out;
    }
    for item in servers {
        if !matches!(item.get("local"), Some(Value::Bool(true))) {
            continue;
        }
        if let (Some(Value::String(slug)), Some(Value::String(line))) = (item.get("slug"), item.get("command_line")) {
            out.insert(slug.clone(), line.clone());
        }
    }
    out
}

/// One line per local MCP server whose launch is new or differs from the one
/// last written (`before`) — its command, an argument, or an environment
/// value the administrator set: what `sync` prints as it applies it.
pub(crate) fn changed_local_command_lines(
    before: Option<&BTreeMap<String, String>>,
    now: &BTreeMap<String, String>,
) -> Vec<String> {
    now.iter()
        .filter(|(slug, line)| before.and_then(|b| b.get(*slug)) != Some(*line))
        .map(|(slug, line)| format!("local MCP server '{slug}' now runs: {line}"))
        .collect()
}

/// A selection as the manifest records it: each id with its slug (`slugs`: the
/// servers the workspace is handed) and the entries [`provision_one`] wrote it
/// as (`written`, by slug — none for a server the config does not carry). An
/// id with no slug there is not recorded.
pub(crate) fn managed_local(
    ids: &[uuid::Uuid],
    slugs: &BTreeMap<uuid::Uuid, String>,
    written: Vec<ManagedLocalMcp>,
) -> Vec<ManagedLocalMcp> {
    ids.iter()
        .filter_map(|id| {
            slugs.get(id).map(|slug| ManagedLocalMcp {
                id: *id,
                slug: slug.clone(),
                entries: written.iter().find(|w| w.slug == *slug).map(|w| w.entries.clone()).unwrap_or_default(),
            })
        })
        .collect()
}

/// For the clients a `sync` covers (`selected`): the local MCP servers of each
/// one's recorded selection that the workspace is still handed (`offered`),
/// sorted. `offered` is `None` when what the workspace hands out could not be
/// read: every recorded server is then kept — an unknown is never a
/// withdrawal. A client outside `selected` keeps its selection as recorded:
/// its config is not rewritten by this run.
pub(crate) fn split_offered_local(
    clients: &[ManagedClient],
    selected: &HashSet<String>,
    offered: Option<&BTreeMap<uuid::Uuid, String>>,
) -> BTreeMap<String, Vec<uuid::Uuid>> {
    clients
        .iter()
        .map(|c| {
            let mut ids: Vec<uuid::Uuid> = c
                .mcp_local_servers
                .iter()
                .filter(|s| !selected.contains(&c.client_id) || offered.is_none_or(|o| o.contains_key(&s.id)))
                .map(|s| s.id)
                .collect();
            ids.sort();
            ids.dedup();
            (c.client_id.clone(), ids)
        })
        .collect()
}

/// Whether there is nothing to write for a group's client: its template is
/// MCP-only (`kind`; `None` when the template could not be read) and its
/// selection, gateway and local, is empty. Such a client is LEFT ALONE by
/// `provision` and `sync` alike — no config is asked for, nothing of its is
/// removed, it stays recorded, and it is not a failure. Any other plan is
/// rendered, and a refusal of it is that client's failure.
pub(crate) fn nothing_to_write(kind: Option<TemplateKind>, group: &Group) -> bool {
    matches!(kind, Some(TemplateKind::Mcp))
        && group.mcp_server_ids.is_empty()
        && group.mcp_local_server_ids.is_empty()
}

/// What a run says of a client it leaves alone ([`nothing_to_write`]).
pub(crate) fn nothing_to_write_line(client_id: &str) -> String {
    format!("{client_id}: no MCP server is selected for it — nothing to write")
}

/// Why a local MCP server leaves a client's selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WithdrawReason {
    /// The workspace is no longer handed it: revoked, disabled or deleted.
    NotOffered,
    /// The client's setup no longer has a form for a local server.
    NoForm,
    /// This run took it out: a flag, or unticked in the prompt.
    Deselected,
}

impl WithdrawReason {
    fn text(self) -> &'static str {
        match self {
            WithdrawReason::NotOffered => "it is no longer offered to this workspace",
            WithdrawReason::NoForm => "this client setup no longer writes local servers",
            WithdrawReason::Deselected => "it is no longer selected for this client",
        }
    }
}

/// The local MCP servers a client was recorded with (`recorded`) that its
/// selection no longer holds (`keeping`), each with why: no longer offered
/// (`offered`: what the workspace hands out, `None` when that is not known —
/// then nothing is called "no longer offered"), else lost with the template's
/// form (`lost_form`), else taken out by this run.
pub(crate) fn local_withdrawals(
    recorded: &[ManagedLocalMcp],
    keeping: &[uuid::Uuid],
    offered: Option<&BTreeSet<uuid::Uuid>>,
    lost_form: bool,
) -> Vec<(uuid::Uuid, WithdrawReason)> {
    recorded
        .iter()
        .filter(|s| !keeping.contains(&s.id))
        .map(|s| {
            let reason = if offered.is_some_and(|o| !o.contains(&s.id)) {
                WithdrawReason::NotOffered
            } else if lost_form {
                WithdrawReason::NoForm
            } else {
                WithdrawReason::Deselected
            };
            (s.id, reason)
        })
        .collect()
}

/// Whether `path` — a recorded file, expanded — is one this job may rewrite:
/// under the project root for a project job, a home-directory (`~/`) path
/// for the global one. A manifest copied with a project names the original
/// project's files, and a path recorded relative to an earlier working
/// directory names no file reliably: neither is this run's to touch.
fn in_job_scope(recorded: &str, path: &Path, project_root: Option<&Path>) -> bool {
    if !path.is_absolute() {
        return false;
    }
    match project_root {
        // Compared by real path, so a root recorded through a symlink still
        // matches the canonical one.
        Some(root) => dunce::canonicalize(path).unwrap_or_else(|_| path.to_path_buf()).starts_with(root),
        None => recorded.starts_with("~/"),
    }
}

/// The format a managed file was recorded with, and that format's empty
/// document — `None` for one the structured writer does not merge.
fn recorded_format(format: &str) -> Option<(TemplateFormat, &'static str)> {
    match format {
        "json" => Some((TemplateFormat::Json, "{}")),
        "yaml" => Some((TemplateFormat::Yaml, "{}")),
        "toml" => Some((TemplateFormat::Toml, "")),
        "shell" => Some((TemplateFormat::Shell, "")),
        _ => None,
    }
}

/// WITHDRAW local MCP servers from one client: the one operation that takes
/// a local server out of a client's files, shared by `provision` and `sync`.
/// It needs no rendered config — it works on each file as it stands — and
/// touches exactly the withdrawn servers' recorded entries:
///
/// - an entry we created (`created`) is removed whole, with whatever the
///   developer pasted into it;
/// - an entry the file already had loses only the leaves we wrote that are
///   unchanged; the rest stays and is named;
/// - nothing else in the file, and no other file, is read as ours to change:
///   the provider, the key, the model, gateway servers and the developer's
///   own entries are not part of the merge at all;
/// - only a file of this job's scope ([`in_job_scope`]) is rewritten, matched
///   by [`is_recorded_file`]; any other is named and left.
///
/// The client's record then drops those servers, their entries and the
/// ownership records under them — the client itself stays. One line per
/// server and file says what was done and why. `preview`: say it, change
/// nothing. Returns whether the record changed, so the caller saves the
/// manifest at once and files and records never disagree.
pub(crate) fn withdraw_local_servers(
    client: &mut ManagedClient,
    gone: &[(uuid::Uuid, WithdrawReason)],
    others: &[ManagedFile],
    run_stamp: &str,
    paths: &Paths,
    preview: bool,
) -> Result<bool> {
    let withdrawn: Vec<(ManagedLocalMcp, WithdrawReason)> = client
        .mcp_local_servers
        .iter()
        .filter_map(|s| gone.iter().find(|(id, _)| *id == s.id).map(|(_, why)| (s.clone(), *why)))
        .collect();
    if withdrawn.is_empty() {
        return Ok(false);
    }
    let would = if preview { "would be " } else { "" };
    let mut said: BTreeSet<String> = BTreeSet::new();
    for file in &mut client.files {
        let Ok(path) = expand_tilde(&file.path) else { continue };
        let entries: Vec<(&ManagedLocalMcp, &LocalMcpEntry, WithdrawReason)> = withdrawn
            .iter()
            .flat_map(|(server, why)| {
                server
                    .entries
                    .iter()
                    .filter(|e| is_recorded_file(&e.file, &file.path, &path))
                    .map(move |e| (server, e, *why))
            })
            .collect();
        if entries.is_empty() {
            continue;
        }
        said.extend(entries.iter().map(|(server, _, _)| server.slug.clone()));
        let Some((format, empty)) = recorded_format(&file.format).filter(|_| in_job_scope(&file.path, &path, paths.project_root()))
        else {
            for (server, _, why) in &entries {
                crate::ui::note(
                    "  ",
                    format_args!(
                        "{} is not this run's to rewrite — take local MCP server '{}' out of it yourself ({})",
                        file.path,
                        server.slug,
                        why.text()
                    ),
                );
            }
            continue;
        };
        let existing = match std::fs::read_to_string(&path) {
            Ok(existing) => existing,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
        };
        let roots: Vec<crate::state::EntryRoot> = entries.iter().map(|(_, e, _)| e.root.clone()).collect();
        let created: Vec<crate::state::EntryRoot> =
            entries.iter().filter(|(_, e, _)| e.created).map(|(_, e, _)| e.root.clone()).collect();
        let (inside, outside) = writer::records_in(format, &file.owned, &roots);
        let inside = crate::state::owned_alone(&inside, &path, others);
        // An empty render over the records of these entries alone: what we
        // created goes whole, what we only wrote into loses our unchanged
        // leaves, and nothing outside them is in the merge.
        let outcome = writer::merge_withdrawing(format, Some(&existing), empty, &inside, &BTreeMap::new(), &created)
            .with_context(|| format!("take a local MCP server out of {}", path.display()))?;
        let mut removed = outcome.withdrawn.iter();
        for (server, entry, why) in &entries {
            let at = match &entry.root.entry {
                Some(e) => format!("{}[{}]", entry.root.path, e.id),
                None => entry.root.path.clone(),
            };
            if !entry.created {
                println!(
                    "  {} — local MCP server '{}' {would}taken out of `{at}`, which this file already had: \
                     only what was written for it and you did not change is removed ({})",
                    file.path,
                    server.slug,
                    why.text()
                );
            } else if removed.next() == Some(&true) {
                println!(
                    "  {} — local MCP server '{}' {would}removed: its whole entry, with anything you pasted into it ({})",
                    file.path,
                    server.slug,
                    why.text()
                );
            }
        }
        for kept in &outcome.kept_edited {
            println!("  {} — you edited `{kept}` after we wrote it; keeping your value", file.path);
        }
        if preview {
            continue;
        }
        if outcome.contents != existing {
            file.file_hash = writer::write_atomic(&path, &outcome.contents, Some((paths.base(), run_stamp)))?;
        }
        file.owned = outside;
    }
    // A server no file of this client carried still leaves its selection.
    for (server, why) in withdrawn.iter().filter(|(server, _)| !said.contains(&server.slug)) {
        println!("  {}: local MCP server '{}' {would}taken out of its selection ({})", client.client_id, server.slug, why.text());
    }
    if preview {
        return Ok(false);
    }
    client.mcp_local_servers.retain(|s| !withdrawn.iter().any(|(gone, _)| gone.id == s.id));
    for (server, _) in &withdrawn {
        client.mcp_local_commands.remove(&server.slug);
    }
    Ok(true)
}

/// Leave a plan its local MCP servers only where its template has a form for
/// one, and say so for every other: one line per client naming the servers it
/// is provisioned without. Run on the plans as they will be rendered.
pub(crate) fn keep_local_where_writable<'a>(
    plans: &mut [ClientPlan],
    slugs: &BTreeMap<uuid::Uuid, String>,
    templates_of: impl Fn(&str) -> Option<&'a [ClientProfileTemplate]>,
) -> Vec<String> {
    let mut lines = Vec::new();
    for plan in plans.iter_mut() {
        if plan.mcp_local_server_ids.is_empty() {
            continue;
        }
        let template = templates_of(&plan.client_id).and_then(|t| t.get(plan.template_index));
        if template.is_some_and(|t| !t.local_mcp.is_none()) {
            continue;
        }
        let names: Vec<String> = plan
            .mcp_local_server_ids
            .iter()
            .filter_map(|id| slugs.get(id))
            .map(|slug| format!("local MCP server '{slug}'"))
            .collect();
        plan.mcp_local_server_ids.clear();
        let setup = template.map(|t| t.title.as_str()).unwrap_or("its setup");
        lines.push(format!(
            "warning: {}: {} not added — {setup} has no form for a server that runs on this machine",
            plan.client_id,
            names.join(", ")
        ));
    }
    lines
}

/// What `provision` prints for the local MCP servers a run adds: each one's
/// whole launch, the variables the developer must fill, and what a sandboxed
/// run (or Windows, `windows`) changes for that kind of command.
pub(crate) fn local_server_notice_lines(servers: &[crate::api::McpLocalServer], windows: bool) -> Vec<String> {
    let mut lines = Vec::new();
    for s in servers {
        lines.push(format!("local MCP server '{}' runs: {}", s.slug, s.command_line));
        let to_fill: Vec<&str> =
            s.launch.env.iter().filter(|e| e.value.is_none()).map(|e| e.name.as_str()).collect();
        if !to_fill.is_empty() {
            lines.push(format!(
                "  '{}' reads {} from you: replace the <paste-your-…-here> placeholder in the written config with your value",
                s.slug,
                to_fill.join(", ")
            ));
        }
        for note in local_command_notes(&s.launch.command, windows) {
            lines.push(format!("  '{}': {note}", s.slug));
        }
    }
    lines
}

/// What a developer should know about a local MCP server started by
/// `command`, by the kind of command it is — each note only where it is true:
/// - a package runner (`npx`, `uvx`): it must be installed; under the native
///   sandbox its download needs the registry's destination list; the
///   container image must hold it; on Windows a client may need it wrapped;
/// - a container engine: no sandbox tier confines what the engine starts;
/// - a path: it does not exist inside the container sandbox;
/// - any other program: it must be installed, and in the image.
pub(crate) fn local_command_notes(command: &str, windows: bool) -> Vec<&'static str> {
    let program = command.rsplit(['/', '\\']).next().unwrap_or(command);
    let program = program.strip_suffix(".exe").unwrap_or(program);
    if matches!(program, "docker" | "podman" | "nerdctl") {
        return vec![
            "it is started through a container engine, so `ssai run`'s sandbox does not confine it — the engine runs it, not the client",
        ];
    }
    if command.contains(['/', '\\']) {
        return vec![
            "under the container sandbox a path on this machine does not exist — it runs only where the image holds it",
        ];
    }
    if matches!(program, "npx" | "uvx") {
        let mut notes = vec![
            "its runner must be installed on this machine (npx comes with Node.js, uvx with uv)",
            "under `ssai run --sandbox native` it is confined with its client, and fetching its package needs the npm / PyPI destination list your administrator attaches",
            "under the container sandbox its runner must exist in the image (uvx is not there by default)",
        ];
        if windows {
            notes.push("on Windows a client may need the runner wrapped: set the command to `cmd` with `/c` before it (cmd /c npx …) in the written config");
        }
        return notes;
    }
    vec!["the program must be installed on this machine, and exist in the image under the container sandbox"]
}

/// A bundle refused because the administrator disabled `client`, said so;
/// any other error as it came.
pub(crate) fn disabled_by_admin(e: anyhow::Error, client: &str) -> anyhow::Error {
    if crate::api::error_code(&e) == Some(crate::api::CLIENT_DISABLED) {
        anyhow::anyhow!("{client} is disabled by your administrator — it is not offered to this workspace")
    } else {
        e
    }
}

/// The gateway-proxy origin (`scheme://host[:port]`) a client's config points
/// at, parsed from its rendered `base_url` placeholder — the egress allowlist
/// `ssai run` permits. `None` for a client without a `base_url` (MCP-only
/// / curl) or an unparsable / non-tuple one.
pub(crate) fn proxy_origin_of(cb: &ClientBundle) -> Option<String> {
    let Some(Value::String(base_url)) = cb.placeholders.get("base_url") else {
        return None;
    };
    let url = url::Url::parse(base_url).ok()?;
    match url.origin() {
        o @ url::Origin::Tuple(..) => Some(o.ascii_serialization()),
        url::Origin::Opaque(_) => None,
    }
}

/// One file's merge, computed and not yet written.
struct PendingWrite {
    filename: String,
    path: PathBuf,
    format: TemplateFormat,
    keyed_arrays: BTreeMap<String, String>,
    /// The file as it stood before this write (None = absent).
    existing: Option<String>,
    outcome: writer::MergeOutcome,
    notes: Vec<String>,
}

/// Whether `recorded` — a file as a manifest names it — is the file at
/// `path`, written this run as `filename`: however its path was spelled when
/// recorded (a relative or symlinked project root names the same file).
fn is_recorded_file(recorded: &str, filename: &str, path: &Path) -> bool {
    recorded == filename || expand_tilde(recorded).is_ok_and(|p| crate::state::same_file(&p, path))
}

impl PendingWrite {
    fn is_file(&self, recorded: &str) -> bool {
        is_recorded_file(recorded, &self.filename, &self.path)
    }

    fn print_notes(&self) {
        for note in &self.notes {
            crate::ui::note("  ", note);
        }
    }

    fn write(self, run_stamp: &str, backup_base: &Path) -> Result<ManagedFile> {
        let file_hash = writer::write_atomic(&self.path, &self.outcome.contents, Some((backup_base, run_stamp)))?;
        self.print_notes();
        Ok(ManagedFile {
            path: self.filename,
            format: format!("{:?}", self.format).to_lowercase(),
            owned: self.outcome.owned,
            file_hash,
        })
    }
}

fn plan_managed(
    filename: &str,
    format: TemplateFormat,
    contents: &str,
    keyed_arrays: &BTreeMap<String, String>,
    prev_files: &[ManagedFile],
    others: &[ManagedFile],
) -> Result<PendingWrite> {
    let path: PathBuf = expand_tilde(filename)?;
    let existing = match std::fs::read_to_string(&path) {
        Ok(s) => Some(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };
    // The record of this file, however its path was spelled when recorded (a
    // relative or symlinked project root names the same file).
    let prev_owned = prev_files
        .iter()
        .find(|f| is_recorded_file(&f.path, filename, &path))
        .map(|f| crate::state::owned_alone(&f.owned, &path, others))
        .unwrap_or_default();

    let outcome = writer::merge(format, existing.as_deref(), contents, &prev_owned, keyed_arrays)
        .with_context(|| format!("merge into {}", path.display()))?;
    // The YAML merge is value-level — make the one thing it can't preserve
    // visible at the point of impact instead of letting the user discover it
    // in a diff. Held until the file is written (or a dry run reports it): a
    // later file of the same tool can still refuse the whole write.
    let mut notes = Vec::new();
    if format == TemplateFormat::Yaml && existing.is_some() {
        notes.push(format!("{filename} — your settings are kept, but YAML comments are not preserved"));
    }
    for kept in &outcome.kept_edited {
        notes.push(format!("{filename} — you edited `{kept}` after we wrote it; keeping your value"));
    }

    Ok(PendingWrite {
        filename: filename.to_string(),
        path,
        format,
        keyed_arrays: keyed_arrays.clone(),
        existing,
        outcome,
        notes,
    })
}

/// `paths` relative to `root`, for those under it.
fn project_relative<'a>(root: &Path, paths: impl Iterator<Item = &'a str>) -> Vec<String> {
    // `/`-separated on every platform: git reads a `\` in a pattern as an
    // escape, so a Windows spelling would match nothing and leave a key file
    // unignored.
    paths
        .filter_map(|p| Path::new(p).strip_prefix(root).ok().map(slash_separated))
        .collect()
}

/// A relative path spelled with `/` between its components.
fn slash_separated(rel: &Path) -> String {
    rel.components().map(|c| c.as_os_str().to_string_lossy()).collect::<Vec<_>>().join("/")
}

/// Take every entry we own out of `prev` (the merge of an empty render with
/// last time's ownership removes exactly those — a keyed-array entry is found
/// by the identity its record carries, so no template's keyed arrays are
/// needed), backing the file up first; delete it when nothing of the user's is
/// left. A value or an entry of ours the user edited stays, and is named. A
/// file already gone is fine. Used for one thing: a file a client's template
/// no longer writes.
fn retire_file(prev: &ManagedFile, others: &[ManagedFile], run_stamp: &str, backup_base: &Path) -> Result<()> {
    let path = expand_tilde(&prev.path)?;
    // A relative path names no file reliably (the caller notes it and never
    // gets here); resolving one against the current directory could rewrite
    // or delete an unrelated file.
    if !path.is_absolute() {
        return Ok(());
    }
    let Ok(existing) = std::fs::read_to_string(&path) else { return Ok(()) };
    let Some((format, empty)) = recorded_format(&prev.format) else { return Ok(()) };
    let owned = crate::state::owned_alone(&prev.owned, &path, others);
    let outcome = writer::merge(format, Some(&existing), empty, &owned, &BTreeMap::new())
        .with_context(|| format!("remove our entries from {}", path.display()))?;
    // Whitespace aside: a file edited in place keeps its own layout, so an
    // empty object can span lines. A comment left in it is the user's, and
    // keeps the file.
    for kept in &outcome.kept_edited {
        println!("  {} — you edited `{kept}` after we wrote it; keeping your value", prev.path);
    }
    let left: String = outcome.contents.chars().filter(|c| !c.is_whitespace()).collect();
    if left.is_empty() || left == "{}" {
        crate::state::backup_file(backup_base, run_stamp, &path)?;
        std::fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;
        println!("  {} is no longer used — removed (backed up)", prev.path);
    } else {
        writer::write_atomic(&path, &outcome.contents, Some((backup_base, run_stamp)))?;
        println!("  {} is no longer used — our entries removed, yours kept", prev.path);
    }
    Ok(())
}

/// The tool's companion files with the key spliced in, at the paths a write
/// would use: beside the project config when this client is written into a
/// project, in `$HOME` otherwise. The one place a companion's sentinel becomes
/// a value — writing and printing both read it. Gated on the template kind
/// inside [`quirk_files`]: an MCP-only template never yields an LLM-credential
/// companion.
fn spliced_companions(
    cb: &ClientBundle,
    placeholders: &BTreeMap<String, Value>,
    plaintext: Option<&str>,
    paths: &Paths,
) -> Result<Vec<QuirkFile>> {
    let root = paths.project_root().filter(|_| cb.template.project_filename.is_some());
    quirk_files(&cb.template, placeholders, plaintext, root)?
        .into_iter()
        .map(|mut extra| {
            extra.contents = splice_key(&extra.contents, plaintext);
            ensure_key_spliced(&extra.contents, plaintext, extra.path.as_deref().unwrap_or(&extra.title))?;
            Ok(extra)
        })
        .collect()
}

/// Print a config instead of writing it: the body, then each companion under
/// its path, each followed by its instructions — a merge note is what keeps a
/// pasted fragment from replacing the user's file. The instructions get the
/// same key splice as the config, since they repeat its lines for a shell
/// export. In a BYOK render `{{api_key}}` is the user's OWN upstream-key
/// placeholder, which the splice never fills — only the gateway sentinel in
/// the `/fwd/…` URL becomes the `vk-`.
fn print_config(
    header: &str,
    spliced: &str,
    cb: &ClientBundle,
    placeholders: &BTreeMap<String, Value>,
    plaintext: Option<&str>,
    paths: &Paths,
) -> Result<()> {
    // Rendered before anything is printed: a companion that fails must not
    // leave half a config, key included, on stdout.
    let companions = spliced_companions(cb, placeholders, plaintext, paths)?;
    println!("{header}\n{spliced}");
    if let Some(instr) = &cb.rendered_instructions {
        println!("{}", splice_key(instr, plaintext));
    }
    for extra in companions {
        let label = extra.path.as_deref().unwrap_or(&extra.title);
        println!("--- {} ({label}) ---\n{}", cb.label, extra.contents);
        if !extra.instructions.trim().is_empty() {
            println!("{}", splice_key(&extra.instructions, plaintext));
        }
    }
    Ok(())
}

/// Print each step no file can carry (a companion with no path) — the user
/// runs it, so it is shown with its instructions on every run that renders
/// it, never only under `--verbose`.
fn print_steps(steps: &[QuirkFile]) {
    for step in steps {
        println!("  {}", crate::ui::muted(&step.title));
        if !step.instructions.trim().is_empty() {
            println!("  {}", step.instructions.trim().replace('\n', "\n  "));
        }
        println!("    {}", step.contents.trim_end().replace('\n', "\n    "));
    }
}

/// A companion resolved for this machine: a file at `path`, or with no path
/// a step for the user to run.
struct QuirkFile {
    path: Option<String>,
    title: String,
    format: TemplateFormat,
    instructions: String,
    contents: String,
}

/// Env lines that make a Node/Python CLI trust a captured private gateway CA —
/// appended to the `.env` companion of env-file clients (gemini, vibe) so they
/// trust a self-signed gateway without a manual shell export. Empty when no CA
/// was captured (public gateway). `NODE_EXTRA_CA_CERTS` is additive (Node trusts
/// every cert in the file as an extra anchor), so it points at the gateway chain.
/// `SSL_CERT_FILE` REPLACES the trust set, so it must point at the additive
/// bundle (system + gateway), never the gateway-only file.
fn ca_env_lines() -> String {
    let Some(ca) = gateway_ca_file() else {
        return String::new();
    };
    // NODE_EXTRA_CA_CERTS (additive) points at the gateway chain. SSL_CERT_FILE
    // REPLACES the trust set, so it points at the additive bundle the installer
    // wrote beside the CA — never the gateway-only file.
    let mut out = format!("NODE_EXTRA_CA_CERTS={}\n", ca.display());
    if let Some(bundle) = gateway_bundle_file() {
        out.push_str(&format!("SSL_CERT_FILE={}\n", bundle.display()));
    }
    out
}

/// Companion files declared by the template, resolved for THIS machine.
///
/// The set and the contents come from the shared
/// [`streamscope_client_templates::companion_files`] — the same function the
/// web quickstart renders from, so the two surfaces cannot describe a
/// different config. Only what is genuinely local is added here: the captured
/// private-CA env lines (paths on this machine) and the project-scope path
/// remap.
fn quirk_files(
    template: &ClientProfileTemplate,
    placeholders: &BTreeMap<String, Value>,
    plaintext: Option<&str>,
    project_root: Option<&Path>,
) -> Result<Vec<QuirkFile>> {
    // An LLM render always mints/reuses a key — no key locally ⇒ nothing to
    // write, or the file would land carrying a raw sentinel.
    if plaintext.is_none() && template.kind.needs_llm() {
        return Ok(Vec::new());
    }
    Ok(companion_files(template, placeholders)
        .with_context(|| format!("rendering companion files for '{}'", template.title))?
        .into_iter()
        .map(|c| {
            let mut contents = c.body;
            // A `.env` companion is where an env-file client picks up trust
            // anchors too — append them so a self-signed gateway needs no
            // manual shell export. Config files in other formats have no such
            // channel, and a step (no path) is not a file.
            if c.format == TemplateFormat::Shell && (c.path.is_some() || c.project_path.is_some()) {
                contents.push_str(&ca_env_lines());
            }
            // Under a project scope a companion lands under the project root
            // — at its declared project path, else its `~/` path re-anchored
            // there — instead of in $HOME.
            let path = match (project_root, companion_project_path(c.path.as_deref(), c.project_path.as_deref())) {
                (Some(root), Some(rel)) => Some(crate::state::join_relative(root, rel).to_string_lossy().into_owned()),
                _ => c.path.clone(),
            };
            QuirkFile { path, title: c.title, format: c.format, instructions: c.instructions, contents }
        })
        .collect())
}

/// The plaintext every config embeds: freshly minted, recalled from the
/// manifest on reuse, or supplied out-of-band — cross-checked against the
/// server's key prefix so a drifted manifest (restored backup, shared $HOME)
/// can't write a wrong key into every tool while reporting success. Shared
/// by `provision` and `sync`; `remedy` is the per-command recovery hint.
pub(crate) fn resolve_bundle_plaintext(
    bundle: &crate::api::BundleResponse,
    reused: Option<String>,
    external: Option<&str>,
    remedy: &str,
) -> Result<Option<String>> {
    let plaintext = bundle
        .minted_secrets
        .api_key
        .clone()
        .or(reused)
        .or_else(|| external.map(str::to_string));
    if bundle.key.is_some() && plaintext.is_none() {
        bail!("the gateway key's plaintext is not available locally — {remedy}");
    }
    if let (Some(key), Some(plain)) = (&bundle.key, &plaintext)
        && let Some(prefix) = &key.key_prefix
        && !plain.starts_with(prefix.as_str())
    {
        bail!(
            "the locally remembered key doesn't match the gateway's key \"{}\" — {remedy}",
            key.name
        );
    }
    Ok(plaintext)
}

/// Integration mode for one client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// A managed `sk-` key + curated routes.
    Gateway,
    /// A `vk-` key bound to a BYOK downstream; native auth/model passed through.
    Byok,
}

impl Mode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Mode::Gateway => "gateway",
            Mode::Byok => "byok",
        }
    }

    /// Parse the mode string stored on a manifest client.
    pub(crate) fn from_manifest(s: &str) -> Mode {
        if s == "byok" {
            Mode::Byok
        } else {
            Mode::Gateway
        }
    }
}

/// One client's resolved integration plan.
#[derive(Clone)]
pub(crate) struct ClientPlan {
    pub(crate) client_id: String,
    pub(crate) template_index: usize,
    pub(crate) mode: Mode,
    /// The LLM provider (gateway) or BYOK downstream (byok). `None` for an
    /// MCP-only client.
    pub(crate) provider_id: Option<uuid::Uuid>,
    /// The MCP virtual servers this client's config is rendered against, SORTED:
    /// one bundle carries one selection, so this is part of the group key below,
    /// and the same set written in a different order must not split one call
    /// into two.
    pub(crate) mcp_server_ids: Vec<uuid::Uuid>,
    /// The local MCP servers selected for this client, SORTED, for the same
    /// reason.
    pub(crate) mcp_local_server_ids: Vec<uuid::Uuid>,
}

/// One bundle call: ONE client, with its mode, provider and MCP servers. Every
/// client gets its own call because a call carries one key, and each tool
/// holds its own key — named for the tool and reused by that tool across
/// projects — so usage and audit attribute per tool. (`indices` names the
/// plan the group renders.)
pub(crate) struct Group {
    pub(crate) client_id: String,
    pub(crate) mode: Mode,
    pub(crate) provider_id: Option<uuid::Uuid>,
    pub(crate) mcp_server_ids: Vec<uuid::Uuid>,
    pub(crate) mcp_local_server_ids: Vec<uuid::Uuid>,
    pub(crate) indices: Vec<usize>,
}

impl Group {
    /// Stable per-group identity for the manifest's no-op etag map.
    pub(crate) fn signature(&self) -> String {
        let mode = match self.mode {
            Mode::Gateway => "gateway",
            Mode::Byok => "byok",
        };
        let ids = |ids: &[uuid::Uuid]| ids.iter().map(|u| u.to_string()).collect::<Vec<_>>().join(",");
        format!(
            "{mode}:{}:mcp={}:local={}:client={}",
            self.provider_id.map(|u| u.to_string()).unwrap_or_default(),
            ids(&self.mcp_server_ids),
            ids(&self.mcp_local_server_ids),
            self.client_id
        )
    }
}

/// One group's bundle outcome, carried to the single manifest write.
struct GroupResult {
    key: Option<BundleKey>,
    plaintext: Option<String>,
    group_sig: String,
    etag: String,
    managed: Vec<ManagedClient>,
}

/// How many distinct keys a set of groups needs: one per (mode, provider). The
/// MCP selection splits a BUNDLE — one call carries one set — but never a key,
/// so two gateway clients that differ only in their MCP servers still share the
/// one key an out-of-band `STREAMSCOPE_GATEWAY_KEY` can be.
pub(crate) fn distinct_key_scopes(groups: &[Group]) -> usize {
    let mut scopes: Vec<(Mode, Option<uuid::Uuid>)> =
        groups.iter().map(|g| (g.mode, g.provider_id)).collect();
    scopes.sort_by_key(|(mode, provider)| {
        (*mode == Mode::Byok, provider.map(|u| u.to_string()).unwrap_or_default())
    });
    scopes.dedup();
    scopes.len()
}

/// Drop etags no managed client's group claims any more. An etag answers "is
/// this group still what the gateway would render", so a signature nothing
/// renders asks nothing. Read from the WHOLE managed set, never this run's
/// selection, or a run naming one client would throw away the others' answers.
pub(crate) fn prune_unused_etags(ws: &mut crate::state::WorkspaceManifest) {
    let plans: Vec<ClientPlan> = ws
        .clients
        .iter()
        .map(|c| ClientPlan {
            client_id: c.client_id.clone(),
            template_index: c.template_index,
            mode: Mode::from_manifest(&c.mode),
            provider_id: c.provider_id,
            mcp_server_ids: c.mcp_server_ids.clone(),
            mcp_local_server_ids: c.mcp_local_servers.iter().map(|s| s.id).collect(),
        })
        .collect();
    let live: std::collections::HashSet<String> =
        group_plans(&plans).iter().map(|g| g.signature()).collect();
    ws.group_etags.retain(|sig, _| live.contains(sig));
}

/// Group the per-client plans into bundle calls, one per client (see
/// [`Group`]). Gateway groups come first.
pub(crate) fn group_plans(plans: &[ClientPlan]) -> Vec<Group> {
    let mut groups: Vec<Group> = Vec::new();
    // (client, byok, provider, MCP servers, local MCP servers)
    type GroupKey = (String, bool, String, Vec<uuid::Uuid>, Vec<uuid::Uuid>);
    let mut index: BTreeMap<GroupKey, usize> = BTreeMap::new();
    for (i, p) in plans.iter().enumerate() {
        // Sorted here too: a plan read back from a stored manifest carries
        // whatever order the run that wrote it used.
        let mut servers = p.mcp_server_ids.clone();
        servers.sort();
        servers.dedup();
        let mut local_servers = p.mcp_local_server_ids.clone();
        local_servers.sort();
        local_servers.dedup();
        let gk = (
            p.client_id.clone(),
            p.mode == Mode::Byok,
            p.provider_id.map(|u| u.to_string()).unwrap_or_default(),
            servers.clone(),
            local_servers.clone(),
        );
        match index.get(&gk) {
            Some(&gi) => groups[gi].indices.push(i),
            None => {
                index.insert(gk, groups.len());
                groups.push(Group {
                    client_id: p.client_id.clone(),
                    mode: p.mode,
                    provider_id: p.provider_id,
                    mcp_server_ids: servers,
                    mcp_local_server_ids: local_servers,
                    indices: vec![i],
                });
            }
        }
    }
    // Stable sort: gateway (false) before byok (true), order otherwise kept.
    groups.sort_by_key(|g| g.mode == Mode::Byok);
    groups
}

/// Resolve an LLM provider for a client in a given mode, filtered to the right
/// kind (BYOK vs gateway). Prompts when several match and we may prompt.
fn resolve_provider(
    sel: Option<&str>,
    mode: Mode,
    me: &PortalMe,
    yes: bool,
    client_id: &str,
) -> Result<uuid::Uuid> {
    let want_byok = matches!(mode, Mode::Byok);
    let kind = if want_byok { "BYOK" } else { "gateway" };
    let candidates: Vec<&crate::api::PortalProvider> = me
        .downstream_providers
        .iter()
        .filter(|p| p.byok == want_byok)
        .collect();
    let names = || {
        candidates
            .iter()
            .map(|p| p.name.clone())
            .collect::<Vec<_>>()
            .join(", ")
    };
    if let Some(sel) = sel {
        let m: Vec<_> = candidates
            .iter()
            .filter(|p| p.id.to_string() == sel || p.name.eq_ignore_ascii_case(sel))
            .collect();
        return match m.len() {
            1 => Ok(m[0].id),
            0 => bail!("no {kind} provider matches {sel:?} for {client_id} — {kind}: {}", names()),
            _ => bail!("provider {sel:?} is ambiguous for {client_id} — use the id"),
        };
    }
    match candidates.len() {
        0 if want_byok => bail!(
            "no BYOK provider is granted to your workspace — ask your admin to grant one \
             (e.g. \"Anthropic Pass-through\"), or use --mode {client_id}=gateway"
        ),
        0 => bail!("no LLM provider is granted to your workspaces — ask your admin"),
        1 => Ok(candidates[0].id),
        _ if yes => bail!(
            "several {kind} providers are granted — pick one with --provider {client_id}=<provider>: {}",
            names()
        ),
        _ => {
            let labels: Vec<Choice> = candidates.iter().map(|p| Choice::new(&p.name)).collect();
            let idx = pick(&format!("Which {kind} provider for {client_id}?"), &labels)?;
            Ok(candidates[idx].id)
        }
    }
}

/// Find the manifest key `client_id` embeds in a group's mode (so a
/// re-provision reuses it). A gateway `sk-` serves any provider; a BYOK `vk-`
/// matches its downstream.
pub(crate) fn find_prev_key<'a>(
    prev: &'a WorkspaceManifest,
    client_id: &str,
    mode: Mode,
    provider_id: Option<uuid::Uuid>,
) -> Option<&'a ManifestKey> {
    let want_fa = matches!(mode, Mode::Byok);
    let key_id = prev
        .clients
        .iter()
        .find(|c| {
            c.client_id == client_id
                && c.mode == mode.as_str()
                && c.key_id.is_some()
                && match mode {
                    Mode::Gateway => true,
                    Mode::Byok => c.provider_id == provider_id,
                }
        })
        .and_then(|c| c.key_id)?;
    // Only the tool's OWN key: one another tool's config also embeds is not
    // reused, so every tool ends up on a key of its own.
    if prev.clients.iter().any(|c| c.key_id == Some(key_id) && c.client_id != client_id) {
        return None;
    }
    prev.keys.get(&key_id).filter(|k| k.forward_auth == want_fa)
}

/// Record one group's key + file bookkeeping on the manifest entry. Keys are
/// recorded in EVERY mode (a dry-run/print bundle can still mint a real key —
/// dropping its plaintext would strand it). `stamp_etag` is false for
/// dry-run/print AND for partially-failed runs. Shared by `provision`/`sync`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn record_group(
    entry: &mut WorkspaceManifest,
    key: Option<&BundleKey>,
    etag: &str,
    plaintext: Option<&str>,
    external_key: Option<&str>,
    group_sig: &str,
    stamp_etag: bool,
    managed_clients: Vec<ManagedClient>,
) {
    if let (Some(key), Some(plain)) = (key, plaintext) {
        entry.keys.insert(
            key.id,
            ManifestKey {
                id: key.id,
                name: key.name.clone(),
                plaintext: plain.to_string(),
                forward_auth: key.forward_auth,
            },
        );
        entry.external_key_sha256 = None;
    } else if let Some(ext) = external_key {
        // The env var stays the source of the plaintext — only its hash is
        // recorded so `sync` can tell when it rotates.
        entry.external_key_sha256 = Some(crate::state::sha256_hex(ext.as_bytes()));
    }
    if stamp_etag {
        entry.group_etags.insert(group_sig.to_string(), etag.to_string());
    }
    for managed in managed_clients {
        entry.clients.retain(|c| c.client_id != managed.client_id);
        entry.clients.push(managed);
    }
}

/// The name prefix of a key minted for `group`'s tool — the server suffixes a
/// taken name (`<prefix>-N`). The one naming rule for `provision` and `sync`:
/// the tool's id, `-byok` appended for a BYOK `vk-`, `ci-` prefixed for a CI
/// run's per-run key (`ci-<tool>`, `ci-<tool>-byok`).
pub(crate) fn key_prefix(ci: bool, group: &Group) -> String {
    match (ci, group.mode) {
        (true, Mode::Gateway) => format!("ci-{}", group.client_id),
        (true, Mode::Byok) => format!("ci-{}-byok", group.client_id),
        (false, Mode::Gateway) => group.client_id.clone(),
        (false, Mode::Byok) => format!("{}-byok", group.client_id),
    }
}

/// What a tool's key is this run: its own live key, the live key this device
/// holds for it, or a mint. `replaces` names the recorded key a mint takes over
/// from (dead, or live but embedded by another tool too); `had_key` says the
/// tool was recorded with a key at all — set, the configs must be rewritten
/// with the new one whatever the etag says (even when the record is dangling).
#[cfg_attr(test, derive(Debug))]
pub(crate) enum KeyChoice {
    Own(ManifestKey),
    Device { key: ManifestKey, replaces: Option<ManifestKey> },
    Mint { replaces: Option<ManifestKey>, old_live: bool, had_key: bool },
}

/// The one key rule of `provision` and `sync`: the tool's own live key, else
/// the device's live key for the tool (`device`, already filtered by the
/// caller for liveness and for `--key-name` / `--key-ttl`), else a mint. A tool
/// recorded WITHOUT a key (spec-OAuth, MCP-only) stays keyless — a device key
/// would make every run rewrite it; a tool new to the manifest takes the
/// device's key.
pub(crate) fn choose_key(
    ws: &WorkspaceManifest,
    group: &Group,
    is_live: impl Fn(uuid::Uuid) -> bool,
    device: Option<ManifestKey>,
) -> KeyChoice {
    let record = ws.clients.iter().find(|c| c.client_id == group.client_id);
    let recorded_id = record.and_then(|c| c.key_id);
    if record.is_some() && recorded_id.is_none() {
        return KeyChoice::Mint { replaces: None, old_live: false, had_key: false };
    }
    if let Some(k) = find_prev_key(ws, &group.client_id, group.mode, group.provider_id).filter(|k| is_live(k.id)) {
        return KeyChoice::Own(k.clone());
    }
    // What the tool's config embeds now, own or shared (`None` when the record
    // names a key the manifest no longer holds).
    let recorded = recorded_id.and_then(|id| ws.keys.get(&id)).cloned();
    match device {
        Some(key) => KeyChoice::Device { key, replaces: recorded },
        None => {
            let old_live = recorded.as_ref().is_some_and(|k| is_live(k.id));
            KeyChoice::Mint { replaces: recorded, old_live, had_key: recorded_id.is_some() }
        }
    }
}

/// Record a key this run minted for `client_id` as its device key, best
/// effort: the manifest records it regardless, and a failure here (an
/// unwritable or unlockable state dir) must not strand a key the gateway has
/// just minted.
pub(crate) fn record_device_key(
    tool_keys: &mut ToolKeys,
    host: &str,
    workspace_id: uuid::Uuid,
    group: &Group,
    key: &BundleKey,
    plaintext: &str,
) {
    let recorded = tool_keys.record_and_save(
        host,
        workspace_id,
        &group.client_id,
        group.provider_id,
        ManifestKey {
            id: key.id,
            name: key.name.clone(),
            plaintext: plaintext.to_string(),
            forward_auth: key.forward_auth,
        },
    );
    if let Err(e) = recorded {
        crate::ui::warn("  ", format_args!("{}'s key was not saved for other projects ({e:#}) — this project keeps it", group.client_id));
    }
}

/// The `(name, prefix)` a minted key is asked for: `--key-name` names the one
/// key of a single-key run, or prefixes each tool's (`<name>-<tool>`); without
/// it, the tool's own prefix ([`key_prefix`]). The same in both modes and in CI.
pub(crate) fn key_name_and_prefix(
    key_name: Option<&str>,
    single_key_run: bool,
    ci: bool,
    group: &Group,
) -> (Option<String>, Option<String>) {
    match key_name {
        Some(n) if single_key_run => (Some(n.to_string()), None),
        Some(n) => (None, Some(format!("{n}-{}", group.client_id))),
        None => (None, Some(key_prefix(ci, group))),
    }
}

/// Drop the keys no client of `entry` embeds any more (a re-provision rotated
/// or dropped a tool's key) and return them. Nothing here revokes a key: the
/// caller says what the user should know about it.
pub(crate) fn prune_unused_keys(entry: &mut WorkspaceManifest) -> Vec<ManifestKey> {
    let used: HashSet<uuid::Uuid> = entry.clients.iter().filter_map(|c| c.key_id).collect();
    let dropped: Vec<uuid::Uuid> = entry.keys.keys().filter(|id| !used.contains(id)).copied().collect();
    dropped.iter().filter_map(|id| entry.keys.remove(id)).collect()
}

/// Tell the user about keys no tool of this manifest uses any more — still
/// valid on the gateway, and possibly still another project's or device's.
pub(crate) fn note_unused_keys(dropped: &[ManifestKey]) {
    for k in dropped {
        println!(
            "  Key \"{}\" is no longer used by any tool here. Other projects on this machine (or \
             other devices) may still use it — revoke it on the portal's Keys page only once \
             nothing does.",
            k.name
        );
    }
}

/// Parse `--mode client=byok|gateway` overrides.
fn parse_mode_overrides(raw: &[String]) -> Result<BTreeMap<String, Mode>> {
    let mut map = BTreeMap::new();
    for entry in raw {
        let (client, value) = entry
            .split_once('=')
            .with_context(|| format!("--mode wants client=byok|gateway, got {entry:?}"))?;
        map.insert(client.to_string(), parse_mode(value)?);
    }
    Ok(map)
}

fn parse_mode(value: &str) -> Result<Mode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "byok" => Ok(Mode::Byok),
        "gateway" | "gw" => Ok(Mode::Gateway),
        other => bail!("unknown mode {other:?} — use byok or gateway"),
    }
}

/// Parse `--provider` values into a bare default plus per-client `client=value`
/// overrides.
fn parse_provider_args(raw: &[String]) -> Result<(Option<String>, BTreeMap<String, String>)> {
    let mut default: Option<String> = None;
    let mut per: BTreeMap<String, String> = BTreeMap::new();
    for entry in raw {
        match entry.split_once('=') {
            Some((client, value)) => {
                per.insert(client.to_string(), value.to_string());
            }
            None => {
                if default.is_some() {
                    bail!("--provider given twice without a client= prefix");
                }
                default = Some(entry.clone());
            }
        }
    }
    Ok((default, per))
}

/// `STREAMSCOPE_GATEWAY_KEY` — an sk-/vk- gateway key supplied out-of-band
/// (the CI render-only escape hatch). Validated here so a typo'd value fails
/// before anything is rendered or written.
pub(crate) fn external_gateway_key() -> Result<Option<String>> {
    let Some(key) = std::env::var("STREAMSCOPE_GATEWAY_KEY")
        .ok()
        .filter(|s| !s.is_empty())
    else {
        return Ok(None);
    };
    if !key.starts_with("sk-") && !key.starts_with("vk-") {
        bail!(
            "STREAMSCOPE_GATEWAY_KEY doesn't look like a gateway key \
             (expected an sk-… virtual key or vk-… BYOK key)"
        );
    }
    Ok(Some(key))
}

/// Parse a duration flag (`--key-ttl`, `--interval`): `<N>s|m|h|d`, e.g.
/// `2h`, `30m`, `7d`. Splits on the last *character* (never a raw byte
/// index — a multi-byte trailing char must fail cleanly, not panic).
pub(crate) fn parse_ttl(raw: &str) -> Result<chrono::Duration> {
    let raw = raw.trim();
    let err = || format!("expected a duration like 2h (<N>s|m|h|d), got {raw:?}");
    let unit = raw.chars().next_back().with_context(err)?;
    let num = &raw[..raw.len() - unit.len_utf8()];
    let n: i64 = num.parse().ok().filter(|n| *n > 0).with_context(err)?;
    match unit {
        's' => Ok(chrono::Duration::seconds(n)),
        'm' => Ok(chrono::Duration::minutes(n)),
        'h' => Ok(chrono::Duration::hours(n)),
        'd' => Ok(chrono::Duration::days(n)),
        _ => bail!(err()),
    }
}


fn parse_template_overrides(raw: &[String]) -> Result<BTreeMap<String, String>> {
    let mut map = BTreeMap::new();
    for entry in raw {
        let (client, name) = entry
            .split_once('=')
            .with_context(|| format!("--template wants client=variant, got {entry:?}"))?;
        map.insert(client.to_string(), name.to_string());
    }
    Ok(map)
}

/// One line naming the variant picked for a client that ships its config in
/// several protocols, and how to pick another — `None` when there is no
/// protocol choice to make (an MCP auth-mode sibling is not one).
fn variant_hint(
    client_id: &str,
    templates: &[ClientProfileTemplate],
    chosen: &ClientProfileTemplate,
) -> Option<String> {
    if !chosen.kind.needs_llm() {
        return None;
    }
    let chosen_name = chosen.variant_name();
    let mut others: Vec<String> = Vec::new();
    let file_writing_protocol_variants = templates.iter().filter(|t| {
        matches!(t.kind, TemplateKind::Combined | TemplateKind::Llm)
            && t.filename.is_some()
            && t.protocol != chosen.protocol
            && matches!(t.mcp_auth_mode, McpAuthMode::Static)
    });
    for t in file_writing_protocol_variants {
        let n = t.variant_name();
        if n != chosen_name && !others.contains(&n) {
            others.push(n);
        }
    }
    if others.is_empty() {
        return None;
    }
    let switch: Vec<String> = others.iter().map(|n| format!("--template {client_id}={n}")).collect();
    Some(format!("  {}: {} (switch: {})", client_id, chosen.title, switch.join(" | ")))
}

/// Point each plan without a `--template` override at the template its client
/// was last provisioned with — a new default never silently swaps an
/// installation's variant. Only a record in the same mode, naming a template
/// that still exists, is the same kind as this run's pick (an LLM config never
/// turns into an MCP-only one, or back), and has a project-local form exactly
/// when the pick does (the global-vs-project split was decided from the pick).
fn keep_recorded_variants<'a>(
    plans: &mut [ClientPlan],
    recorded: &[ManagedClient],
    overrides: &BTreeMap<String, String>,
    templates_of: impl Fn(&str) -> Option<&'a [ClientProfileTemplate]>,
) {
    for plan in plans.iter_mut() {
        if overrides.contains_key(&plan.client_id) {
            continue;
        }
        let Some(templates) = templates_of(&plan.client_id) else { continue };
        // A BYOK installation keeps its variant only against the same
        // pass-through: another may speak another protocol, and the forwarded
        // credential works only on its own.
        let Some(prev) = recorded.iter().find(|c| {
            c.client_id == plan.client_id
                && Mode::from_manifest(&c.mode) == plan.mode
                && (plan.mode != Mode::Byok || c.provider_id == plan.provider_id)
        }) else {
            continue;
        };
        let (Some(now), Some(then)) =
            (templates.get(plan.template_index), templates.get(prev.template_index))
        else {
            continue;
        };
        if now.kind.needs_llm() == then.kind.needs_llm()
            && now.project_filename.is_some() == then.project_filename.is_some()
        {
            plan.template_index = prev.template_index;
        }
    }
}

/// Resolve a `--template <client>=<variant>` name to a template index. Several
/// templates can share a name only when all but one are print-only snippets
/// (aider's shell env, curl-generic's SDK env vars): the one that writes a
/// file wins, else the first.
fn template_index_by_name(
    client_id: &str,
    templates: &[ClientProfileTemplate],
    name: &str,
) -> Result<usize> {
    let matching = || {
        templates
            .iter()
            .enumerate()
            .filter(|(_, t)| t.variant_name() == name)
    };
    if let Some((i, _)) = matching()
        .find(|(_, t)| t.filename.is_some())
        .or_else(|| matching().next())
    {
        return Ok(i);
    }
    let mut names: Vec<String> = Vec::new();
    for n in templates.iter().map(ClientProfileTemplate::variant_name) {
        if !names.contains(&n) {
            names.push(n);
        }
    }
    bail!(
        "{client_id} has no {name:?} variant — pick one of: {}",
        names.join(", ")
    )
}

/// The gateway MCP servers a run gives its clients.
pub(crate) struct McpChoice {
    /// What the workspace offers — `None` when the run did not need to read it.
    pub(crate) offered: Option<BTreeSet<uuid::Uuid>>,
    /// `Some`: this set for every client (named with `--mcp`, `--all-mcp`,
    /// ticked in the prompt, or none with `--no-mcp`). `None`: each client
    /// keeps the ones it was provisioned with.
    pub(crate) chosen: Option<Vec<uuid::Uuid>>,
}

impl McpChoice {
    /// The ids for a client recorded with `recorded` (sorted, a set), and how
    /// many of the recorded ones the workspace no longer offers.
    pub(crate) fn for_client(&self, recorded: &[uuid::Uuid]) -> (Vec<uuid::Uuid>, usize) {
        let offered = |id: &uuid::Uuid| self.offered.as_ref().is_none_or(|o| o.contains(id));
        let mut ids: Vec<uuid::Uuid> = match &self.chosen {
            Some(ids) => ids.clone(),
            None => recorded.iter().copied().filter(offered).collect(),
        };
        ids.sort();
        ids.dedup();
        let gone = match &self.chosen {
            Some(_) => 0,
            None => recorded.iter().filter(|id| !offered(id)).count(),
        };
        (ids, gone)
    }
}

/// Resolve which MCP virtual servers the MCP-capable clients get.
///
/// Precedence: `--no-mcp` → none; `--mcp <slug>…` → exactly those (validated);
/// `--all-mcp` → every reachable server; otherwise an interactive run where a
/// selected client can consume MCP proposes the reachable servers — ticked:
/// the ones a selected client was provisioned with (`recorded`), or all of
/// them when none was. Any other run with no flag changes nothing: each
/// client keeps the ones it was provisioned with (those still offered), and a
/// client provisioned for the first time gets none. Any chosen
/// `per_user_oauth` server the current user hasn't linked yet prints a
/// "connect in the portal first" note — the config is still written and goes
/// live once the user connects.
async fn resolve_mcp_servers(
    api: &ApiClient,
    workspace_id: uuid::Uuid,
    args: &ProvisionArgs,
    any_client_supports_mcp: bool,
    recorded: &BTreeSet<uuid::Uuid>,
) -> Result<McpChoice> {
    if args.no_mcp {
        return Ok(McpChoice { offered: None, chosen: Some(Vec::new()) });
    }

    // An explicit `--mcp <slug>` list always wins (validated against the
    // reachable set), even for a client that has no MCP template.
    if !args.mcp.is_empty() {
        let available = api.mcp_virtual_servers(workspace_id).await?;
        let selected: Vec<McpVirtualServer> = args
            .mcp
            .iter()
            .map(|slug| {
                available
                    .iter()
                    .find(|s| &s.slug == slug)
                    .cloned()
                    .with_context(|| {
                        format!(
                            "no MCP server with slug {slug:?} — available: {}",
                            available.iter().map(|s| s.slug.clone()).collect::<Vec<_>>().join(", ")
                        )
                    })
            })
            .collect::<Result<_>>()?;
        warn_connect_first(&selected);
        return Ok(McpChoice { offered: None, chosen: Some(selected.iter().map(|s| s.id).collect()) });
    }

    // `--all-mcp` is an explicit request, like `--mcp <slug>` — honour it
    // regardless of whether a selected client can consume MCP.
    if args.all_mcp {
        let available = api.mcp_virtual_servers(workspace_id).await?;
        warn_connect_first(&available);
        return Ok(McpChoice { offered: None, chosen: Some(available.iter().map(|s| s.id).collect()) });
    }

    // Nothing to keep and nobody to ask: nothing is read.
    let asks = any_client_supports_mcp && !args.yes;
    if recorded.is_empty() && !asks {
        return Ok(McpChoice { offered: None, chosen: None });
    }

    let available = api.mcp_virtual_servers(workspace_id).await?;
    let offered: BTreeSet<uuid::Uuid> = available.iter().map(|s| s.id).collect();
    if !asks || available.is_empty() {
        return Ok(McpChoice { offered: Some(offered), chosen: None });
    }

    // Interactive proposal — each line shows `name (slug)` plus a connect-first
    // hint for a per-user-OAuth server the user hasn't linked yet.
    let labels: Vec<Choice> = available
        .iter()
        .map(|s| {
            let choice = Choice::new(format!("{} ({})", s.name, s.slug));
            if s.connection_status == "needs_connection" {
                choice.hint("connect in portal first")
            } else if !s.client_headers.is_empty() {
                choice.hint(format!("your client sends {}", s.client_headers.join(", ")))
            } else {
                choice
            }
        })
        .collect();
    let ticked: Vec<usize> =
        (0..available.len()).filter(|&i| recorded.is_empty() || recorded.contains(&available[i].id)).collect();
    let picks = pick_many_ticked("Which MCP servers should I wire into MCP-capable clients?", &labels, 0, &ticked)?;
    let selected: Vec<McpVirtualServer> = picks.into_iter().map(|i| available[i].clone()).collect();
    warn_connect_first(&selected);
    Ok(McpChoice { offered: Some(offered), chosen: Some(selected.iter().map(|s| s.id).collect()) })
}

/// The local MCP servers a run gives its clients.
pub(crate) struct LocalChoice {
    /// What the workspace is handed — empty when the run did not need to read it.
    pub(crate) offered: Vec<crate::api::McpLocalServer>,
    /// Whether `offered` was read: only then does a recorded server missing
    /// from it mean "no longer offered".
    pub(crate) offered_read: bool,
    /// `Some`: this set (named with `--local-mcp`, ticked in the prompt, or
    /// none). `None`: each client keeps the ones it was provisioned with.
    pub(crate) chosen: Option<Vec<uuid::Uuid>>,
    /// The clients a set ticked in the prompt was asked for — the ones the
    /// question named. `None`: the set is for every client (flags).
    pub(crate) picked_for: Option<Vec<String>>,
}

impl LocalChoice {
    /// The ids for `client_id`, recorded with `recorded` (sorted, a set). A
    /// set picked in the prompt goes only to the clients the prompt named:
    /// another client gets none of it, and no warning about it.
    pub(crate) fn for_client(&self, client_id: &str, recorded: &[ManagedLocalMcp]) -> Vec<uuid::Uuid> {
        let offered = |id: &uuid::Uuid| !self.offered_read || self.offered.iter().any(|s| s.id == *id);
        let named = self.picked_for.as_ref().is_none_or(|clients| clients.iter().any(|c| c == client_id));
        let mut ids: Vec<uuid::Uuid> = match &self.chosen {
            Some(ids) if named => ids.clone(),
            Some(_) => Vec::new(),
            None => recorded.iter().filter(|s| offered(&s.id)).map(|s| s.id).collect(),
        };
        ids.sort();
        ids.dedup();
        ids
    }
}

/// Resolve which local MCP servers (started by this machine) the clients that
/// have a form for one get.
///
/// Precedence: `--no-mcp` / `--no-local-mcp` → none; `--local-mcp <slug>…` →
/// exactly those (validated against what the workspace is handed); otherwise
/// an interactive run where a selected client can start one (`targets`)
/// proposes them, each with its command line ([`local_pick`]): ONE selection,
/// written to every one of those clients. Any other run
/// with no flag changes nothing: each client keeps the ones it was provisioned
/// with, a client provisioned for the first time gets none.
///
/// A run that would keep recorded servers must know which are still handed to
/// the workspace, so that read failing fails the run; with nothing recorded
/// the prompt is a convenience and a failed read only skips it.
async fn resolve_local_mcp_servers(
    api: &ApiClient,
    args: &ProvisionArgs,
    workspace_id: uuid::Uuid,
    targets: &[String],
    recorded: &BTreeSet<uuid::Uuid>,
) -> Result<LocalChoice> {
    let none = LocalChoice { offered: Vec::new(), offered_read: false, chosen: Some(Vec::new()), picked_for: None };
    if args.no_mcp || args.no_local_mcp {
        return Ok(none);
    }
    if !args.local_mcp.is_empty() {
        let offered = api.mcp_local_servers(workspace_id).await?;
        let chosen = args
            .local_mcp
            .iter()
            .map(|slug| {
                offered.iter().find(|s| &s.slug == slug).map(|s| s.id).with_context(|| {
                    format!(
                        "no local MCP server with slug {slug:?} — available: {}",
                        offered.iter().map(|s| s.slug.clone()).collect::<Vec<_>>().join(", ")
                    )
                })
            })
            .collect::<Result<Vec<_>>>()?;
        return Ok(LocalChoice { offered, offered_read: true, chosen: Some(chosen), picked_for: None });
    }
    let asks = !targets.is_empty() && !args.yes;
    let offered = if !recorded.is_empty() {
        api.mcp_local_servers(workspace_id).await?
    } else if asks {
        let (offered, warning) = proposal_or_none(api.mcp_local_servers(workspace_id).await);
        if let Some(warning) = warning {
            crate::ui::warn("", format_args!("{warning}"));
        }
        offered
    } else {
        return Ok(none);
    };
    if !asks || offered.is_empty() {
        return Ok(LocalChoice { offered, offered_read: true, chosen: None, picked_for: None });
    }
    let labels: Vec<Choice> = offered
        .iter()
        .map(|s| {
            Choice::new(format!("{} ({})", s.name, s.slug))
                .hint(format!("runs: {}", s.command_line))
        })
        .collect();
    let (question, ticked) = local_pick(&offered, recorded, targets);
    let picks = pick_many_ticked(&question, &labels, 0, &ticked)?;
    let chosen = picks.into_iter().map(|i| offered[i].id).collect();
    Ok(LocalChoice { offered, offered_read: true, chosen: Some(chosen), picked_for: Some(targets.to_vec()) })
}

/// The interactive pick of local MCP servers: its question and the entries
/// ticked to start. The pick is one selection for the run, so the question
/// names the clients it is written to when there are several (`targets`), and
/// what is ticked is every server recorded for at least one selected client
/// (`recorded`) — all of them when none is recorded.
fn local_pick(
    offered: &[crate::api::McpLocalServer],
    recorded: &BTreeSet<uuid::Uuid>,
    targets: &[String],
) -> (String, Vec<usize>) {
    let ticked = (0..offered.len())
        .filter(|&i| recorded.is_empty() || recorded.contains(&offered[i].id))
        .collect();
    let question = match targets {
        [] | [_] => "Which local MCP servers (started on this machine) should I add?".to_string(),
        several => format!(
            "Which local MCP servers (started on this machine) should I add? One selection, for: {}",
            several.join(", ")
        ),
    };
    (question, ticked)
}

/// What an interactive run proposes when nobody asked for a local server: the
/// list as read, or — when the gateway could not answer — none, with the line
/// that says so. The proposal is a convenience; failing to read it never
/// stops the run. (A `--local-mcp <slug>` the developer asked for is another
/// matter: that read failing fails the run.)
fn proposal_or_none(
    read: Result<Vec<crate::api::McpLocalServer>>,
) -> (Vec<crate::api::McpLocalServer>, Option<String>) {
    match read {
        Ok(available) => (available, None),
        Err(e) => (
            Vec::new(),
            Some(format!(
                "the local MCP servers of this workspace could not be read ({e:#}) — continuing without any"
            )),
        ),
    }
}

/// Print what each chosen server still needs: a "connect in the portal first"
/// note for one the current user hasn't connected yet, the headers their MCP
/// client must send itself (the config holds a placeholder for each), and
/// that a client set up for sign-in leaves out a server on the `/fwd` mount.
/// The config is written regardless.
fn warn_connect_first(servers: &[McpVirtualServer]) {
    for s in servers {
        if s.connection_status == "needs_connection" {
            crate::ui::note("  ", format_args!("connect '{}' in the portal first (Portal → MCP Connections) — the config is written now and works once linked", s.name));
        }
        if !s.client_headers.is_empty() {
            crate::ui::note("  ", format_args!("'{}' reads {} from your MCP client: replace the <paste-your-…-here> placeholder in the written config with your value", s.name, s.client_headers.join(", ")));
        }
        if s.fwd_mount {
            crate::ui::note("  ", format_args!("'{}' takes your client's own Authorization header, so a client set up to sign in with OAuth leaves it out", s.name));
        }
    }
}

/// Default template pick. An LLM template (combined/llm) always wins — the
/// client's OpenAI-compatible one when it ships several protocols
/// ([`default_llm_template_index`]). Otherwise the choice depends on whether this run wires MCP servers:
/// with `--mcp`, prefer the MCP template (a client like Cursor gets its server
/// wired); without it, fall back to an LLM `instructions` template (Cursor's
/// UI-setup guide) so the run still does something useful. An MCP-only client
/// in an LLM-only run yields `None`, so the caller skips it gracefully rather
/// than rendering an MCP template that needs servers it won't get.
///
/// A local MCP server (`wants_local`) changes the pick only for a client with
/// no LLM template in a run that wires no gateway server: its MCP template
/// that has a form for a local server, if it has one — never an MCP template
/// that could not write it.
fn default_template_index(templates: &[ClientProfileTemplate], has_mcp: bool, wants_local: bool) -> Option<usize> {
    let llm = default_llm_template_index(templates, None);
    let mcp = || templates.iter().position(|t| matches!(t.kind, TemplateKind::Mcp));
    let local_mcp =
        || templates.iter().position(|t| matches!(t.kind, TemplateKind::Mcp) && !t.local_mcp.is_none());
    let instr = || templates.iter().position(|t| matches!(t.kind, TemplateKind::Instructions));
    if has_mcp {
        llm.or_else(mcp).or_else(instr)
    } else if wants_local {
        llm.or_else(local_mcp).or_else(instr)
    } else {
        llm.or_else(instr)
    }
}

/// A template that writes a real file (`filename`) but has no project-local
/// form (`project_filename`) can only ever live at its one global path — its
/// tool reads that single file regardless of the working directory. In a
/// project run such a client is provisioned into the GLOBAL scope rather than
/// skipped. Print-only templates (no `filename`) are not global-only: they just
/// print and belong to whichever scope job carries them.
fn is_global_only_template(t: &ClientProfileTemplate) -> bool {
    t.filename.is_some() && t.project_filename.is_none()
}

/// Resolve a template's `filename` to a writable path: literal `~/`-paths
/// pass through; display names go through [`client_file_path`]; anything
/// else is unknown (`None` → the caller prints instead of writing).
fn resolve_target_path(client_id: &str, filename: &str) -> Option<String> {
    if filename.starts_with("~/") || filename.starts_with('/') {
        return Some(filename.to_string());
    }
    client_file_path(client_id, filename)
}

/// Platform locations for clients whose profile filename is a display name
/// rather than a literal path (the web quickstart shows the display name to
/// humans; where the file actually lives per platform is the CLI's
/// knowledge).
fn client_file_path(client_id: &str, display_name: &str) -> Option<String> {
    let (linux, macos) = match (client_id, display_name) {
        ("cline", "VS Code settings.json") => (
            "~/.config/Code/User/settings.json",
            "~/Library/Application Support/Code/User/settings.json",
        ),
        ("cline", "cline_mcp_settings.json") => (
            "~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
            "~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
        ),
        ("claude-desktop", "claude_desktop_config.json") => (
            "~/.config/Claude/claude_desktop_config.json",
            "~/Library/Application Support/Claude/claude_desktop_config.json",
        ),
        _ => return None,
    };
    // On Windows the Linux spelling stands: `expand_tilde` finds these apps'
    // folders under `%APPDATA%`.
    Some(if cfg!(target_os = "macos") { macos } else { linux }.to_string())
}

/// What client detection found: the clients installed on this machine, and
/// those with only a configuration left behind.
struct Detected {
    installed: Vec<&'static str>,
    /// Clients whose binary is absent but whose config dir exists — usually
    /// left by an uninstall or by an earlier provisioning. Never selected by
    /// default: provisioning one writes a config nothing reads, and `run`
    /// fails to start it.
    config_only: Vec<&'static str>,
}

/// Which profile ids are installed on this machine. A CLI client is installed
/// when its launch binary is on PATH; a config dir alone does not count — it
/// is often the one an earlier provisioning wrote. A desktop app (no binary on
/// PATH as a rule) is probed by the data dir the APP creates on first start,
/// never by the file Streamscope writes for it.
fn detect_installed_clients() -> Detected {
    match crate::state::UserDirs::current() {
        Ok(dirs) => detect_in(&dirs, Platform::current(), |bin| crate::program::find(bin).is_some()),
        Err(_) => Detected { installed: Vec::new(), config_only: Vec::new() },
    }
}

/// The platform detection probes for: each keeps its desktop apps elsewhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Platform {
    Linux,
    MacOs,
    Windows,
}

impl Platform {
    fn current() -> Self {
        if cfg!(target_os = "macos") {
            Platform::MacOs
        } else if cfg!(windows) {
            Platform::Windows
        } else {
            Platform::Linux
        }
    }
}

/// Where VS Code and its forks keep installed extensions.
const VSCODE_EXTENSIONS: &str = ".vscode/extensions";
const EDITOR_EXTENSION_DIRS: [&str; 7] = [
    VSCODE_EXTENSIONS,
    ".vscode-insiders/extensions",
    ".vscode-oss/extensions",
    ".vscode-server/extensions",
    ".cursor/extensions",
    ".windsurf/extensions",
    ".vscodium/extensions",
];

/// The installed extension folder names (`publisher.name-version`) of each
/// editor dir under `home`, read once per detection.
fn installed_extensions(home: &Path) -> Vec<(&'static str, Vec<String>)> {
    EDITOR_EXTENSION_DIRS
        .iter()
        .map(|d| {
            let names = std::fs::read_dir(home.join(d))
                .map(|entries| {
                    entries.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().into_owned()).collect()
                })
                .unwrap_or_default();
            (*d, names)
        })
        .collect()
}

/// Detection against the user folders `dirs` on the platform `os`, with
/// `which` answering whether a program is on PATH. A client is installed by
/// its program (CLI), its editor extension, or its desktop app; a config dir
/// alone is reported as left over, never as an install.
fn detect_in(dirs: &crate::state::UserDirs, os: Platform, which: impl Fn(&str) -> bool) -> Detected {
    let home = dirs.home.as_path();
    // Resolved as `expand_tilde` resolves what provisioning writes: the same
    // folder detection looks in.
    let exists = |p: &str| !p.is_empty() && dirs.resolve(p).is_some_and(|p| p.exists());
    let pick = |linux: &'static str, mac: &'static str| if os == Platform::MacOs { mac } else { linux };
    // (id, launch binary, editor extension prefix, the editors whose extension
    // reads the config we write, config dir — reported when only it is present).
    const ANY_EDITOR: &[&str] = &EDITOR_EXTENSION_DIRS;
    let cli: &[(&str, &str, &str, &[&str], &str)] = &[
        ("claude-code", "claude", "", &[], "~/.claude"),
        ("codex", "codex", "", &[], "~/.codex"),
        ("gemini-cli", "gemini", "", &[], "~/.gemini"),
        ("vibe", "vibe", "", &[], "~/.vibe"),
        ("qwen-code", "qwen", "", &[], "~/.qwen"),
        ("goose", "goose", "", &[], "~/.config/goose"),
        ("opencode", "opencode", "", &[], "~/.config/opencode"),
        ("crush", "crush", "", &[], "~/.config/crush"),
        ("aider", "aider", "", &[], "~/.aider.conf.yml"),
        // The Continue CLI (`cn`) and its extension, in any editor, read `~/.continue`.
        ("continue", "cn", "continue.continue-", ANY_EDITOR, "~/.continue"),
        // Cline is configured in VS Code's own settings file, which no fork reads.
        ("cline", "", "saoudrizwan.claude-dev-", &[VSCODE_EXTENSIONS], ""),
    ];
    let extensions = installed_extensions(home);
    let extension_in = |prefix: &str, editors: &[&str]| {
        extensions
            .iter()
            .filter(|(d, _)| editors.contains(d))
            .any(|(_, names)| names.iter().any(|n| n.starts_with(prefix)))
    };
    // (id, binary when it has one, the app's own install or data paths, our config dir).
    // The Windows folders are each app's per-user install (verified on
    // Windows 11).
    let apps: &[(&str, &str, &[&str], &str)] = &[
        (
            "cursor",
            "cursor",
            match os {
                Platform::MacOs => &["~/Library/Application Support/Cursor"],
                Platform::Windows => &["%LOCALAPPDATA%/Programs/cursor"],
                Platform::Linux => &["~/.config/Cursor"],
            },
            "~/.cursor",
        ),
        (
            "zed",
            "zed",
            match os {
                Platform::MacOs => &["~/Library/Application Support/Zed"],
                Platform::Windows => &["%LOCALAPPDATA%/Programs/Zed", "%LOCALAPPDATA%/Zed"],
                Platform::Linux => &["~/.local/share/zed"],
            },
            "~/.config/zed",
        ),
        (
            "claude-desktop",
            "claude-desktop",
            match os {
                Platform::MacOs => &["/Applications/Claude.app", "~/Applications/Claude.app"],
                Platform::Windows => &["%LOCALAPPDATA%/AnthropicClaude"],
                Platform::Linux => &[],
            },
            pick("~/.config/Claude", "~/Library/Application Support/Claude"),
        ),
    ];
    let mut found = Detected { installed: Vec::new(), config_only: Vec::new() };
    for (id, bin, extension, editors, dir) in cli {
        if (!bin.is_empty() && which(bin)) || (!extension.is_empty() && extension_in(extension, editors)) {
            found.installed.push(*id);
        } else if exists(dir) {
            found.config_only.push(*id);
        }
    }
    for (id, bin, app_paths, our_dir) in apps {
        if (!bin.is_empty() && which(bin)) || app_paths.iter().any(|p| exists(p)) {
            found.installed.push(*id);
        } else if exists(our_dir) {
            found.config_only.push(*id);
        }
    }
    found
}

#[cfg(test)]
mod detect_tests {
    use super::*;

    /// A Unix user's folders: the home alone.
    fn dirs(home: &Path) -> crate::state::UserDirs {
        crate::state::UserDirs { home: home.to_path_buf(), appdata: None, local_appdata: None }
    }

    fn home(tag: &str) -> PathBuf {
        let h = std::env::temp_dir().join(format!("ss-detect-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&h);
        std::fs::create_dir_all(&h).unwrap();
        h
    }

    #[test]
    fn a_program_or_an_extension_is_an_install_a_leftover_dir_is_not() {
        let h = home("classes");
        std::fs::create_dir_all(h.join(".codex")).unwrap(); // left over, no binary
        std::fs::create_dir_all(h.join(".continue")).unwrap(); // the extension's file…
        std::fs::create_dir_all(h.join(".vscode-insiders/extensions/continue.continue-1.2.3")).unwrap();
        std::fs::create_dir_all(h.join(".cursor/extensions/saoudrizwan.claude-dev-3.0.0")).unwrap();
        let d = detect_in(&dirs(&h), Platform::Linux, |b| b == "claude");
        assert!(d.installed.contains(&"claude-code"), "{:?}", d.installed);
        assert!(d.installed.contains(&"continue"), "extension without `cn`, in any editor: {:?}", d.installed);
        // Cline in a fork reads that fork's settings, which provisioning does not write.
        assert!(!d.installed.contains(&"cline"), "Cline only in Cursor: {:?}", d.installed);
        std::fs::create_dir_all(h.join(".vscode/extensions/saoudrizwan.claude-dev-3.0.0")).unwrap();
        assert!(detect_in(&dirs(&h), Platform::Linux, |_| false).installed.contains(&"cline"), "Cline in VS Code");
        assert!(
            !d.installed.contains(&"codex") && d.config_only.contains(&"codex"),
            "{:?} / {:?}",
            d.installed,
            d.config_only
        );
        let _ = std::fs::remove_dir_all(&h);
    }

    #[test]
    fn claude_desktop_in_the_users_applications_folder_counts_on_macos() {
        let h = home("app");
        std::fs::create_dir_all(h.join("Applications/Claude.app")).unwrap();
        assert!(detect_in(&dirs(&h), Platform::MacOs, |_| false).installed.contains(&"claude-desktop"));
        // Positive control for the absence: the same home on Linux has no app path.
        assert!(!detect_in(&dirs(&h), Platform::Linux, |_| false).installed.contains(&"claude-desktop"));
        let _ = std::fs::remove_dir_all(&h);
    }

    /// On Windows a desktop app is found by its per-user install folder, and
    /// a left-over config where the app keeps it (`%APPDATA%`) — never in the
    /// machine's real folders: the test gives its own.
    #[test]
    fn windows_apps_are_found_in_their_appdata_folders() {
        let h = home("windows");
        let win = crate::state::UserDirs {
            home: h.join("profile"),
            appdata: Some(h.join("roaming")),
            local_appdata: Some(h.join("local")),
        };
        for d in ["local/AnthropicClaude", "local/Programs/Zed", "roaming/Block/goose/config"] {
            std::fs::create_dir_all(h.join(d)).unwrap();
        }
        let d = detect_in(&win, Platform::Windows, |_| false);
        assert!(d.installed.contains(&"claude-desktop") && d.installed.contains(&"zed"), "{:?}", d.installed);
        assert!(!d.installed.contains(&"cursor"), "{:?}", d.installed);
        assert!(d.config_only.contains(&"goose"), "{:?}", d.config_only);
        // Control: the same folders mean nothing to a Linux probe.
        let linux = detect_in(&win, Platform::Linux, |_| false);
        assert!(!linux.installed.contains(&"claude-desktop") && !linux.installed.contains(&"zed"), "{:?}", linux.installed);
        let _ = std::fs::remove_dir_all(&h);
    }
}

#[cfg(test)]
mod gitignore_entry_tests {
    use super::project_relative;
    use std::path::Path;

    /// A `.gitignore` entry is `/`-separated on every platform: git reads a
    /// `\` as an escape, so `.gemini\.env` would leave the key file unignored.
    #[test]
    fn an_ignore_entry_is_slash_separated() {
        let root = Path::new("proj");
        let file = root.join(".gemini").join(".env");
        let written = file.to_string_lossy().into_owned();
        assert_eq!(project_relative(root, std::iter::once(written.as_str())), [".gemini/.env"]);
        // A path outside the root names no entry.
        assert!(project_relative(root, std::iter::once("elsewhere/.env")).is_empty());
    }
}

#[cfg(test)]
mod path_table_tests {
    use super::client_file_path;

    /// Every seeded profile template whose `filename` is a display name (no
    /// `~/` or `/` prefix) must resolve through the path table — otherwise a
    /// seed rename silently downgrades that client to print-mode. Keep
    /// `client_file_path` in sync with `seeds/client_profiles/`.
    #[test]
    fn every_seed_display_name_resolves() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../seeds/client_profiles");
        let mut checked = 0;
        for entry in std::fs::read_dir(dir).expect("seeds/client_profiles readable") {
            let path = entry.expect("dir entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let profile: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&path).expect("read seed"))
                    .expect("seed parses");
            let client_id = profile["id"].as_str().expect("seed has id");
            for template in profile["templates"].as_array().expect("templates array") {
                let Some(filename) = template["filename"].as_str() else {
                    continue;
                };
                if filename.starts_with("~/") || filename.starts_with('/') {
                    continue;
                }
                assert!(
                    client_file_path(client_id, filename).is_some(),
                    "{client_id}: display-name filename {filename:?} has no path-table entry"
                );
                checked += 1;
            }
        }
        assert!(checked >= 3, "expected the cline/claude-desktop display names, found {checked}");
    }
}

#[cfg(test)]
mod scope_split_tests {
    use super::{is_global_only_template, parse_template_overrides, template_index_by_name, variant_hint};
    use streamscope_client_templates::{ClientProfileTemplate, TemplateFormat, TemplateKind};

    fn tmpl(filename: Option<&str>, project_filename: Option<&str>) -> ClientProfileTemplate {
        ClientProfileTemplate {
            kind: TemplateKind::Combined,
            protocol: None,
            route_tag: None,
            filename: filename.map(str::to_string),
            project_filename: project_filename.map(str::to_string),
            format: TemplateFormat::Yaml,
            title: "t".into(),
            instructions: None,
            mcp_auth_mode: Default::default(),
            key_delivery: Default::default(),
            companions: Vec::new(),
            keyed_arrays: Default::default(),
            local_mcp: Default::default(),
            body: String::new(),
        }
    }

    fn variant(
        kind: TemplateKind,
        protocol: Option<&str>,
        auth: streamscope_client_templates::McpAuthMode,
        filename: Option<&str>,
    ) -> ClientProfileTemplate {
        ClientProfileTemplate {
            kind,
            protocol: protocol.map(str::to_string),
            mcp_auth_mode: auth,
            title: format!("{kind:?} {protocol:?} {auth:?} {filename:?}"),
            body: "key: {{api_key}}\n".into(),
            ..tmpl(filename, None)
        }
    }

    /// Mirrors the shapes the seeds ship: two LLM protocols, an OAuth sibling,
    /// a print-only snippet sharing a name with a file-writing one, MCP-only.
    fn variants() -> Vec<ClientProfileTemplate> {
        use streamscope_client_templates::McpAuthMode::{SpecOauth, Static};
        vec![
            variant(TemplateKind::Combined, Some("chat_completions"), Static, Some("~/.c")),
            variant(TemplateKind::Llm, Some("anthropic_messages"), Static, None),
            variant(TemplateKind::Combined, Some("anthropic_messages"), Static, Some("~/.c")),
            variant(TemplateKind::Combined, Some("anthropic_messages"), SpecOauth, Some("~/.c")),
            variant(TemplateKind::Mcp, None, Static, Some("~/.c")),
        ]
    }

    fn plan(client_id: &str, template_index: usize, mode: super::Mode) -> super::ClientPlan {
        super::ClientPlan {
            client_id: client_id.into(),
            template_index,
            mode,
            provider_id: None,
            mcp_server_ids: Vec::new(),
            mcp_local_server_ids: Vec::new(),
        }
    }

    fn recorded(client_id: &str, template_index: usize, mode: &str) -> crate::state::ManagedClient {
        serde_json::from_value(serde_json::json!({
            "client_id": client_id,
            "template_index": template_index,
            "mode": mode,
            "provider_id": null,
            "key_id": null,
            "mcp_server_ids": [], "mcp_local_servers": [], "mcp_local_commands": {},
            "files": [],
            "last_provisioned": "2026-10-01T00:00:00Z",
            "launch_command": null,
        }))
        .expect("managed client")
    }

    #[test]
    fn a_reprovision_keeps_the_recorded_variant() {
        use super::Mode::Gateway;
        // [chat, anthropic snippet, anthropic, anthropic-oauth, mcp]: the default is 0.
        let t = variants();
        let templates = |_: &str| Some(t.as_slice());
        let keep = |plans: &mut [super::ClientPlan], prev: &[crate::state::ManagedClient]| {
            super::keep_recorded_variants(plans, prev, &Default::default(), templates);
        };
        let prev = [
            recorded("same-mode", 2, "gateway"),
            recorded("other-mode", 2, "byok"),
            recorded("mcp-only", 4, "gateway"),
            recorded("gone", 99, "gateway"),
        ];
        let mut plans = [
            plan("same-mode", 0, Gateway),  // recorded LLM config, same mode → kept
            plan("other-mode", 0, Gateway), // recorded in another mode → the default
            plan("mcp-only", 0, Gateway),   // recorded MCP-only, LLM run → the default
            plan("gone", 0, Gateway),       // recorded index no longer exists → the default
            plan("new", 0, Gateway),        // not recorded → the default
        ];
        keep(&mut plans, &prev);
        assert_eq!(plans.map(|p| p.template_index), [2, 0, 0, 0, 0]);

        // A recorded config without the pick's project form is not kept.
        let mut other_form = t.clone();
        other_form[2].project_filename = Some("p.json".into());
        let mut plans = [plan("same-mode", 0, Gateway)];
        super::keep_recorded_variants(&mut plans, &prev, &Default::default(), |_| {
            Some(other_form.as_slice())
        });
        assert_eq!(plans[0].template_index, 0);

        // And back: an MCP-only run never takes a recorded LLM config.
        let mut plans = [plan("same-mode", 4, Gateway)];
        keep(&mut plans, &prev);
        assert_eq!(plans[0].template_index, 4);

        // An explicit --template always wins over the record.
        let mut plans = [plan("same-mode", 0, Gateway)];
        let overrides = [("same-mode".to_string(), "chat".to_string())].into();
        super::keep_recorded_variants(&mut plans, &prev, &overrides, templates);
        assert_eq!(plans[0].template_index, 0);

        // A BYOK record is kept against its own pass-through only: another may
        // speak another protocol.
        let (a, b) = (uuid::Uuid::from_u128(1), uuid::Uuid::from_u128(2));
        let mut byok_prev = recorded("byok", 2, "byok");
        byok_prev.provider_id = Some(a);
        let byok_plan = |provider| super::ClientPlan { provider_id: Some(provider), ..plan("byok", 0, super::Mode::Byok) };
        let mut plans = [byok_plan(a), byok_plan(b)];
        keep(&mut plans, std::slice::from_ref(&byok_prev));
        assert_eq!(plans.map(|p| p.template_index), [2, 0]);
    }

    #[test]
    fn a_template_override_picks_by_variant_name() {
        let t = variants();
        assert_eq!(template_index_by_name("x", &t, "chat").unwrap(), 0);
        // The print-only snippet comes first, but the file-writing one wins.
        assert_eq!(template_index_by_name("x", &t, "anthropic").unwrap(), 2);
        assert_eq!(template_index_by_name("x", &t, "anthropic-oauth").unwrap(), 3);
        assert_eq!(template_index_by_name("x", &t, "mcp").unwrap(), 4);
        // A name shared only by print-only snippets still resolves (the first).
        let snippets = vec![
            variant(TemplateKind::Llm, Some("chat_completions"), Default::default(), None),
            variant(TemplateKind::Llm, Some("chat_completions"), Default::default(), None),
        ];
        assert_eq!(template_index_by_name("x", &snippets, "chat").unwrap(), 0);
    }

    #[test]
    fn a_template_override_refuses_what_the_client_does_not_ship() {
        let t = variants();
        for bad in ["gemini", "responses", "0", "2", "Chat", ""] {
            let err = template_index_by_name("x", &t, bad).unwrap_err().to_string();
            assert!(
                err.contains("chat, anthropic, anthropic-oauth, mcp"),
                "{bad:?} must be refused with the variant list, got: {err}"
            );
        }
        assert!(parse_template_overrides(&["opencode".into()]).is_err());
        assert_eq!(
            parse_template_overrides(&["opencode=anthropic".into()]).unwrap()["opencode"],
            "anthropic"
        );
    }

    #[test]
    fn the_variant_hint_names_the_pick_and_the_others() {
        let t = variants();
        let hint = variant_hint("x", &t, &t[0]).expect("several LLM variants → a hint");
        assert!(hint.contains(&t[0].title), "{hint}");
        assert!(hint.ends_with("(switch: --template x=anthropic)"), "{hint}");
        // From the other side the OpenAI-compatible one is offered, never the
        // chosen protocol's own OAuth sibling.
        let back = variant_hint("x", &t, &t[2]).expect("a hint");
        assert!(back.ends_with("(switch: --template x=chat)"), "{back}");
        // No protocol choice to make → no line: one protocol plus its OAuth
        // sibling (claude-code's shape), a print-only alternative, MCP-only.
        assert!(variant_hint("x", &t[2..4], &t[2]).is_none());
        assert!(variant_hint("x", &t[..2], &t[0]).is_none());
        assert!(variant_hint("x", &t, &t[4]).is_none());
    }

    #[test]
    fn classifies_templates_by_scope() {
        // Global-only: writes a file, no project-local form → routed to global.
        assert!(is_global_only_template(&tmpl(Some("~/.continue/config.yaml"), None)));
        // Project-capable: has a project-local destination → follows scope.
        assert!(!is_global_only_template(&tmpl(
            Some("~/.claude/settings.json"),
            Some(".claude/settings.json")
        )));
        // Print-only (curl / env snippet): not a file, so not global-only.
        assert!(!is_global_only_template(&tmpl(None, None)));
    }

    /// Continue ships a single global config and no project-local form, so a
    /// project-scoped `provision` must route it to the global scope rather than
    /// skip it. Guards the seed against a change that would silently alter that.
    #[test]
    fn continue_seed_is_global_only() {
        let path =
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../seeds/client_profiles/continue.json");
        let profile: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).expect("read continue seed"))
                .expect("continue seed parses");
        let combined = profile["templates"]
            .as_array()
            .expect("templates array")
            .iter()
            .find(|t| t["kind"] == "combined")
            .expect("continue has a combined template");
        assert!(combined["filename"].as_str().is_some(), "continue writes a file");
        assert!(
            combined.get("project_filename").and_then(|v| v.as_str()).is_none(),
            "continue has no project-local form → global-only"
        );
    }
}

#[cfg(test)]
mod splice_tests {
    use super::*;
    use streamscope_client_templates::{
        ClientProfileTemplate, TemplateFormat, TemplateKind, UPSTREAM_API_KEY_PLACEHOLDER,
    };

    /// A bundle client carries the warnings the gateway sends; `warnings` is
    /// part of the bundle's shape, so a bundle without it is refused.
    #[test]
    fn a_bundle_client_carries_its_warnings() {
        let mut client = serde_json::json!({
            "client_id": "cursor",
            "label": "Cursor",
            "template_index": 0,
            "template": {"kind": "mcp", "format": "json", "title": "Cursor", "body": "{}"},
            "placeholders": {},
            "rendered_body": "{}",
            "rendered_instructions": null,
            "launch_command": null,
        });
        assert!(serde_json::from_value::<crate::api::ClientBundle>(client.clone()).is_err());
        client["warnings"] = serde_json::json!([]);
        let cb: crate::api::ClientBundle = serde_json::from_value(client.clone()).expect("parses with no warnings");
        assert!(cb.warnings.is_empty());
        client["warnings"] = serde_json::json!([{"slug": "gh", "reason": "sign_in_cannot_reach_fwd", "message": "m"}]);
        let cb: crate::api::ClientBundle = serde_json::from_value(client).expect("parses with warnings");
        assert_eq!(cb.warnings.len(), 1);
    }

    /// Each MCP server the gateway left out is one line naming the client and
    /// carrying the gateway's message; none left out prints nothing.
    #[test]
    fn every_left_out_mcp_server_is_one_warning_line() {
        let warnings: Vec<crate::api::McpServerWarning> = serde_json::from_value(serde_json::json!([
            {"virtual_server_id": "00000000-0000-0000-0000-000000000001", "slug": "gh",
             "reason": "sign_in_cannot_reach_fwd", "message": "MCP server 'gh' was left out: …"},
            {"virtual_server_id": "00000000-0000-0000-0000-000000000002", "slug": "jira",
             "reason": "pass_through_key_not_accepted", "message": "MCP server 'jira' was left out: …"},
            {"virtual_server_id": null, "local_server_id": "00000000-0000-0000-0000-000000000003", "slug": "fs",
             "reason": "local_server_project_only", "message": "local MCP server 'fs' is not in this config: …"},
        ]))
        .expect("the server's shape deserializes");
        let all = vec![
            "warning: claude-code: MCP server 'gh' was left out: …".to_string(),
            "warning: claude-code: MCP server 'jira' was left out: …".to_string(),
            "warning: claude-code: local MCP server 'fs' is not in this config: …".to_string(),
        ];
        assert_eq!(super::mcp_warning_lines("claude-code", &warnings, false), all);
        // A project write carries the local server: only that line goes.
        assert_eq!(super::mcp_warning_lines("claude-code", &warnings, true), all[..2].to_vec());
        assert!(super::mcp_warning_lines("claude-code", &[], false).is_empty());
    }

    fn local_bundle(form: &str, project_filename: Option<&str>) -> ClientBundle {
        use streamscope_client_templates::mcp_local_server_item;
        let local = mcp_local_server_item(
            "fs",
            "Files",
            None,
            "npx",
            &["-y".to_string(), "pkg@1.0.0".to_string(), "two words".to_string()],
            &[("LOG".to_string(), Some("info".to_string())), ("TOKEN".to_string(), None)],
        );
        let remote = BTreeMap::from([("slug".to_string(), Value::String("web".into()))]);
        let mut template = serde_json::json!({
            "kind": "mcp", "format": "json", "title": "T", "body": "{}", "local_mcp": form,
        });
        if let Some(p) = project_filename {
            template["filename"] = "~/.c.json".into();
            template["project_filename"] = p.into();
        }
        serde_json::from_value(serde_json::json!({
            "client_id": "c", "label": "C", "template_index": 0,
            "template": template,
            "placeholders": {"mcp_servers": Value::List(vec![remote, local])},
            "rendered_body": "{}", "rendered_instructions": null, "launch_command": null, "warnings": [],
        }))
        .expect("a bundle client")
    }

    /// A project whose client config is written through [`provision_one`]:
    /// the template writes each MCP server under `mcpServers`, a local one as
    /// its command line, and names it in the `enabled` list (string entries).
    struct LocalProject {
        dir: PathBuf,
        paths: Paths,
    }

    const LOCAL_BODY: &str = r#"{
  "provider": {"key": "sk-fixed", "model": "m"},
  "mcpServers": {
{{#each mcp_servers}}    "{{slug}}": {{#if local}}{"command": "{{command}}", "args": [{{#each args}}"{{value}}"{{#unless @last}}, {{/unless}}{{/each}}], "env": { {{#each env}}"{{name}}": "{{value}}"{{#unless @last}}, {{/unless}}{{/each}} }}{{else}}{"url": "https://gw/{{slug}}"}{{/if}}{{#unless @last}},{{/unless}}
{{/each}}  },
  "enabled": [{{#each mcp_servers}}"{{slug}}"{{#unless @last}}, {{/unless}}{{/each}}]
}
"#;

    impl LocalProject {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("ss-local-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let dir = dunce::canonicalize(&dir).unwrap();
            let paths = Paths::for_scope(&ManifestScope::Project(dir.clone())).unwrap();
            paths.ensure().unwrap();
            Self { dir, paths }
        }

        fn config(&self) -> PathBuf {
            self.dir.join(".c.json")
        }

        fn read(&self) -> serde_json::Value {
            serde_json::from_str(&std::fs::read_to_string(self.config()).unwrap()).unwrap()
        }

        /// A bundle client carrying the gateway server `web` and the local
        /// servers `local` (slugs).
        fn bundle(&self, local: &[&str]) -> ClientBundle {
            use streamscope_client_templates::mcp_local_server_item;
            let mut servers = vec![BTreeMap::from([("slug".to_string(), Value::String("web".into()))])];
            for slug in local {
                servers.push(mcp_local_server_item(
                    slug,
                    slug,
                    None,
                    "npx",
                    &["-y".to_string(), format!("{slug}@1.0.0")],
                    &[("LOG".to_string(), Some("info".to_string())), ("TOKEN".to_string(), None)],
                ));
            }
            let mut cb: ClientBundle = serde_json::from_value(serde_json::json!({
                "client_id": "c", "label": "C", "template_index": 0,
                "template": {
                    "kind": "mcp", "format": "json", "title": "T", "body": LOCAL_BODY, "local_mcp": "config",
                    "filename": "~/.c.json", "project_filename": ".c.json",
                    "keyed_arrays": {"/enabled": streamscope_client_templates::STRING_ENTRIES},
                },
                "placeholders": {"mcp_servers": Value::List(servers)},
                "rendered_body": "", "rendered_instructions": null, "launch_command": null, "warnings": [],
            }))
            .expect("a bundle client");
            cb.rendered_body = render(&cb.template.body, cb.template.format, &cb.placeholders).unwrap();
            cb
        }

        /// Write `local` for the client as recorded in `ws`, and record it.
        fn provision(&self, ws: &mut WorkspaceManifest, local: &[&str], stamp: &str) {
            let cb = self.bundle(local);
            let records = crate::state::FileRecords { ws, others: &[] };
            let mode = WriteMode { dry_run: false, print: false, verbose: false };
            let mut m = provision_one(&cb, None, &mode, stamp, &records, &self.paths, &mut Vec::new())
                .unwrap()
                .expect("a written client");
            let ids: Vec<uuid::Uuid> = (0..local.len()).map(|i| uuid::Uuid::from_u128(i as u128 + 1)).collect();
            let slugs: BTreeMap<uuid::Uuid, String> =
                ids.iter().copied().zip(local.iter().map(|s| s.to_string())).collect();
            m.mcp_local_servers = managed_local(&ids, &slugs, std::mem::take(&mut m.mcp_local_servers));
            m.mcp_local_commands = local_commands_written(&cb, true);
            ws.clients.retain(|c| c.client_id != "c");
            ws.clients.push(m);
        }

        fn paste(&self, placeholder_of: &str, value: &str) {
            let text = std::fs::read_to_string(self.config()).unwrap();
            let sentinel = format!("<paste-your-{placeholder_of}-token-here>");
            assert!(text.contains(&sentinel), "{text}");
            std::fs::write(self.config(), text.replace(&sentinel, value)).unwrap();
        }
    }

    impl Drop for LocalProject {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// Withdrawing a local server from a client removes that server's entry
    /// — from the map and from the list of names, with the value the developer
    /// pasted into it — and nothing else: the other local server and its
    /// pasted value, the gateway server, the provider and key, and the
    /// developer's own settings are as they were; the client keeps its record,
    /// less that server; and a later write of the remaining selection changes
    /// nothing. A preview changes neither the file nor the record.
    #[test]
    fn withdrawing_a_local_server_removes_its_entry_and_nothing_else() {
        let id = uuid::Uuid::from_u128;
        let project = LocalProject::new("withdraw");
        std::fs::write(project.config(), r#"{"theme": "dark", "mcpServers": {"mine": {"command": "my-server"}}}"#).unwrap();
        let mut ws = WorkspaceManifest::default();
        project.provision(&mut ws, &["fs", "git"], "20261010T000000Z");
        for server in &ws.clients[0].mcp_local_servers {
            let roots: Vec<(&str, Option<&str>, bool)> = server
                .entries
                .iter()
                .map(|e| (e.root.path.as_str(), e.root.entry.as_ref().map(|x| x.id.as_str()), e.created))
                .collect();
            let map_root = format!("/mcpServers/{}", server.slug);
            assert_eq!(roots, vec![("/enabled", Some(server.slug.as_str()), true), (map_root.as_str(), None, true)]);
        }
        project.paste("fs", "fs-secret");
        project.paste("git", "git-secret");
        let before = project.read();

        let gone = [(id(1), WithdrawReason::Deselected)];
        // A preview says it and changes nothing.
        assert!(!withdraw_local_servers(&mut ws.clients[0], &gone, &[], "20261010T000001Z", &project.paths, true).unwrap());
        assert_eq!(project.read(), before);
        assert_eq!(ws.clients[0].mcp_local_servers.len(), 2);

        assert!(withdraw_local_servers(&mut ws.clients[0], &gone, &[], "20261010T000002Z", &project.paths, false).unwrap());
        let v = project.read();
        assert!(v["mcpServers"].get("fs").is_none() && !v.to_string().contains("fs-secret"), "{v}");
        assert_eq!(v["enabled"], serde_json::json!(["web", "git"]));
        let mut expected = before.clone();
        expected["mcpServers"].as_object_mut().unwrap().remove("fs");
        expected["enabled"] = serde_json::json!(["web", "git"]);
        assert_eq!(v, expected, "something besides the server's entry changed");
        assert_eq!(v["provider"], serde_json::json!({"key": "sk-fixed", "model": "m"}));
        assert_eq!(v["mcpServers"]["git"]["env"]["TOKEN"], "git-secret");
        // The record: the client stays, less the server and what it owned.
        let client = &ws.clients[0];
        assert_eq!(client.mcp_local_servers.iter().map(|s| s.slug.as_str()).collect::<Vec<_>>(), vec!["git"]);
        assert!(!client.mcp_local_commands.contains_key("fs") && client.mcp_local_commands.contains_key("git"));
        assert!(client.files[0].owned.iter().all(|o| !o.path.starts_with("/mcpServers/fs")), "{:?}", client.files[0].owned);
        // Nothing to withdraw twice; and the remaining selection writes back unchanged.
        assert!(!withdraw_local_servers(&mut ws.clients[0], &gone, &[], "20261010T000003Z", &project.paths, false).unwrap());
        project.provision(&mut ws, &["git"], "20261010T000004Z");
        assert_eq!(project.read(), v);

        // The last one too: its entry goes, the client and the rest stay.
        assert!(withdraw_local_servers(&mut ws.clients[0], &[(id(1), WithdrawReason::NotOffered)], &[], "20261010T000005Z", &project.paths, false).unwrap());
        let v = project.read();
        assert!(!v.to_string().contains("git"), "{v}");
        assert_eq!(v["mcpServers"]["web"]["url"], "https://gw/web");
        assert_eq!(v["mcpServers"]["mine"], serde_json::json!({"command": "my-server"}));
        assert_eq!((v["provider"]["key"].as_str(), v["theme"].as_str()), (Some("sk-fixed"), Some("dark")));
        assert!(ws.clients[0].mcp_local_servers.is_empty() && ws.clients.len() == 1);
    }

    /// An entry the file held BEFORE the server was first written there is
    /// the developer's: the write merges into it and records that it was not
    /// created, and a withdrawal takes out only the leaves written and left
    /// unchanged — their own key and the value they pasted stay.
    #[test]
    fn an_entry_the_file_already_had_is_never_removed_whole() {
        let project = LocalProject::new("preexisting");
        std::fs::write(
            project.config(),
            r#"{"mcpServers": {"fs": {"command": "my-fs", "cwd": "/srv"}}, "enabled": ["fs"]}"#,
        )
        .unwrap();
        let mut ws = WorkspaceManifest::default();
        project.provision(&mut ws, &["fs"], "20261010T000000Z");
        let created: Vec<bool> = ws.clients[0].mcp_local_servers[0].entries.iter().map(|e| e.created).collect();
        assert_eq!(created, vec![false, false]);
        project.paste("fs", "fs-secret");

        let gone = [(uuid::Uuid::from_u128(1), WithdrawReason::NoForm)];
        assert!(withdraw_local_servers(&mut ws.clients[0], &gone, &[], "20261010T000001Z", &project.paths, false).unwrap());
        let v = project.read();
        assert_eq!(v["mcpServers"]["fs"], serde_json::json!({"cwd": "/srv", "env": {"TOKEN": "fs-secret"}}), "{v}");
        // The name we wrote is unchanged, so it goes; theirs was the same
        // string and the list held it once.
        assert_eq!(v["enabled"], serde_json::json!(["web"]));
        assert_eq!(v["provider"]["key"], "sk-fixed");
    }

    /// A withdrawal rewrites only a file of the job's own scope: the same
    /// record under the global job (a project's file is not a home-directory
    /// path) leaves the file exactly as it is, while the selection still
    /// drops the server. Positive control: the project's own job removes it.
    #[test]
    fn a_withdrawal_rewrites_only_a_file_of_the_jobs_scope() {
        let project = LocalProject::new("scope");
        let mut ws = WorkspaceManifest::default();
        project.provision(&mut ws, &["fs"], "20261010T000000Z");
        project.paste("fs", "fs-secret");
        let before = std::fs::read_to_string(project.config()).unwrap();
        let gone = [(uuid::Uuid::from_u128(1), WithdrawReason::NotOffered)];

        let global = Paths::for_scope(&ManifestScope::Global).unwrap();
        let mut elsewhere = ws.clients[0].clone();
        assert!(withdraw_local_servers(&mut elsewhere, &gone, &[], "20261010T000001Z", &global, false).unwrap());
        assert_eq!(std::fs::read_to_string(project.config()).unwrap(), before);
        assert!(elsewhere.mcp_local_servers.is_empty());

        assert!(withdraw_local_servers(&mut ws.clients[0], &gone, &[], "20261010T000002Z", &project.paths, false).unwrap());
        let v = project.read();
        assert!(v["mcpServers"].get("fs").is_none() && !v.to_string().contains("fs-secret"), "{v}");
    }

    /// Which recorded local servers leave a selection, and why: one the
    /// workspace no longer hands out, one lost with the template's form, one
    /// this run took out — and, when what the workspace hands out is not
    /// known, never "no longer offered".
    #[test]
    fn a_local_server_leaves_a_selection_for_one_of_three_reasons() {
        let id = uuid::Uuid::from_u128;
        let recorded = managed_with_local("cursor", &[(1, "fs"), (2, "git"), (3, "db")]).mcp_local_servers;
        let offered = BTreeSet::from([id(1), id(2)]);
        // Everything kept: nothing leaves.
        assert!(local_withdrawals(&recorded, &[id(1), id(2), id(3)], Some(&offered), false).is_empty());
        // `db` is no longer offered; `git` was taken out by the run.
        assert_eq!(
            local_withdrawals(&recorded, &[id(1)], Some(&offered), false),
            vec![(id(2), WithdrawReason::Deselected), (id(3), WithdrawReason::NotOffered)]
        );
        // The form went: every server still offered leaves for that reason.
        assert_eq!(
            local_withdrawals(&recorded, &[], Some(&offered), true),
            vec![(id(1), WithdrawReason::NoForm), (id(2), WithdrawReason::NoForm), (id(3), WithdrawReason::NotOffered)]
        );
        // What is offered is unknown: a missing server is not called withdrawn.
        assert_eq!(local_withdrawals(&recorded, &[id(1), id(2)], None, false), vec![(id(3), WithdrawReason::Deselected)]);
        let texts: BTreeSet<&str> =
            [WithdrawReason::NotOffered, WithdrawReason::NoForm, WithdrawReason::Deselected].iter().map(|r| r.text()).collect();
        assert_eq!(texts.len(), 3);
    }

    /// What a run gives each client, by kind and by flag. With no flag a
    /// client keeps what it was provisioned with and is still offered —
    /// gateway servers and local ones alike; a named or ticked set replaces
    /// that kind for the run; a client with no record gets nothing by default.
    #[test]
    fn a_client_keeps_its_recorded_servers_of_each_kind_unless_the_run_says_otherwise() {
        let id = uuid::Uuid::from_u128;
        let server = |n: u128, slug: &str| -> crate::api::McpLocalServer {
            serde_json::from_value(serde_json::json!({
                "id": id(n), "slug": slug, "name": slug, "launch": {"command": "npx", "env": []}, "command_line": "npx",
            }))
            .unwrap()
        };
        // ---- gateway servers ----
        let recorded = [id(2), id(1), id(9)];
        // No flag, nothing read: the record as it stands.
        let untouched = McpChoice { offered: None, chosen: None };
        assert_eq!(untouched.for_client(&recorded), (vec![id(1), id(2), id(9)], 0));
        assert_eq!(untouched.for_client(&[]), (vec![], 0));
        // No flag, the offer read: the recorded ones still offered.
        let kept = McpChoice { offered: Some(BTreeSet::from([id(1), id(2), id(3)])), chosen: None };
        assert_eq!(kept.for_client(&recorded), (vec![id(1), id(2)], 1));
        // `--mcp` / `--all-mcp` / the prompt: that set, whatever was recorded.
        let named = McpChoice { offered: None, chosen: Some(vec![id(3)]) };
        assert_eq!(named.for_client(&recorded), (vec![id(3)], 0));
        assert_eq!(named.for_client(&[]), (vec![id(3)], 0));
        // `--no-mcp`: none.
        let none = McpChoice { offered: None, chosen: Some(Vec::new()) };
        assert_eq!(none.for_client(&recorded), (vec![], 0));

        // ---- local servers ----
        let recorded = managed_with_local("cursor", &[(2, "git"), (1, "fs"), (9, "gone")]).mcp_local_servers;
        let offered = vec![server(1, "fs"), server(2, "git"), server(3, "db")];
        let kept = LocalChoice { offered: offered.clone(), offered_read: true, chosen: None, picked_for: None };
        assert_eq!(kept.for_client("cursor", &recorded), vec![id(1), id(2)]);
        assert!(kept.for_client("cursor", &[]).is_empty());
        // The offer not read: the record as it stands.
        let unread = LocalChoice { offered: Vec::new(), offered_read: false, chosen: None, picked_for: None };
        assert_eq!(unread.for_client("cursor", &recorded), vec![id(1), id(2), id(9)]);
        // Named on the command line: the set, for every client.
        let named = LocalChoice { offered: offered.clone(), offered_read: true, chosen: Some(vec![id(3)]), picked_for: None };
        assert_eq!(named.for_client("cursor", &recorded), vec![id(3)]);
        assert_eq!(named.for_client("zed", &[]), vec![id(3)]);
        // Ticked in the prompt: only for the clients the prompt named.
        let picked = LocalChoice {
            offered: offered.clone(),
            offered_read: true,
            chosen: Some(vec![id(3)]),
            picked_for: Some(vec!["cursor".to_string()]),
        };
        assert_eq!(picked.for_client("cursor", &[]), vec![id(3)]);
        assert!(picked.for_client("zed", &[]).is_empty());
        // `--no-local-mcp` / `--no-mcp`: none.
        let none = LocalChoice { offered: Vec::new(), offered_read: false, chosen: Some(Vec::new()), picked_for: None };
        assert!(none.for_client("cursor", &recorded).is_empty());

        // The interactive pick is one selection for the run: ticked is what
        // ANY selected client has (the union the caller passes), all when
        // nothing is recorded; with several clients the question names them.
        let base = "Which local MCP servers (started on this machine) should I add?";
        let union = BTreeSet::from([id(1), id(3), id(9)]);
        let two = ["claude-desktop".to_string(), "cursor".to_string()];
        assert_eq!(
            super::local_pick(&offered, &union, &two),
            (format!("{base} One selection, for: claude-desktop, cursor"), vec![0, 2])
        );
        assert_eq!(super::local_pick(&offered, &union, &two[..1]), (base.to_string(), vec![0, 2]));
        assert_eq!(super::local_pick(&offered, &BTreeSet::new(), &two[..1]), (base.to_string(), vec![0, 1, 2]));
    }

    /// The launch recorded for a client is the whole one — the administrator's
    /// environment values first — of each local server its written config
    /// carries: every one for a template that writes them anywhere, none
    /// outside a project for one that writes them only in a project's file,
    /// none for a template with no form — and never a gateway server.
    #[test]
    fn the_recorded_local_commands_are_the_ones_the_written_config_carries() {
        let want = BTreeMap::from([("fs".to_string(), "LOG=info npx -y pkg@1.0.0 'two words'".to_string())]);
        assert_eq!(super::local_commands_written(&local_bundle("config", None), false), want);
        assert_eq!(super::local_commands_written(&local_bundle("config", Some(".c.json")), true), want);
        assert_eq!(super::local_commands_written(&local_bundle("project", Some(".c.json")), true), want);
        assert!(super::local_commands_written(&local_bundle("project", Some(".c.json")), false).is_empty());
        // A project job writes a client with no project form at its global path.
        assert!(super::local_commands_written(&local_bundle("project", None), true).is_empty());
        assert!(super::local_commands_written(&local_bundle("none", None), false).is_empty());
    }

    /// `sync` prints a local server's launch when it is new or changed — a
    /// changed environment value included — and nothing for one written as
    /// before.
    #[test]
    fn only_an_added_or_changed_local_command_is_printed() {
        let map = |pairs: &[(&str, &str)]| -> BTreeMap<String, String> {
            pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
        };
        let before = map(&[("fs", "LOG=info npx -y pkg@1.0.0"), ("git", "uvx git==1.0")]);
        assert!(super::changed_local_command_lines(Some(&before), &before).is_empty());
        assert_eq!(
            super::changed_local_command_lines(Some(&before), &map(&[("fs", "LOG=info npx -y pkg@2.0.0"), ("git", "uvx git==1.0")])),
            vec!["local MCP server 'fs' now runs: LOG=info npx -y pkg@2.0.0".to_string()]
        );
        // The arguments as before, one environment value changed.
        assert_eq!(
            super::changed_local_command_lines(Some(&before), &map(&[("fs", "LOG=debug npx -y pkg@1.0.0"), ("git", "uvx git==1.0")])),
            vec!["local MCP server 'fs' now runs: LOG=debug npx -y pkg@1.0.0".to_string()]
        );
        assert_eq!(
            super::changed_local_command_lines(None, &map(&[("fs", "npx -y pkg@1.0.0")])),
            vec!["local MCP server 'fs' now runs: npx -y pkg@1.0.0".to_string()]
        );
        // One removed prints nothing here: nothing new runs.
        assert!(super::changed_local_command_lines(Some(&before), &map(&[("git", "uvx git==1.0")])).is_empty());
    }

    /// A template of `kind` (and LLM `protocol`) with the local form `local_mcp`.
    fn tpl(kind: &str, protocol: Option<&str>, local_mcp: &str, title: &str) -> ClientProfileTemplate {
        serde_json::from_value(serde_json::json!({
            "kind": kind, "protocol": protocol, "format": "json", "title": title,
            "filename": "~/.x.json", "body": "{}", "local_mcp": local_mcp,
        }))
        .expect("a template")
    }

    fn managed_with_local(client_id: &str, local: &[(u128, &str)]) -> crate::state::ManagedClient {
        serde_json::from_value(serde_json::json!({
            "client_id": client_id, "template_index": 0, "mode": "gateway", "provider_id": null, "key_id": null,
            "mcp_server_ids": [],
            "mcp_local_servers": local.iter().map(|(id, slug)| serde_json::json!({"id": uuid::Uuid::from_u128(*id), "slug": slug, "entries": []})).collect::<Vec<_>>(),
            "mcp_local_commands": {}, "files": [], "last_provisioned": "2026-10-01T00:00:00Z", "launch_command": null,
        }))
        .expect("a managed client")
    }

    /// A sync asks for the local servers the workspace still offers; a client
    /// the run does not cover keeps its selection, withdrawn server included;
    /// and when what the workspace offers could not be read, every recorded
    /// server is kept.
    #[test]
    fn a_sync_drops_the_local_servers_the_workspace_no_longer_offers() {
        let id = uuid::Uuid::from_u128;
        let clients = vec![
            managed_with_local("cursor", &[(1, "fs"), (2, "git")]),
            managed_with_local("codex", &[(2, "git"), (3, "db")]),
            managed_with_local("zed", &[]),
        ];
        let offered = BTreeMap::from([(id(1), "fs".to_string()), (id(3), "db".to_string())]);
        let all: HashSet<String> = ["cursor", "codex", "zed"].iter().map(|s| s.to_string()).collect();
        let kept = super::split_offered_local(&clients, &all, Some(&offered));
        assert_eq!(kept["cursor"], vec![id(1)]);
        assert_eq!(kept["codex"], vec![id(3)]);
        assert!(kept["zed"].is_empty());
        // Everything still offered: nothing is dropped.
        let everything = BTreeMap::from([(id(1), "fs".into()), (id(2), "git".into()), (id(3), "db".into())]);
        assert_eq!(super::split_offered_local(&clients, &all, Some(&everything))["cursor"], vec![id(1), id(2)]);
        // A run covering cursor alone leaves codex's selection as recorded.
        let only: HashSet<String> = ["cursor".to_string()].into_iter().collect();
        let kept = super::split_offered_local(&clients, &only, Some(&offered));
        assert_eq!(kept["cursor"], vec![id(1)]);
        assert_eq!(kept["codex"], vec![id(2), id(3)]);
        // The offer unknown: nothing is dropped, whatever it would have said.
        let kept = super::split_offered_local(&clients, &all, None);
        assert_eq!(kept["cursor"], vec![id(1), id(2)]);
        assert_eq!(kept["codex"], vec![id(2), id(3)]);
    }

    /// A client is left alone — nothing asked of the gateway, nothing written
    /// — exactly when its template is MCP-only and its selection is empty.
    /// Any other client is rendered: one with a server of either kind, one on
    /// a setup that holds a provider, one whose template could not be read.
    #[test]
    fn a_client_is_left_alone_only_on_an_mcp_only_template_with_no_server() {
        let id = uuid::Uuid::from_u128;
        let group = |mcp: &[u128], local: &[u128]| Group {
            client_id: "cursor".into(),
            mode: Mode::Gateway,
            provider_id: None,
            mcp_server_ids: mcp.iter().map(|n| id(*n)).collect(),
            mcp_local_server_ids: local.iter().map(|n| id(*n)).collect(),
            indices: vec![0],
        };
        let mcp = Some(TemplateKind::Mcp);
        assert!(super::nothing_to_write(mcp, &group(&[], &[])));
        assert!(!super::nothing_to_write(mcp, &group(&[9], &[])));
        assert!(!super::nothing_to_write(mcp, &group(&[], &[1])));
        for kind in [TemplateKind::Combined, TemplateKind::Llm, TemplateKind::Instructions] {
            assert!(!super::nothing_to_write(Some(kind), &group(&[], &[])), "{kind:?}");
        }
        assert!(!super::nothing_to_write(None, &group(&[], &[])));
        assert_eq!(
            super::nothing_to_write_line("cursor"),
            "cursor: no MCP server is selected for it — nothing to write"
        );
    }

    /// A local server goes only to a plan whose template has a form for one:
    /// the others lose it and are named, one line each; none is dropped
    /// silently and no plan is removed.
    #[test]
    fn a_plan_keeps_its_local_servers_only_where_its_template_writes_them() {
        let id = uuid::Uuid::from_u128;
        let templates = BTreeMap::from([
            ("writes".to_string(), vec![tpl("mcp", None, "config", "Writes")]),
            ("project".to_string(), vec![tpl("mcp", None, "project", "Project")]),
            ("plain".to_string(), vec![tpl("mcp", None, "none", "Plain setup")]),
        ]);
        let plan = |client: &str, local: &[u128]| super::ClientPlan {
            client_id: client.into(),
            template_index: 0,
            mode: super::Mode::Gateway,
            provider_id: None,
            mcp_server_ids: Vec::new(),
            mcp_local_server_ids: local.iter().map(|n| id(*n)).collect(),
        };
        let mut plans = vec![plan("writes", &[1, 2]), plan("project", &[1]), plan("plain", &[1, 2]), plan("unknown", &[1])];
        let slugs = BTreeMap::from([(id(1), "fs".to_string()), (id(2), "git".to_string())]);
        let lines = super::keep_local_where_writable(&mut plans, &slugs, |c| templates.get(c).map(Vec::as_slice));
        assert_eq!(plans.len(), 4);
        assert_eq!(plans[0].mcp_local_server_ids, vec![id(1), id(2)]);
        assert_eq!(plans[1].mcp_local_server_ids, vec![id(1)]);
        assert!(plans[2].mcp_local_server_ids.is_empty() && plans[3].mcp_local_server_ids.is_empty());
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[0].starts_with("warning: plain: local MCP server 'fs', local MCP server 'git' not added"), "{}", lines[0]);
        assert!(lines[0].contains("Plain setup"), "{}", lines[0]);
        assert!(lines[1].starts_with("warning: unknown: local MCP server 'fs' not added"), "{}", lines[1]);
        // Nothing selected: nothing said.
        let mut plans = vec![plan("plain", &[])];
        assert!(super::keep_local_where_writable(&mut plans, &slugs, |c| templates.get(c).map(Vec::as_slice)).is_empty());
    }

    /// A local server breaks the default pick only for a client with no LLM
    /// template in a run with no gateway server, and only toward an MCP
    /// template that has a form for one.
    #[test]
    fn a_local_server_never_moves_a_client_onto_a_template_that_cannot_write_it() {
        let mcp_plain = tpl("mcp", None, "none", "MCP");
        let mcp_local = tpl("mcp", None, "config", "MCP with local");
        let instr = tpl("instructions", None, "none", "Instructions");
        let llm = tpl("combined", Some("chat_completions"), "none", "LLM");
        // No LLM template: instructions without MCP, the MCP template with a
        // gateway server, and with a local server alone only the one that writes it.
        let gui = [instr.clone(), mcp_plain.clone(), mcp_local.clone()];
        assert_eq!(super::default_template_index(&gui, false, false), Some(0));
        assert_eq!(super::default_template_index(&gui, true, false), Some(1));
        assert_eq!(super::default_template_index(&gui, true, true), Some(1));
        assert_eq!(super::default_template_index(&gui, false, true), Some(2));
        let no_form = [instr.clone(), mcp_plain.clone()];
        assert_eq!(super::default_template_index(&no_form, false, true), Some(0));
        assert_eq!(super::default_template_index(std::slice::from_ref(&mcp_plain), false, true), None);
        // An LLM template wins whatever is selected.
        let cli = [mcp_local, llm];
        for (has_mcp, wants_local) in [(false, false), (true, false), (false, true), (true, true)] {
            assert_eq!(super::default_template_index(&cli, has_mcp, wants_local), Some(1));
        }
    }

    /// Each note is printed only for the kind of command it is true of: the
    /// runner notes for `npx` / `uvx`, the path note for a path, the engine
    /// note for a container engine, and for any other program only that it
    /// must be installed; the Windows note only on Windows, only for a runner.
    #[test]
    fn a_local_command_note_is_printed_only_for_what_it_describes() {
        let notes = |c: &str, windows: bool| super::local_command_notes(c, windows).join(" | ");
        for runner in ["npx", "uvx", "npx.exe"] {
            let n = notes(runner, false);
            assert!(n.contains("must be installed") && n.contains("native") && n.contains("in the image"), "{runner}: {n}");
            assert!(!n.contains("Windows"), "{runner}: {n}");
            assert!(notes(runner, true).contains("cmd /c npx"), "{runner}");
        }
        for typed in ["my-tool", "node", "python3"] {
            let n = notes(typed, true);
            assert!(n.contains("must be installed"), "{typed}: {n}");
            assert!(!n.contains("runner") && !n.contains("native") && !n.contains("Windows") && !n.contains("PyPI"), "{typed}: {n}");
        }
        let path = notes("/opt/tools/mcp", true);
        assert!(path.contains("path on this machine") && !path.contains("runner") && !path.contains("Windows"), "{path}");
        for engine in ["docker", "podman", "/usr/bin/docker", "docker.exe"] {
            let n = notes(engine, true);
            assert!(n.contains("container engine") && !n.contains("native") && !n.contains("runner"), "{engine}: {n}");
        }
        assert!(!notes("dockerize", false).contains("container engine"));
    }

    /// The optional proposal of local servers: read, it is offered as it is;
    /// unreadable, the run goes on with none and one line says why.
    #[test]
    fn an_unreadable_local_server_list_is_a_warning_and_no_proposal() {
        let (available, warning) = super::proposal_or_none(Err(anyhow::anyhow!("gateway error: 503")));
        assert!(available.is_empty());
        let warning = warning.expect("a line saying the list could not be read");
        assert!(warning.contains("503") && warning.contains("continuing without any"), "{warning}");

        let servers: Vec<crate::api::McpLocalServer> = serde_json::from_value(serde_json::json!([
            {"id": "00000000-0000-0000-0000-000000000001", "slug": "fs", "name": "Files",
             "command_line": "npx -y pkg@1.0.0", "launch": {"command": "npx", "env": []}},
        ]))
        .unwrap();
        let (available, warning) = super::proposal_or_none(Ok(servers));
        assert_eq!(available.len(), 1);
        assert!(warning.is_none());
    }

    #[test]
    fn a_provision_run_shows_each_whole_launch_and_what_the_developer_fills() {
        let servers: Vec<crate::api::McpLocalServer> = serde_json::from_value(serde_json::json!([
            {"id": "00000000-0000-0000-0000-000000000001", "slug": "fs", "name": "Files",
             "command_line": "LOG=info npx -y pkg@1.0.0",
             "launch": {"command": "npx", "args": ["-y", "pkg@1.0.0"],
                        "env": [{"name": "LOG", "value": "info"}, {"name": "TOKEN", "secret": true}]}},
        ]))
        .expect("the server's shape deserializes");
        let lines = super::local_server_notice_lines(&servers, false);
        assert_eq!(lines[0], "local MCP server 'fs' runs: LOG=info npx -y pkg@1.0.0");
        assert!(lines[1].contains("TOKEN") && !lines[1].contains("LOG"), "{}", lines[1]);
        assert!(lines.len() > 2 && !lines.iter().any(|l| l.contains("Windows")), "{lines:?}");
        assert!(super::local_server_notice_lines(&servers, true).iter().any(|l| l.contains("Windows")));
    }

    #[test]
    fn splice_replaces_only_the_gateway_sentinel() {
        // The gateway-key sentinel is replaced; the upstream-key sentinel
        // (left for the user in BYOK) is NOT — and the two don't alias even
        // though one is a near-prefix of the other.
        let body = format!(
            "base={API_KEY_PLACEHOLDER} upstream={UPSTREAM_API_KEY_PLACEHOLDER}"
        );
        let out = splice_key(&body, Some("vk-real"));
        assert_eq!(out, "base=vk-real upstream=<paste-your-upstream-api-key-here>");
        assert!(ensure_key_spliced(&out, Some("vk-real"), "test").is_ok());
    }

    #[test]
    fn ensure_key_spliced_catches_a_surviving_sentinel() {
        // A write path that forgot to splice (sentinel survives + a key was
        // available) is a hard error.
        let leaked = format!("token={API_KEY_PLACEHOLDER}");
        assert!(ensure_key_spliced(&leaked, Some("sk-x"), "leak").is_err());
        // With no key, the sentinel legitimately stays (print-only snippet).
        assert!(ensure_key_spliced(&leaked, None, "snippet").is_ok());
    }

    /// A template declaring one companion, used to exercise what the CLI adds
    /// on top of the shared renderer. The companion CONTENTS are the shared
    /// crate's business (byte-exact seed tests live there); these cover the
    /// two genuinely machine-local steps and the splice contract.
    fn tmpl_with_companion(path: &str, format: TemplateFormat, body: &str) -> ClientProfileTemplate {
        ClientProfileTemplate {
            kind: TemplateKind::Combined,
            protocol: None,
            route_tag: None,
            filename: None,
            project_filename: None,
            format: TemplateFormat::Yaml,
            title: "t".into(),
            instructions: None,
            mcp_auth_mode: Default::default(),
            key_delivery: Default::default(),
            companions: vec![streamscope_client_templates::CompanionTemplate {
                path: Some(path.into()),
                project_path: None,
                format,
                title: "c".into(),
                instructions: String::new(),
                body: body.into(),
            }],
            keyed_arrays: Default::default(),
            local_mcp: Default::default(),
            body: String::new(),
        }
    }

    fn gateway_phs() -> BTreeMap<String, Value> {
        BTreeMap::from([(
            "api_key".to_string(),
            Value::String(API_KEY_PLACEHOLDER.to_string()),
        )])
    }

    #[test]
    fn a_companion_goes_through_the_same_splice_pass_as_the_body() {
        let t = tmpl_with_companion("~/.tool/.env", TemplateFormat::Shell, "KEY={{api_key}}\n");
        let q = quirk_files(&t, &gateway_phs(), Some("sk-real"), None).unwrap();
        assert_eq!(q.len(), 1);
        assert_eq!(q[0].path.as_deref(), Some("~/.tool/.env"));
        let spliced = splice_key(&q[0].contents, Some("sk-real"));
        assert!(ensure_key_spliced(&spliced, Some("sk-real"), ".env").is_ok());
        assert!(spliced.starts_with("KEY=sk-real\n"));
        assert!(!spliced.contains(API_KEY_PLACEHOLDER));
    }

    #[test]
    fn a_byok_companion_leaves_the_upstream_sentinel_for_the_user() {
        let t = tmpl_with_companion("~/.tool/.env", TemplateFormat::Shell, "KEY={{api_key}}\n");
        let phs = BTreeMap::from([(
            "api_key".to_string(),
            Value::String(UPSTREAM_API_KEY_PLACEHOLDER.to_string()),
        )]);
        let q = quirk_files(&t, &phs, Some("vk-id"), None).unwrap();
        let spliced = splice_key(&q[0].contents, Some("vk-id"));
        assert!(ensure_key_spliced(&spliced, Some("vk-id"), ".env").is_ok());
        assert!(spliced.starts_with("KEY=<paste-your-upstream-api-key-here>\n"));
    }

    /// A `.env` companion is where an env-file client picks up trust anchors,
    /// so the CA lines are appended there and nowhere else.
    #[test]
    fn only_a_shell_companion_gets_the_private_ca_env_lines_appended() {
        let ca = ca_env_lines();
        let shell = tmpl_with_companion("~/.tool/.env", TemplateFormat::Shell, "KEY={{api_key}}\n");
        let q = quirk_files(&shell, &gateway_phs(), Some("sk-real"), None).unwrap();
        assert_eq!(
            q[0].contents,
            format!("KEY={API_KEY_PLACEHOLDER}\n{ca}"),
            "a shell companion carries the CA lines"
        );

        let yaml = tmpl_with_companion(
            "~/.tool/secrets.yaml",
            TemplateFormat::Yaml,
            "KEY: {{api_key}}\n",
        );
        let q = quirk_files(&yaml, &gateway_phs(), Some("sk-real"), None).unwrap();
        assert!(
            !q[0].contents.contains("SSL_CERT_FILE"),
            "a non-shell companion has no channel for them; got:\n{}",
            q[0].contents
        );
    }

    /// Under a project scope a `~/`-anchored companion lands under the
    /// project root rather than in $HOME, at its declared project path when
    /// it has one.
    #[test]
    fn a_project_scope_run_remaps_a_tilde_companion_beside_the_project_config() {
        let t = tmpl_with_companion("~/.tool/.env", TemplateFormat::Shell, "KEY={{api_key}}\n");
        let root = Path::new("/tmp/proj");
        let q = quirk_files(&t, &gateway_phs(), Some("sk-real"), Some(root)).unwrap();
        let want = root.join(".tool").join(".env");
        assert_eq!(q[0].path.as_deref(), want.to_str());

        // An absolute companion path is NOT remapped — only the `~/` anchor is.
        let abs = tmpl_with_companion("/etc/tool.env", TemplateFormat::Shell, "KEY={{api_key}}\n");
        let q = quirk_files(&abs, &gateway_phs(), Some("sk-real"), Some(root)).unwrap();
        assert_eq!(q[0].path.as_deref(), Some("/etc/tool.env"));

        // A declared project path wins over the re-anchored one, in a project
        // only.
        let mut declared = tmpl_with_companion("~/.tool.json", TemplateFormat::Json, "{}\n");
        declared.companions[0].project_path = Some(".tool/servers.json".into());
        let q = quirk_files(&declared, &gateway_phs(), Some("sk-real"), Some(root)).unwrap();
        let want = root.join(".tool").join("servers.json");
        assert_eq!(q[0].path.as_deref(), want.to_str());
        let q = quirk_files(&declared, &gateway_phs(), Some("sk-real"), None).unwrap();
        assert_eq!(q[0].path.as_deref(), Some("~/.tool.json"));
    }

    /// A companion with no path is a step to show, in either scope — never a
    /// file, so nothing re-anchors it under a project.
    #[test]
    fn a_companion_with_no_path_is_a_step_not_a_file() {
        let mut t = tmpl_with_companion("~/unused", TemplateFormat::Text, "tool add --key {{api_key}}\n");
        t.companions[0].path = None;
        for root in [None, Some(Path::new("/tmp/proj"))] {
            let q = quirk_files(&t, &gateway_phs(), Some("sk-real"), root).unwrap();
            assert_eq!(q[0].path, None, "{root:?}");
        }
    }

    /// An LLM render with no key locally writes nothing, rather than laying
    /// down a file carrying a raw sentinel.
    #[test]
    fn no_local_key_writes_no_llm_companion() {
        let t = tmpl_with_companion("~/.tool/.env", TemplateFormat::Shell, "KEY={{api_key}}\n");
        assert!(quirk_files(&t, &gateway_phs(), None, None).unwrap().is_empty());
    }

    /// A companion that renders to invalid output must surface as an error,
    /// not silently disappear — a missing credential file is the failure the
    /// whole companion mechanism exists to prevent.
    #[test]
    fn a_companion_that_cannot_render_fails_the_run() {
        let t = tmpl_with_companion("~/.tool/broken.yaml", TemplateFormat::Yaml, "a: b\n  c: d\n");
        assert!(quirk_files(&t, &gateway_phs(), Some("sk-real"), None).is_err());
    }
}

#[cfg(test)]
mod ttl_tests {
    use super::parse_ttl;

    #[test]
    fn parses_units_and_rejects_garbage() {
        assert_eq!(parse_ttl("2h").unwrap(), chrono::Duration::hours(2));
        assert_eq!(parse_ttl(" 30m ").unwrap(), chrono::Duration::minutes(30));
        assert_eq!(parse_ttl("7d").unwrap(), chrono::Duration::days(7));
        assert_eq!(parse_ttl("45s").unwrap(), chrono::Duration::seconds(45));
        assert!(parse_ttl("").is_err());
        assert!(parse_ttl("h").is_err());
        assert!(parse_ttl("0h").is_err());
        assert!(parse_ttl("-5m").is_err());
        assert!(parse_ttl("2x").is_err());
        // Multi-byte trailing characters must error, never panic.
        assert!(parse_ttl("2µ").is_err());
        assert!(parse_ttl("30分").is_err());
    }
}

#[cfg(test)]
mod group_tests {
    use super::*;

    fn plan(client_id: &str, provider: Option<uuid::Uuid>, mcp: &[uuid::Uuid]) -> ClientPlan {
        ClientPlan {
            client_id: client_id.to_string(),
            template_index: 0,
            mode: Mode::Gateway,
            provider_id: provider,
            mcp_server_ids: mcp.to_vec(),
            mcp_local_server_ids: Vec::new(),
        }
    }

    /// One bundle carries one MCP selection, so two clients that differ in it
    /// are two calls — otherwise whichever of them the call was built for
    /// decides for both.
    #[test]
    fn clients_with_different_mcp_servers_do_not_share_a_bundle() {
        let provider = uuid::Uuid::new_v4();
        let web = uuid::Uuid::new_v4();
        let plans = vec![
            plan("cursor", Some(provider), &[web]),
            plan("vibe", Some(provider), &[]),
            plan("claude", Some(provider), &[web]),
        ];
        let groups = group_plans(&plans);
        assert_eq!(groups.len(), 3, "{:?}", groups.iter().map(|g| g.signature()).collect::<Vec<_>>());
        // The etag map is keyed by the signature, so no two may collide — one
        // group's no-op answer would otherwise be read for another.
        let mut sigs: Vec<String> = groups.iter().map(|g| g.signature()).collect();
        sigs.sort();
        sigs.dedup();
        assert_eq!(sigs.len(), 3);
    }

    /// Same mode, same provider, same servers — still one call per client: a
    /// call carries one key, and every tool holds its own.
    #[test]
    fn clients_agreeing_on_everything_still_get_a_call_each() {
        let provider = uuid::Uuid::new_v4();
        let web = uuid::Uuid::new_v4();
        let plans = vec![
            plan("cursor", Some(provider), &[web]),
            plan("vibe", Some(provider), &[web]),
        ];
        let groups = group_plans(&plans);
        assert_eq!(groups.iter().map(|g| g.client_id.as_str()).collect::<Vec<_>>(), vec!["cursor", "vibe"]);
        assert!(groups.iter().all(|g| g.indices.len() == 1));
    }

    /// The same servers in a different order are the same selection — a stored
    /// manifest's order is whatever the run that wrote it used.
    #[test]
    fn the_order_of_the_mcp_servers_does_not_change_a_groups_signature() {
        let provider = uuid::Uuid::new_v4();
        let web = uuid::Uuid::new_v4();
        let docs = uuid::Uuid::new_v4();
        let a = group_plans(&[plan("cursor", Some(provider), &[web, docs])]);
        let b = group_plans(&[plan("cursor", Some(provider), &[docs, web])]);
        assert_eq!(a[0].signature(), b[0].signature());
    }

    /// An etag answers a question about a group that exists; one for a group no
    /// client has any more is an answer nobody will ask for.
    #[test]
    fn an_etag_for_a_group_no_client_has_is_dropped() {
        use crate::state::{ManagedClient, WorkspaceManifest};
        let provider = uuid::Uuid::new_v4();
        let web = uuid::Uuid::new_v4();
        let mut ws = WorkspaceManifest {
            clients: vec![ManagedClient {
                client_id: "cursor".into(),
                template_index: 0,
                mode: "gateway".into(),
                provider_id: Some(provider),
                key_id: None,
                mcp_server_ids: vec![web],
                mcp_local_servers: vec![],
                mcp_local_commands: Default::default(),
                files: vec![],
                last_provisioned: chrono::Utc::now(),
                launch_command: None,
            }],
            ..Default::default()
        };
        let live = Group {
            client_id: "cursor".into(),
            mode: Mode::Gateway,
            provider_id: Some(provider),
            mcp_server_ids: vec![web],
            mcp_local_server_ids: vec![],
            indices: vec![0],
        }
        .signature();
        ws.group_etags.insert(live.clone(), "etag-live".into());
        ws.group_etags.insert("gateway:someone-else".into(), "etag-stale".into());

        prune_unused_etags(&mut ws);

        assert_eq!(ws.group_etags.keys().collect::<Vec<_>>(), vec![&live]);
    }

    /// An out-of-band key serves every gateway client of one provider. The MCP
    /// selection splits the bundle call, never the key, so two gateway clients
    /// that differ only in their servers must not be refused as "mixed".
    #[test]
    fn differing_mcp_servers_do_not_read_as_a_mixed_key_scope() {
        let provider = uuid::Uuid::new_v4();
        let web = uuid::Uuid::new_v4();
        let groups = group_plans(&[
            plan("cursor", Some(provider), &[web]),
            plan("vibe", Some(provider), &[]),
        ]);
        assert_eq!(groups.len(), 2, "the bundle calls are still separate");
        assert_eq!(distinct_key_scopes(&groups), 1, "but one key serves both");
    }

    /// Two providers genuinely need two keys, and one out-of-band key cannot be
    /// both — that refusal has to stay.
    #[test]
    fn two_providers_still_need_two_keys() {
        let groups = group_plans(&[
            plan("cursor", Some(uuid::Uuid::new_v4()), &[]),
            plan("vibe", Some(uuid::Uuid::new_v4()), &[]),
        ]);
        assert_eq!(distinct_key_scopes(&groups), 2);
    }
}

#[cfg(test)]
mod retire_tests {
    use super::*;

    /// Write `rendered` over `existing` the way provisioning does and return
    /// the record it would keep.
    fn provisioned(path: &Path, existing: Option<&str>, rendered: &str) -> ManagedFile {
        let out = writer::merge(TemplateFormat::Json, existing, rendered, &[], &BTreeMap::new()).unwrap();
        std::fs::write(path, &out.contents).unwrap();
        ManagedFile {
            path: path.to_string_lossy().into_owned(),
            format: "json".into(),
            owned: out.owned,
            file_hash: String::new(),
        }
    }

    #[test]
    fn a_retired_keyed_array_entry_goes_by_the_identity_its_record_carries() {
        let dir = std::env::temp_dir().join(format!("ss-retire-keyed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("opencode.json");
        let keyed = BTreeMap::from([("/experimental/policies".to_string(), "action+resource".to_string())]);
        let user = r#"{"experimental":{"policies":[{"action":"provider.use","resource":"*","effect":"deny"}]}}"#;
        let ours = r#"{"experimental":{"policies":[{"action":"provider.use","resource":"ss","effect":"allow"}]}}"#;
        let out = writer::merge(TemplateFormat::Json, Some(user), ours, &[], &keyed).unwrap();
        std::fs::write(&path, &out.contents).unwrap();
        let rec = ManagedFile {
            path: path.to_string_lossy().into_owned(),
            format: "json".into(),
            owned: out.owned,
            file_hash: String::new(),
        };
        retire_file(&rec, &[], "20261010T000000Z", &dir.join("state")).unwrap();
        let left: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            left["experimental"]["policies"],
            serde_json::json!([{"action":"provider.use","resource":"*","effect":"deny"}]),
            "our allow goes, the user's deny stays"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Two gateways provisioning one project's OpenCode config both render
    /// the `provider.use` deny and record it: retiring one gateway's entries
    /// keeps the deny the other still records, and with no other record it goes.
    #[test]
    fn an_entry_another_gateway_records_is_kept_when_one_retires() {
        let dir = std::env::temp_dir().join(format!("ss-retire-shared-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("opencode.json");
        let keyed = BTreeMap::from([("/experimental/policies".to_string(), "action+resource".to_string())]);
        let render = |provider: &str| {
            format!(
                r#"{{"model":"{provider}/m","experimental":{{"policies":[{{"action":"provider.use","resource":"{provider}","effect":"allow"}},{{"action":"provider.use","resource":"*","effect":"deny"}}]}}}}"#
            )
        };
        let a = writer::merge(TemplateFormat::Json, None, &render("gw-a"), &[], &keyed).unwrap();
        let b = writer::merge(TemplateFormat::Json, Some(&a.contents), &render("gw-b"), &[], &keyed).unwrap();
        let record = |owned| ManagedFile {
            path: path.to_string_lossy().into_owned(),
            format: "json".into(),
            owned,
            file_hash: String::new(),
        };
        let (rec_a, rec_b) = (record(a.owned), record(b.owned));
        let live = || -> serde_json::Value { serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap() };
        let policies = || -> Vec<String> {
            let v = live();
            v["experimental"]["policies"]
                .as_array()
                .map(|a| a.iter().map(|p| format!("{} {}", p["resource"].as_str().unwrap(), p["effect"].as_str().unwrap())).collect())
                .unwrap_or_default()
        };

        std::fs::write(&path, &b.contents).unwrap();
        retire_file(&rec_a, std::slice::from_ref(&rec_b), "20261010T000000Z", &dir.join("state")).unwrap();
        assert_eq!(policies(), ["gw-b allow", "* deny"], "gw-a's allow goes; the deny gw-b records stays");
        assert_eq!(live()["model"], "gw-b/m", "gw-b's live model is not gw-a's to remove");

        // A path both write with different values is each one's own: gw-a's
        // live value goes with gw-a even though gw-b records the path.
        std::fs::write(&path, &a.contents).unwrap();
        retire_file(&rec_a, std::slice::from_ref(&rec_b), "20261010T000002Z", &dir.join("state")).unwrap();
        assert!(live().get("model").is_none(), "gw-a's own model stayed behind: {}", live());

        std::fs::write(&path, &b.contents).unwrap();
        retire_file(&rec_a, &[], "20261010T000001Z", &dir.join("state")).unwrap();
        assert_eq!(policies(), ["gw-b allow"], "with no other record the deny goes with gw-a");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_moved_config_loses_our_entries_and_keeps_the_users() {
        let dir = std::env::temp_dir().join(format!("ss-retire-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ours = r#"{"providers":{"ss":{"settings":{"apiKey":"sk-x"}}},"model":"ss/m"}"#;

        let shared = dir.join("shared.json");
        let rec = provisioned(&shared, Some(r#"{"theme":"dark"}"#), ours);
        retire_file(&rec, &[], "20261010T000000Z", &dir.join("state")).unwrap();
        let left: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&shared).unwrap()).unwrap();
        assert_eq!(left, serde_json::json!({ "theme": "dark" }), "only the user's setting stays");

        let only_ours = dir.join("only.json");
        let rec = provisioned(&only_ours, None, ours);
        retire_file(&rec, &[], "20261010T000000Z", &dir.join("state")).unwrap();
        assert!(!only_ours.exists(), "a file holding only our entries is removed");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
