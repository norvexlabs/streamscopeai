<script lang="ts">
  import { untrack } from 'svelte';
  import { portalApi } from '#lib/portal-client.js';
  import { extractError, extractErrorCode, fetchAllPages } from '#lib/api-helpers.js';
  import { portalScope, resolvePortalWorkspace } from '#lib/scope.svelte.js';
  import CodeSnippet from '#lib/components/CodeSnippet.svelte';
  import Callout from '#lib/components/Callout.svelte';
  import McpConnectBanner from '#lib/components/portal/McpConnectBanner.svelte';
  import { serversNeedingConnection } from '#lib/mcp/connectionState.js';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import Tabs from '#lib/components/Tabs.svelte';
  import { getTabFromUrl } from '#lib/tabs.js';
  import type { components } from '#lib/generated/api-types.js';
  import type { McpAuthMode } from '#lib/api-types.js';
  import { page } from '$app/state';
  import { pthref, thref } from '#lib/tenant.js';
  import { m } from '#lib/paraglide/messages.js';
  import {
    defaultLlmTemplateIndex,
    groupIndexFor,
    llmTemplateGroups as groupLlmTemplates,
    mcpAuthModeOf,
    mcpOnlyTemplateIndex,
    offersOpenAiAndAnthropic,
    sameGroup,
    templateNeedsLlm,
  } from '#lib/clientTemplates.js';
  import type { PageProps } from './$types';

  let { params }: PageProps = $props();

  let slug = $derived(params.slug);

  // ---------- Setup mode: the ssai CLI (offered first) vs the web wizard ----------
  type SetupTab = 'wizard' | 'cli';
  let setupTab = $state<SetupTab>(getTabFromUrl(['cli', 'wizard'], 'cli'));
  let cliPortalUrl = $derived(`${page.url.origin}/portal/t/${slug}`);
  let cliInstallCmd = $derived(`curl -fsSL ${page.url.origin}/api/v1/cli/install.sh | sh`);
  let cliInstallPs = $derived(`irm ${page.url.origin}/api/v1/cli/install.ps1 | iex`);
  let cliCiRecipe = $derived(
    [
      `export STREAMSCOPE_URL=${cliPortalUrl}`,
      `export STREAMSCOPE_AK=ak-…   # ${m.portal_qs_cli_ci_ak_comment()}`,
      'ssai provision --client opencode --yes',
    ].join('\n')
  );

  type ClientProfileSummary = components['schemas']['ClientProfileSummary'];
  type ClientProfile = components['schemas']['ClientProfile'];
  type ClientProfileTemplate = components['schemas']['ClientProfileTemplate'];
  type PortalRoute = components['schemas']['PortalRoute'];
  type RenderResponse = components['schemas']['RenderResponse'];
  type PortalMcpVirtualServer = components['schemas']['PortalMcpVirtualServer'];
  type PortalMcpLocalServer = components['schemas']['PortalMcpLocalServer'];
  type PortalWorkspace = components['schemas']['PortalWorkspaceInfo'];
  type QuickstartKey = components['schemas']['QuickstartKey'];
  type McpServerWarning = components['schemas']['McpServerWarning'];

  /** Why the render left a selected MCP server out, in the reader's language;
   *  the server's own text for a reason this console does not know. */
  function mcpWarningText(w: McpServerWarning): string {
    const serverText = w.message;
    switch (w.reason) {
      case 'sign_in_cannot_reach_fwd':
        return m.portal_qs_mcp_warning_sign_in_cannot_reach_fwd();
      case 'pass_through_key_not_accepted':
        return m.portal_qs_mcp_warning_pass_through_key_not_accepted();
      case 'local_server_not_supported':
        return m.portal_qs_mcp_warning_local_server_not_supported();
      case 'local_server_project_only':
        return m.portal_qs_mcp_warning_local_server_project_only();
      default:
        return serverText;
    }
  }

  /** The variables the administrator left without a value: the rendered
   *  config holds a paste-here placeholder for each. */
  function localEnvToFill(l: PortalMcpLocalServer): string[] {
    return (l.launch.env ?? []).filter((e) => e.value == null).map((e) => e.name);
  }

  /** Wizard steps. `config` is shown only when the chosen client offers both
   *  an LLM-capable template and an MCP-only one; `llm` / `mcp` are shown
   *  only when the chosen template needs them. */
  type WizardStep = 'client' | 'config' | 'llm' | 'mcp' | 'render';

  /** The unified key for a render — one key per (user, workspace) serves both
   *  LLM and MCP traffic. Either mints a fresh key (`mode: 'mint'`) or reuses
   *  one already in the workspace (`mode: 'reuse'`). */
  interface KeyConfig {
    mode: 'mint' | 'reuse';
    keyName: string;
    reuseKeyId: string;
    forwardAuth: boolean;
    keys: QuickstartKey[];
  }

  function emptyKey(): KeyConfig {
    return { mode: 'mint', keyName: '', reuseKeyId: '', forwardAuth: false, keys: [] };
  }

  /** Lowest free key name: `prefix` when unused, else `prefix-N` (N ≥ 2).
   *  Mirrors the backend `next_available_name` so the minted-name preview
   *  the user sees matches what the render call produces. */
  function nextName(prefix: string, keys: QuickstartKey[]): string {
    const taken = new Set(keys.map((k) => k.name));
    if (!taken.has(prefix)) return prefix;
    let n = 2;
    while (taken.has(`${prefix}-${n}`)) n += 1;
    return `${prefix}-${n}`;
  }

  // ---------- Initial data ----------
  let clients = $state<ClientProfileSummary[]>([]);
  let routes = $state<PortalRoute[]>([]);
  // Every virtual server any of the member's workspaces grants: the banner
  // above both setups. The wizard offers `virtualServers`, its workspace's own.
  let allVirtualServers = $state<PortalMcpVirtualServer[]>([]);
  let workspaces = $state<PortalWorkspace[]>([]);
  // What the wizard's workspace grants, read on entering it (`enterWorkspace`)
  // and empty until then — never another workspace's: its MCP virtual servers,
  // its providers (the route list spans every workspace the member is in, and
  // a render draws on one) and, among those, its BYOK pass-through downstreams
  // (no routes: provisioned host-only).
  let virtualServers = $state<PortalMcpVirtualServer[]>([]);
  let grantedProviderIds = $state<Set<string>>(new Set());
  let byokProviders = $state<{ id: string; name: string; upstreamProtocol: string | null }[]>([]);
  let loading = $state(true);
  let loadError = $state('');

  // ---------- Wizard state ----------
  let step = $state<WizardStep>('client');
  let renderError = $state('');
  let renderErrorCode = $state<string | null>(null);
  let rendering = $state(false);
  let rendered = $state<RenderResponse | null>(null);
  // What the last render sent: whether it carried local servers and nothing
  // that needs a gateway key, and the variables of its local servers the
  // member fills (each is a paste-here placeholder in the result).
  let renderedLocalOnly = $state(false);
  let renderedLocalFill = $state<string[]>([]);

  // Selected client + template
  let selectedClient = $state<ClientProfile | null>(null);
  let selectedTemplateIndex = $state<number>(0);
  // Whether the user picked the snippet variant themselves — then a provider
  // change never moves it.
  let variantPicked = $state(false);

  // The workspace the wizard works in (see "The wizard's workspace" below) —
  // the key is pinned to it — and the one unified key for the render.
  let wizardWorkspaceId = $state<string>('');
  let keyCfg = $state<KeyConfig>(emptyKey());

  // LLM step — which provider the snippet defaults its model from.
  let llmProviderId = $state<string>('');
  type ExpiryChoice = 'never' | '30' | '90' | 'custom';
  let expiryChoice = $state<ExpiryChoice>('never');
  let expiresInDaysCustom = $state<number>(30);

  // MCP step — selection only; the unified key covers every ticked server.
  let mcpSelected = $state<Record<string, boolean>>({});
  // The local MCP servers (run on the member's own machine) the wizard's
  // workspace hands its members, read on entering it like its other grants,
  // and which of them are ticked.
  let localServers = $state<PortalMcpLocalServer[]>([]);
  let localSelected = $state<Record<string, boolean>>({});

  $effect(() => {
    void loadInitial();
  });

  // Whether the selected LLM provider is a BYOK pass-through downstream. A BYOK
  // provider is provisioned host-only: a vk- key bound to it, native auth/model
  // passed through.
  const selectedIsByok = $derived(byokProviders.some((p) => p.id === llmProviderId));

  // A pass-through forwards the user's own credential, which works on its
  // server's protocol: the variant follows the provider to the template
  // speaking it, as `ssai provision` does, until the user picks one.
  $effect(() => {
    if (step !== 'llm' || !selectedClient || variantPicked) return;
    const native = byokProviders.find((p) => p.id === llmProviderId)?.upstreamProtocol ?? null;
    const templates = selectedClient.templates;
    const i = defaultLlmTemplateIndex(templates, native);
    // Only across protocols: the MCP step's auth-mode sibling stays.
    if (i >= 0 && groupIndexFor(templates, i) !== groupIndexFor(templates, selectedTemplateIndex)) {
      selectedTemplateIndex = i;
    }
  });

  // A BYOK provider requires a BYOK (vk-) key — keep the key mode in lockstep
  // with the provider so the user never lands a gateway key on a BYOK provider
  // (the proxy would reject it) and vice versa. Gemini included: its `?key=`
  // query param (and `x-goog-api-key` header) are forwarded by the gateway, so
  // host-only BYOK works for it too.
  $effect(() => {
    if (keyCfg.mode !== 'mint') return;
    const tmpl = chosenTemplate();
    if (!tmpl || !templateNeedsLlm(tmpl)) return;
    if (selectedIsByok && !keyCfg.forwardAuth) keyCfg.forwardAuth = true;
    if (!selectedIsByok && keyCfg.forwardAuth) keyCfg.forwardAuth = false;
  });

  /** The data every workspace shares, and the memberships that decide which
   *  workspace the wizard works in. Without the memberships nothing can be
   *  offered: a failed read is an error to retry, never "no workspace". */
  async function loadInitial() {
    loading = true;
    loadError = '';
    membershipsLoaded = false;
    try {
      const [routesList, vsList, meRes] = await Promise.all([
        // A failed list leaves its picker empty rather than blocking the
        // other client kinds the wizard can still set up.
        fetchAllPages<PortalRoute>((offset, limit) =>
          portalApi.GET('/api/v1/portal/quickstart/routes', { params: { query: { offset, limit } } }))
          .catch((): PortalRoute[] => []),
        fetchAllPages<PortalMcpVirtualServer>((offset, limit) =>
          portalApi.GET('/api/v1/portal/mcp/virtual-servers', { params: { query: { offset, limit } } }))
          .catch((): PortalMcpVirtualServer[] => []),
        portalApi.GET('/api/v1/portal/auth/me'),
      ]);
      if (meRes.error || !meRes.data) {
        loadError = extractError(meRes.error, m.portal_qs_err_load_workspaces());
        return;
      }
      routes = routesList;
      allVirtualServers = vsList;
      workspaces = meRes.data.workspaces ?? [];
      membershipsLoaded = true;
      // Enter the header's workspace — as it stands now, whatever it was when
      // the load began — before the wizard shows, so it never paints empty.
      followHeader();
    } finally {
      loading = false;
    }
  }

  // ---------- The wizard's workspace ----------
  // INVARIANT: the wizard works in ONE workspace, `wizardWorkspaceId`, and
  // `enterWorkspace` is the only code that assigns it. Its source is the header
  // workspace (`headerWorkspaceId`), reached through `followHeader` alone,
  // which never moves the wizard while a configuration is being rendered or is
  // on screen: a minted key is shown once, so the result stays as it is, under
  // a notice naming both workspaces, until the member starts over. Entering a
  // workspace starts the wizard over — nothing chosen before carries — and
  // reads, once, everything the steps offer for it: its clients, what it
  // grants, its keys. Each entry takes the next `entry` number; a read issued
  // under an earlier one (another workspace's, or this workspace's before a
  // restart) is dropped when it lands. What a workspace grants fails CLOSED: a
  // failed read is an error to retry, never the grants of every membership.
  let membershipsLoaded = $state(false);
  let clientsLoading = $state(false);
  // Not reactive: only compared by the reads they number. `picks` numbers the
  // client picks of one entry: the latest one wins.
  let entry = 0;
  let picks = 0;

  /** The header's workspace by the header's own rule (the remembered choice
   *  while still a membership, else the first one); `''` for a member of none. */
  const headerWorkspaceId = $derived(resolvePortalWorkspace(workspaces, portalScope.activeWorkspace) ?? '');

  function workspaceName(id: string): string {
    return workspaces.find((w) => w.id === id)?.name ?? '';
  }

  /** A configuration is on screen for a workspace the header has since left. */
  const switchedAway = $derived(!!rendered && membershipsLoaded && headerWorkspaceId !== wizardWorkspaceId);

  /** Move the wizard to the header's workspace, unless a render is in flight
   *  or its result is on screen. */
  function followHeader() {
    if (!membershipsLoaded || rendering || rendered) return;
    if (headerWorkspaceId !== wizardWorkspaceId) void enterWorkspace(headerWorkspaceId);
  }

  // Runs on a header switch and when the initial load ends (so a switch made
  // while it ran is honoured); everything else `followHeader` reads is
  // untracked.
  $effect(() => {
    void headerWorkspaceId;
    void membershipsLoaded;
    untrack(followHeader);
  });

  /** Start the wizard over in workspace `id`: clear every choice and result,
   *  then read what the steps offer for it. */
  async function enterWorkspace(id: string) {
    const mine = ++entry;
    wizardWorkspaceId = id;
    selectedClient = null;
    selectedTemplateIndex = 0;
    variantPicked = false;
    rendered = null;
    renderedLocalOnly = false;
    renderedLocalFill = [];
    renderError = '';
    renderErrorCode = null;
    llmProviderId = '';
    keyCfg = emptyKey();
    expiryChoice = 'never';
    expiresInDaysCustom = 30;
    step = 'client';
    clients = [];
    virtualServers = [];
    localServers = [];
    grantedProviderIds = new Set();
    byokProviders = [];
    mcpSelected = {};
    localSelected = {};
    loadError = '';
    // A member of no workspace: nothing to read, and no earlier entry's read
    // will clear the flag (it is dropped when it lands).
    clientsLoading = false;
    if (!id) return;
    clientsLoading = true;
    const [offered, grants, servers, locals, keys] = await Promise.all([
      portalApi.GET('/api/v1/portal/quickstart/clients', { params: { query: { workspace_id: id } } }),
      portalApi.GET('/api/v1/portal/auth/me', { params: { query: { workspace_id: id } } }),
      fetchAllPages<PortalMcpVirtualServer>((offset, limit) =>
        portalApi.GET('/api/v1/portal/mcp/virtual-servers', { params: { query: { workspace_id: id, offset, limit } } }))
        .catch(() => null),
      fetchAllPages<PortalMcpLocalServer>((offset, limit) =>
        portalApi.GET('/api/v1/portal/mcp/local-servers', { params: { query: { workspace_id: id, offset, limit } } }))
        .catch(() => null),
      // A failed key list offers no key to reuse; a new one can still be minted.
      fetchAllPages<QuickstartKey>((offset, limit) =>
        portalApi.GET('/api/v1/portal/quickstart/keys', { params: { query: { workspace_id: id, offset, limit } } }))
        .catch((): QuickstartKey[] => []),
    ]);
    // A newer entry owns the wizard: this answer is not its.
    if (mine !== entry) return;
    clientsLoading = false;
    if (offered.error) {
      loadError = extractError(offered.error, m.portal_qs_err_load_clients());
      return;
    }
    if (grants.error || !grants.data || servers === null || locals === null) {
      loadError = extractError(grants.error, m.portal_qs_err_load_grants());
      return;
    }
    const providers = grants.data.downstream_providers ?? [];
    clients = offered.data?.clients ?? [];
    grantedProviderIds = new Set(providers.map((p) => p.id));
    byokProviders = providers
      .filter((p) => p.byok)
      .map((p) => ({ id: p.id, name: p.name, upstreamProtocol: p.upstream_protocol ?? null }));
    virtualServers = servers;
    mcpSelected = Object.fromEntries(servers.map((v) => [v.id, false]));
    localServers = locals;
    localSelected = Object.fromEntries(locals.map((l) => [l.id, false]));
    keyCfg.keys = keys;
    keyCfg.mode = keys.length > 0 ? 'reuse' : 'mint';
    keyCfg.reuseKeyId = keys[0]?.id ?? '';
    // Name left blank — the input shows the suggested name as a placeholder;
    // an empty submit lets the backend pick the next free suffix.
  }

  /** The member's own restart: the header's workspace, whatever is on screen. */
  function startOver() {
    void enterWorkspace(headerWorkspaceId);
  }

  /** Retry what failed: the memberships, else the wizard's workspace. */
  function retryLoad() {
    if (membershipsLoaded) void enterWorkspace(headerWorkspaceId);
    else void loadInitial();
  }

  // ---------- Derived state ----------
  /** The steps shown for the current client + template, in order. Drives
   *  the step indicator and `goBack()`; collapses steps that don't apply. */
  const shownSteps: WizardStep[] = $derived.by(() => {
    const out: WizardStep[] = ['client'];
    if (!selectedClient) {
      out.push('llm', 'mcp', 'render');
      return out;
    }
    if (clientNeedsConfigChoice()) out.push('config');
    const tmpl = chosenTemplate();
    if (templateNeedsLlm(tmpl)) out.push('llm');
    if (templateNeedsMcp(tmpl)) out.push('mcp');
    out.push('render');
    return out;
  });
  const totalSteps = $derived(shownSteps.length);
  // Effective step number for the indicator (collapses skipped steps).
  const displayStep = $derived(Math.max(1, shownSteps.indexOf(step) + 1));

  const stepBlurbs: Record<WizardStep, string> = $derived({
    client: m.portal_qs_blurb_client(),
    config: m.portal_qs_blurb_config(),
    llm: m.portal_qs_blurb_llm(),
    mcp: m.portal_qs_blurb_mcp(),
    render: m.portal_qs_blurb_render(),
  });
  const stepTitles: Record<WizardStep, string> = $derived({
    client: m.portal_qs_title_client(),
    config: m.portal_qs_title_config(),
    llm: m.portal_qs_title_llm(),
    mcp: m.portal_qs_title_mcp(),
    render: m.portal_qs_title_render(),
  });

  function chosenTemplate(): ClientProfileTemplate | null {
    return selectedClient?.templates[selectedTemplateIndex] ?? null;
  }

  /** Where the chosen template writes a local MCP server: into the config
   *  this page renders (`config`), only into a project's own file, which
   *  `ssai provision` writes (`project`), or nowhere (`none`). */
  const localMcp = $derived(chosenTemplate()?.local_mcp ?? 'none');
  /** The ticked gateway servers. */
  const gatewayPicked = $derived(virtualServers.filter((v) => mcpSelected[v.id]));
  /** The ticked local servers the chosen template can write here. */
  const localPicked = $derived(localMcp === 'config' ? localServers.filter((l) => localSelected[l.id]) : []);
  /** Only local servers are ticked, on a template with no LLM section:
   *  nothing in the render reaches the gateway, so it needs no key. */
  const localOnlySelection = $derived.by(() => {
    const t = chosenTemplate();
    return !!t && !templateNeedsLlm(t) && templateNeedsMcp(t) && gatewayPicked.length === 0 && localPicked.length > 0;
  });

  function templateNeedsMcp(t: ClientProfileTemplate | null): boolean {
    return !!t && (t.kind === 'mcp' || t.kind === 'combined');
  }

  /** `true` when the selected client ships a template that needs an LLM key
   *  (`llm` / `combined` / `instructions`). */
  function clientHasFull(): boolean {
    return !!selectedClient && selectedClient.templates.some(templateNeedsLlm);
  }
  /** `true` when the selected client ships a `kind = "mcp"` template — one
   *  that renders without an LLM model. */
  function clientHasMcpOnly(): boolean {
    return !!selectedClient && selectedClient.templates.some((t) => t.kind === 'mcp');
  }
  /** `true` when an MCP-only template of the selected client writes local
   *  servers into the config this page renders. */
  function mcpOnlyWritesLocal(): boolean {
    return !!selectedClient && mcpOnlyTemplateIndex(selectedClient.templates, { gateway: false, local: true }) >= 0;
  }
  /** `true` when the MCP-only setup has a server to offer: a gateway one, or
   *  a local one its template writes into the config this page renders. */
  function mcpOnlyHasServers(): boolean {
    return virtualServers.length > 0 || (localServers.length > 0 && mcpOnlyWritesLocal());
  }
  /** Show the `config` step only when the client supports both shapes. */
  function clientNeedsConfigChoice(): boolean {
    return clientHasFull() && clientHasMcpOnly();
  }

  /** The chosen template's MCP auth mode; `static` when none is chosen. */
  function chosenMcpAuthMode(): McpAuthMode {
    return mcpAuthModeOf(chosenTemplate() ?? {});
  }

  /** `true` when the render needs a key minted/reused: a template with an
   *  LLM section always, an MCP-only one when a gateway server is ticked and
   *  it authenticates with a key (OAuth mints none). Local servers alone
   *  need no key. */
  function renderNeedsKey(): boolean {
    const t = chosenTemplate();
    if (templateNeedsLlm(t)) return true;
    if (t && templateNeedsMcp(t) && mcpAuthModeOf(t) === 'static') return gatewayPicked.length > 0;
    return false;
  }

  /** Step-`llm` template picker entries. See `#lib/clientTemplates.js` for why
   *  the collapse keys on the label rather than `(kind, protocol)`. */
  function llmTemplateGroups(): Array<{ index: number; label: string }> {
    return selectedClient ? groupLlmTemplates(selectedClient.templates) : [];
  }

  /** Step-`mcp` auth-mode picker entries — only `(kind, protocol)` siblings
   *  of the current template count; hidden when there's just one. */
  function mcpAuthModeOptions(): Array<{ index: number; mode: McpAuthMode }> {
    if (!selectedClient) return [];
    const current = chosenTemplate();
    if (!current) return [];
    const out: Array<{ index: number; mode: McpAuthMode }> = [];
    selectedClient.templates.forEach((t, i) => {
      if (!templateNeedsMcp(t)) return;
      if (t.kind !== current.kind) return;
      if ((t.protocol ?? '') !== (current.protocol ?? '')) return;
      out.push({ index: i, mode: mcpAuthModeOf(t) });
    });
    return out.length > 1 ? out : [];
  }

  /** Snap `selectedTemplateIndex` to the static-MCP variant of the picked
   *  group; Step `mcp` lets the user swap to OAuth. */
  function pickLlmGroup(repIndex: number) {
    if (!selectedClient) return;
    const rep = selectedClient.templates[repIndex];
    if (!rep) return;
    const staticSibling = selectedClient.templates.findIndex(
      (t) => sameGroup(t, rep) && mcpAuthModeOf(t) === 'static',
    );
    selectedTemplateIndex = staticSibling >= 0 ? staticSibling : repIndex;
    variantPicked = true;
  }

  function compatibleProviders(): { id: string; name: string; routeCount: number }[] {
    const grouped = new Map<string, { name: string; count: number }>();
    for (const r of routes) {
      if (!grantedProviderIds.has(r.provider_id)) continue;
      const e = grouped.get(r.provider_id);
      if (e) e.count += 1;
      else grouped.set(r.provider_id, { name: r.provider_name, count: 1 });
    }
    return [...grouped.entries()].map(([id, v]) => ({ id, name: v.name, routeCount: v.count }));
  }

  /** Whether the wizard's workspace grants a provider an LLM configuration can
   *  use — one with routes, or a BYOK pass-through. The route list alone spans
   *  every workspace the member is in. */
  const workspaceGrantsLlm = $derived(compatibleProviders().length > 0 || byokProviders.length > 0);

  /** Virtual servers for the Step-`mcp` checkbox list — built-in first, then
   *  alphabetical by name. */
  function sortedVirtualServers(): PortalMcpVirtualServer[] {
    return [...virtualServers].sort((a, b) => {
      if (a.built_in !== b.built_in) return a.built_in ? -1 : 1;
      return a.name.localeCompare(b.name);
    });
  }

  // ---------- Navigation ----------
  async function pickClient(c: ClientProfileSummary) {
    renderError = '';
    renderErrorCode = null;
    rendered = null;
    selectedTemplateIndex = 0;
    variantPicked = false;
    const mine = entry;
    const pick = ++picks;
    const { data, error: err } = await portalApi.GET(
      '/api/v1/portal/quickstart/clients/{id}',
      { params: { path: { id: c.id }, query: { workspace_id: wizardWorkspaceId } } },
    );
    // The wizard started over meanwhile (another workspace, or this one
    // again), or the member picked another client: this answer is not the
    // wizard's.
    if (mine !== entry || pick !== picks) return;
    if (err || !data) {
      // The administrator switched the client off after the list was read.
      renderError =
        extractErrorCode(err) === 'client_disabled'
          ? m.portal_qs_err_client_not_offered()
          : extractError(err, m.portal_qs_err_load_client_profile());
      return;
    }
    selectedClient = data;
    if (clientNeedsConfigChoice()) {
      // Default the index to a valid template so `chosenTemplate()` (and the
      // step indicator) resolve while on the `config` step; the user's
      // choice re-selects authoritatively in `pickConfigType()`.
      selectedTemplateIndex = defaultLlmTemplateIndex(data.templates);
      step = 'config';
    } else if (clientHasFull()) {
      enterFull();
    } else {
      enterMcpOnly();
    }
  }

  /** Enter the full-config path: select the default LLM template (the
   *  OpenAI-compatible one when the client ships several) and open the LLM
   *  step. */
  function enterFull() {
    if (!selectedClient) return;
    const llm = defaultLlmTemplateIndex(selectedClient.templates);
    selectedTemplateIndex = llm >= 0 ? llm : 0;
    variantPicked = false;
    step = 'llm';
  }

  /** Enter the MCP-only path: select the MCP template that can write what
   *  the workspace offers (`mcpOnlyTemplateIndex`) and open the MCP step,
   *  skipping the LLM model entirely. */
  function enterMcpOnly() {
    if (!selectedClient) return;
    const fits = mcpOnlyTemplateIndex(selectedClient.templates, {
      gateway: virtualServers.length > 0,
      local: localServers.length > 0,
    });
    selectedTemplateIndex = fits >= 0 ? fits : 0;
    step = 'mcp';
  }

  function pickConfigType(type: 'full' | 'mcp') {
    renderError = '';
    if (type === 'full') enterFull();
    else enterMcpOnly();
  }

  function expiresAtIso(): string | null {
    let days: number;
    switch (expiryChoice) {
      case 'never': return null;
      case '30': days = 30; break;
      case '90': days = 90; break;
      case 'custom':
        days = expiresInDaysCustom;
        if (!Number.isFinite(days) || days <= 0) return null;
        break;
    }
    return new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
  }

  function validateKey(): string | null {
    if (renderNeedsKey()) {
      if (!wizardWorkspaceId) return m.portal_qs_err_pick_workspace();
      if (keyCfg.mode === 'reuse' && !keyCfg.reuseKeyId) {
        return m.portal_qs_err_pick_existing_key();
      }
    }
    return null;
  }

  async function nextFromLlm() {
    renderError = '';
    if (!llmProviderId) {
      renderError = m.portal_qs_err_pick_provider();
      return;
    }
    const keyErr = validateKey();
    if (keyErr) {
      renderError = keyErr;
      return;
    }
    if (templateNeedsMcp(chosenTemplate())) {
      step = 'mcp';
    } else {
      await render();
    }
  }

  async function nextFromMcp() {
    renderError = '';
    const tmpl = chosenTemplate();
    // Only what the template can write counts: a local server it has no
    // form for is not a selection.
    const selectedCount = gatewayPicked.length + localPicked.length;
    if (tmpl?.kind === 'mcp' && selectedCount === 0) {
      renderError = m.portal_qs_err_select_mcp();
      return;
    }
    const keyErr = validateKey();
    if (keyErr) {
      renderError = keyErr;
      return;
    }
    await render();
  }

  function buildMcpServers(tmpl: ClientProfileTemplate): components['schemas']['McpServerSelection'][] {
    if (!templateNeedsMcp(tmpl)) return [];
    return gatewayPicked.map((v) => ({ virtual_server_id: v.id }));
  }

  function buildMcpLocalServers(tmpl: ClientProfileTemplate): components['schemas']['McpLocalServerSelection'][] {
    if (!templateNeedsMcp(tmpl)) return [];
    return localPicked.map((l) => ({ local_server_id: l.id }));
  }

  function buildKeySpec(): components['schemas']['KeySpec'] | undefined {
    if (!renderNeedsKey()) return undefined;
    if (keyCfg.mode === 'reuse') {
      return { reuse_key_id: keyCfg.reuseKeyId };
    }
    return {
      name: keyCfg.keyName.trim() || undefined,
      forward_auth: keyCfg.forwardAuth,
      expires_at: expiresAtIso() ?? undefined,
    };
  }

  async function render() {
    // Double-click guard: a fast second click would mint a second key
    // before Svelte's reactivity has flipped the disabled state.
    if (rendering) return;
    rendering = true;
    renderError = '';
    rendered = null;
    try {
      const tmpl = chosenTemplate();
      if (!tmpl || !selectedClient) {
        renderError = m.portal_qs_err_no_template();
        return;
      }
      const key = buildKeySpec();
      const gatewaySent = buildMcpServers(tmpl);
      const localSent = templateNeedsMcp(tmpl) ? localPicked : [];
      const body: components['schemas']['RenderRequest'] = {
        client_id: selectedClient.id,
        template_index: selectedTemplateIndex,
        workspace_id: wizardWorkspaceId,
        // Absent when nothing rendered reaches the gateway with a key.
        key,
        llm_provider_id: templateNeedsLlm(tmpl) ? llmProviderId : undefined,
        mcp_servers: gatewaySent,
        mcp_local_servers: buildMcpLocalServers(tmpl),
      };
      const { data, error: err } = await portalApi.POST(
        '/api/v1/portal/quickstart/actions/render',
        { body },
      );
      if (err || !data) {
        renderError = extractError(err, m.portal_qs_err_render_failed());
        renderErrorCode = extractErrorCode(err);
        return;
      }
      const leftOut = new Set(data.warnings.map((w) => w.local_server_id).filter((id) => id != null));
      renderedLocalFill = [
        ...new Set(localSent.filter((l) => !leftOut.has(l.id)).flatMap((l) => localEnvToFill(l))),
      ];
      renderedLocalOnly = key === undefined && gatewaySent.length === 0 && localSent.length > 0;
      rendered = data;
      step = 'render';
    } finally {
      rendering = false;
      // A header switch made while the render was in flight: a result stays on
      // screen under its notice, a failed render lets the wizard follow.
      followHeader();
    }
  }

  function goBack() {
    renderError = '';
    const idx = shownSteps.indexOf(step);
    const prev = idx > 0 ? shownSteps[idx - 1] : undefined;
    if (prev) step = prev;
  }

  const API_KEY_SENTINEL = '<paste-your-api-key-here>';

  function substitutionsFor(): Record<string, string> {
    if (!rendered) return {};
    const subs: Record<string, string> = {};
    if (rendered.minted_secrets.api_key) {
      subs[API_KEY_SENTINEL] = rendered.minted_secrets.api_key;
    }
    return subs;
  }

  /** A key was minted but its sentinel appears in nothing we rendered — the
   *  tool reads it from the shell environment (Zed) or from a file the render
   *  doesn't cover, so the plaintext would otherwise be unobtainable: it is
   *  shown once, here, and never recoverable afterwards. Kept as a snippet so
   *  the plaintext still reaches the clipboard via `substitutions` rather than
   *  the DOM. */
  const keyIsUnreachable = $derived(
    !!rendered?.minted_secrets.api_key &&
      !rendered.template.body.includes(API_KEY_SENTINEL) &&
      !rendered.companions.some((c) => c.body.includes(API_KEY_SENTINEL))
  );
</script>

{#snippet workspaceLine()}
  <div class="text-xs text-(--text-secondary)" data-testid="qs-workspace">
    <span class="block">{m.portal_qs_workspace_label()}</span>
    <span class="block mt-1 text-sm font-semibold text-(--text-primary)">{workspaceName(wizardWorkspaceId)}</span>
    <span class="block mt-1 opacity-70">
      {localOnlySelection ? m.portal_qs_workspace_help_local() : m.portal_qs_workspace_help()}
      {#if workspaces.length > 1}{m.portal_qs_workspace_change()}{/if}
    </span>
  </div>
{/snippet}

{#snippet keyPicker(prefix: string, allowFwd: boolean, fwdLabel: string, fwdHelp: string)}
  <fieldset class="text-xs text-(--text-secondary) space-y-2">
    <legend class="font-semibold">{m.portal_qs_api_key()}</legend>
    {#if keyCfg.keys.length > 0}
      <label class="flex items-center gap-2">
        <input
          type="radio"
          name="keymode"
          checked={keyCfg.mode === 'reuse'}
          onchange={() => (keyCfg.mode = 'reuse')}
        />
        {m.portal_qs_reuse_existing_key()}
      </label>
    {/if}
    <label class="flex items-center gap-2">
      <input
        type="radio"
        name="keymode"
        checked={keyCfg.mode === 'mint'}
        onchange={() => (keyCfg.mode = 'mint')}
      />
      {m.portal_qs_mint_new_key()}
    </label>

    {#if keyCfg.mode === 'reuse' && keyCfg.keys.length > 0}
      <SelectInput bind:value={keyCfg.reuseKeyId}>
        {#each keyCfg.keys as k (k.id)}
          <option value={k.id}>{k.name} · {k.key_prefix}… · {k.forward_auth ? 'BYOK' : m.portal_qs_key_standard()}</option>
        {/each}
      </SelectInput>
      <p class="text-[11px] text-(--text-tertiary)">
        {m.portal_qs_reuse_key_help()}
      </p>
    {:else}
      <input
        type="text"
        bind:value={keyCfg.keyName}
        placeholder={nextName(prefix, keyCfg.keys)}
        class="block w-full rounded-sm bg-(--bg-secondary) border border-(--border) px-2 py-1 text-sm text-(--text-primary)"
      />
      <p class="text-[11px] text-(--text-tertiary)">
        {m.portal_qs_mint_name_help()}
      </p>
      {#if allowFwd}
        <label class="flex items-center gap-2">
          <input type="checkbox" bind:checked={keyCfg.forwardAuth} />
          {fwdLabel}
        </label>
        {#if keyCfg.forwardAuth}
          <p class="text-[11px] text-(--text-tertiary)">{fwdHelp}</p>
        {/if}
      {/if}
    {/if}
  </fieldset>
{/snippet}

<div class="space-y-1">
  <h1 class="text-2xl font-bold text-(--text-primary)">{m.portal_qs_heading()}</h1>
  <p class="text-sm text-(--text-secondary)">
    {m.portal_qs_intro()}
  </p>
</div>

<Tabs
  class="mt-4"
  tabs={[
    { id: 'cli', label: m.portal_qs_tab_cli() },
    { id: 'wizard', label: m.portal_qs_tab_wizard() },
  ]}
  active={setupTab}
  onchange={(t) => (setupTab = t as SetupTab)}
/>

<!-- Both setups write the same MCP servers, so the banner is above both. -->
{#if !loading && !loadError && serversNeedingConnection(allVirtualServers).length > 0}
  <div class="mt-6"><McpConnectBanner {slug} servers={serversNeedingConnection(allVirtualServers)} /></div>
{/if}

{#if setupTab === 'cli'}
  <div class="mt-6 space-y-6 max-w-3xl" data-testid="cli-setup-panel">
    <p class="text-sm text-(--text-secondary)">
      {m.portal_qs_cli_intro_pre()} <span class="font-mono text-(--text-primary)">ssai</span> {m.portal_qs_cli_intro_post()}<!-- i18n-ok: CLI command name -->
    </p>

    <div class="space-y-2">
      <h2 class="text-sm font-semibold text-(--text-primary)">{m.portal_qs_cli_step_install()}</h2>
      <CodeSnippet
        body={cliInstallCmd}
        format="shell"
        instructions={m.portal_qs_cli_install_instructions()}
      />
      <CodeSnippet
        body={cliInstallPs}
        format="shell"
        instructions={m.portal_qs_cli_install_windows_instructions()}
      />
    </div>

    <div class="space-y-2">
      <h2 class="text-sm font-semibold text-(--text-primary)">{m.portal_qs_cli_step_login()}</h2>
      <CodeSnippet
        body={`ssai login ${cliPortalUrl}`}
        format="shell"
        instructions={m.portal_qs_cli_login_instructions()}
      />
    </div>

    <div class="space-y-2">
      <h2 class="text-sm font-semibold text-(--text-primary)">{m.portal_qs_cli_step_provision()}</h2>
      <CodeSnippet
        body={'ssai provision'}
        format="shell"
        instructions={m.portal_qs_cli_provision_instructions()}
      />
    </div>

    <div class="space-y-2">
      <h2 class="text-sm font-semibold text-(--text-primary)">{m.portal_qs_cli_step_run()}</h2>
      <CodeSnippet
        body={'ssai run claude'}
        format="shell"
        instructions={m.portal_qs_cli_run_instructions()}
      />
    </div>

    <div class="space-y-2">
      <h2 class="text-sm font-semibold text-(--text-primary)">{m.portal_qs_cli_step_ci()}</h2>
      <p class="text-xs text-(--text-secondary)">
        {m.portal_qs_cli_ci_pre()} <span class="font-mono">--key-ttl</span>{m.portal_qs_cli_ci_post()}<!-- i18n-ok: CLI flag name -->
      </p>
      <CodeSnippet body={cliCiRecipe} format="shell" />
    </div>
  </div>
{:else}

{#if loading}
  <div class="mt-6 text-sm text-(--text-secondary)">{m.portal_qs_loading()}</div>
{:else if loadError}
  <div class="mt-6 flex items-center gap-3 text-sm text-(--error)" role="alert">
    <span>{loadError}</span>
    <button type="button" onclick={retryLoad} class="underline text-(--text-primary)">{m.portal_qs_retry()}</button>
  </div>
{:else if !wizardWorkspaceId}
  <div class="mt-6 text-sm text-(--text-secondary)">{m.portal_qs_no_workspace()}</div>
{:else}
  <!-- Step indicator -->
  <div class="mt-6 mb-4 flex items-center gap-3 text-xs text-(--text-secondary)">
    <span class="font-mono">{m.portal_qs_step({ current: displayStep, total: totalSteps })}</span>
    <span class="text-(--text-primary) font-semibold">{stepTitles[step]}</span>
    <span class="opacity-70">— {stepBlurbs[step]}</span>
  </div>

  <!-- Render error banner — visible on every step when set. -->
  {#if renderError}
    {#if renderErrorCode === 'proxy_public_url_unset' || renderErrorCode === 'admin_public_url_unset'}
      <div role="alert" aria-live="polite" class="mb-4 rounded-sm border border-(--warning-border) bg-(--warning-bg) px-3 py-2 text-xs text-(--warning)">
        <p class="font-semibold mb-1">{m.portal_qs_public_url_unset_title()}</p>
        <p class="mb-2">{renderError}</p>
        <a href={thref(slug, '/settings?tab=proxy')} class="underline text-(--warning) hover:text-(--warning)">{m.portal_qs_open_settings_proxy()}</a>
      </div>
    {:else}
      <div role="alert" aria-live="polite" class="mb-4 rounded-sm border border-(--error-border) bg-(--error-bg) px-3 py-2 text-xs text-(--error-text)">
        {renderError}
      </div>
    {/if}
  {/if}

  <!-- Step: pick client -->
  {#if step === 'client' && clientsLoading}
    <div class="text-sm text-(--text-secondary)">{m.portal_qs_loading()}</div>
  {:else if step === 'client' && clients.length === 0}
    <div class="text-sm text-(--text-secondary)" data-testid="qs-no-clients">{m.portal_qs_no_clients()}</div>
  {:else if step === 'client'}
    <div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3" data-testid="qs-client-grid">
      {#each clients as c (c.id)}
        <button
          type="button"
          class="rounded-lg border border-(--border) bg-(--bg-card) hover:border-(--accent) p-4 text-left transition disabled:opacity-50 disabled:cursor-not-allowed"
          disabled={!c.compatible}
          title={c.compatible ? '' : (c.incompatibility_reason ?? m.portal_qs_client_incompatible())}
          onclick={() => pickClient(c)}
        >
          <div class="text-sm font-semibold text-(--text-primary)">{c.label}</div>
          <div class="mt-1 flex items-center gap-1 text-[10px]">
            {#if c.supports_llm}
              <span class="px-1 py-0.5 rounded-sm bg-(--bg-secondary) text-(--text-secondary)">LLM</span>
            {/if}
            {#if c.supports_mcp}
              <span class="px-1 py-0.5 rounded-sm bg-(--bg-secondary) text-(--text-secondary)">MCP</span>
            {/if}
          </div>
        </button>
      {/each}
    </div>
  {/if}

  <!-- Step: config type -->
  {#if step === 'config' && selectedClient}
    <div class="space-y-4 max-w-2xl">
      <div class="flex items-center justify-between">
        <button class="text-xs text-(--text-secondary) hover:text-(--text-primary)" onclick={goBack}>{m.portal_qs_back()}</button>
        <div class="text-xs text-(--text-secondary)">{selectedClient.label}</div>
      </div>

      <p class="text-xs text-(--text-secondary)">
        {m.portal_qs_config_intro({ client: selectedClient.label })}
      </p>

      <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <button
          type="button"
          data-testid="config-type-full"
          class="rounded-lg border border-(--border) bg-(--bg-card) hover:border-(--accent) p-4 text-left transition disabled:opacity-50 disabled:cursor-not-allowed"
          disabled={!workspaceGrantsLlm}
          title={workspaceGrantsLlm ? '' : m.portal_qs_no_llm_provider()}
          onclick={() => pickConfigType('full')}
        >
          <div class="text-sm font-semibold text-(--text-primary)">{m.portal_qs_full_setup()}</div>
          <div class="mt-1 text-xs text-(--text-secondary)">
            {m.portal_qs_full_setup_desc()}
          </div>
        </button>
        <button
          type="button"
          data-testid="config-type-mcp"
          class="rounded-lg border border-(--border) bg-(--bg-card) hover:border-(--accent) p-4 text-left transition disabled:opacity-50 disabled:cursor-not-allowed"
          disabled={!mcpOnlyHasServers()}
          title={mcpOnlyHasServers() ? '' : m.portal_qs_no_mcp_servers()}
          onclick={() => pickConfigType('mcp')}
        >
          <div class="text-sm font-semibold text-(--text-primary)">{m.portal_qs_mcp_only()}</div>
          <div class="mt-1 text-xs text-(--text-secondary)">
            {m.portal_qs_mcp_only_desc()}
          </div>
        </button>
      </div>
    </div>
  {/if}

  <!-- Step: LLM key -->
  {#if step === 'llm' && selectedClient}
    <div class="space-y-4 max-w-2xl">
      <div class="flex items-center justify-between">
        <button class="text-xs text-(--text-secondary) hover:text-(--text-primary)" onclick={goBack}>{m.portal_qs_back()}</button>
        <div class="text-xs text-(--text-secondary)">{selectedClient.label}</div>
      </div>

      <div class="rounded-lg border border-(--border) bg-(--bg-card) p-4 space-y-3">
        {#if llmTemplateGroups().length > 1}
          <label class="block text-xs text-(--text-secondary)">
            {m.portal_qs_snippet_variant()}
            <SelectInput
              value={selectedClient ? groupIndexFor(selectedClient.templates, selectedTemplateIndex) : undefined}
              onchange={(e) => pickLlmGroup(Number((e.target as HTMLSelectElement).value))}
              class="mt-1"
            >
              {#each llmTemplateGroups() as g (g.index)}
                <option value={g.index}>{g.label}</option>
              {/each}
            </SelectInput>
          </label>
          {#if offersOpenAiAndAnthropic(selectedClient.templates)}
            <p class="text-xs text-(--text-secondary)" data-testid="variant-help">
              {m.portal_qs_snippet_variant_help()}
            </p>
          {/if}
        {/if}

        {@render workspaceLine()}

        <label class="block text-xs text-(--text-secondary)">
          {m.portal_qs_downstream_provider()}
          <SelectInput
            bind:value={llmProviderId}
            class="mt-1"
          >
            <option value="">{m.portal_qs_pick_provider_option()}</option>
            {#each compatibleProviders() as p (p.id)}
              <option value={p.id}>{p.name} · {p.routeCount} {p.routeCount === 1 ? m.portal_qs_model() : m.portal_qs_models()}</option>
            {/each}
            {#if byokProviders.length > 0}
              <optgroup label={m.portal_qs_byok_passthrough_group()}>
                {#each byokProviders as p (p.id)}
                  <option value={p.id}>{p.name} · {m.portal_qs_byok_own_key()}</option>
                {/each}
              </optgroup>
            {/if}
          </SelectInput>
          {#if selectedIsByok}
            <span class="block mt-1 opacity-70">
              {m.portal_qs_byok_help_pre()} <code class="font-mono">vk-</code> {m.portal_qs_byok_help_post()}
            </span>
          {:else}
            <span class="block mt-1 opacity-70">
              {m.portal_qs_provider_help()}
            </span>
          {/if}
        </label>

        {@render keyPicker(
          selectedClient.id,
          true,
          m.portal_qs_byok_fwd_label(),
          m.portal_qs_byok_fwd_help_llm(),
        )}

        {#if keyCfg.mode === 'mint'}
          <fieldset class="text-xs text-(--text-secondary) space-y-1">
            <legend class="font-semibold">{m.portal_qs_expires()}</legend>
            <label class="flex items-center gap-2">
              <input type="radio" value="never" bind:group={expiryChoice} />
              {m.portal_qs_expiry_never()}
            </label>
            <label class="flex items-center gap-2">
              <input type="radio" value="30" bind:group={expiryChoice} />
              {m.portal_qs_expiry_30()}
            </label>
            <label class="flex items-center gap-2">
              <input type="radio" value="90" bind:group={expiryChoice} />
              {m.portal_qs_expiry_90()}
            </label>
            <label class="flex items-center gap-2">
              <input type="radio" value="custom" bind:group={expiryChoice} />
              {m.portal_qs_expiry_custom()}
              {#if expiryChoice === 'custom'}
                <input
                  type="number"
                  min="1"
                  bind:value={expiresInDaysCustom}
                  class="w-20 rounded-sm bg-(--bg-secondary) border border-(--border) px-2 py-0.5"
                />
                {m.portal_qs_days()}
              {/if}
            </label>
          </fieldset>
        {/if}
      </div>

      <button
        type="button"
        onclick={nextFromLlm}
        disabled={rendering}
        class="px-3 py-1.5 rounded-sm bg-(--accent) hover:bg-(--accent-hover) text-(--accent-fg) text-sm disabled:opacity-50"
      >
        {#if templateNeedsMcp(chosenTemplate())}
          {m.portal_qs_continue()}
        {:else}
          {rendering ? m.portal_qs_rendering() : m.portal_qs_render_snippet()}
        {/if}
      </button>
    </div>
  {/if}

  <!-- Step: MCP -->
  {#if step === 'mcp' && selectedClient}
    <div class="space-y-4 max-w-2xl">
      <div class="flex items-center justify-between">
        <button class="text-xs text-(--text-secondary) hover:text-(--text-primary)" onclick={goBack}>{m.portal_qs_back()}</button>
        <div class="text-xs text-(--text-secondary)">{selectedClient.label} · MCP</div>
      </div>

      <div class="rounded-lg border border-(--border) bg-(--bg-card) p-4 space-y-3">
        {#if mcpAuthModeOptions().length > 0}
          <label class="block text-xs text-(--text-secondary)">
            {m.portal_qs_auth_mode()}
            <SelectInput
              bind:value={selectedTemplateIndex}
              class="mt-1"
            >
              {#each mcpAuthModeOptions() as opt (opt.index)}
                <option value={opt.index}>
                  {opt.mode === 'spec_oauth' ? m.portal_qs_auth_oauth() : m.portal_qs_auth_static()}
                </option>
              {/each}
            </SelectInput>
          </label>
        {/if}

        {#if chosenTemplate()?.kind === 'combined'}
          <p class="text-xs text-(--text-secondary)">
            {m.portal_qs_mcp_pick_optional()}
          </p>
        {:else}
          <p class="text-xs text-(--text-secondary)">
            {m.portal_qs_mcp_pick_required()}
          </p>
        {/if}

        {#each sortedVirtualServers() as v (v.id)}
          <label class="flex items-center gap-2 text-sm text-(--text-primary) rounded-sm border border-(--border) bg-(--bg-secondary) p-3">
            <input
              type="checkbox"
              checked={mcpSelected[v.id] ?? false}
              onchange={(e) => (mcpSelected[v.id] = (e.target as HTMLInputElement).checked)}
            />
            <span class="font-semibold">{v.name}</span>
            <span class="text-xs text-(--text-tertiary)">{m.portal_qs_slug_label({ slug: v.slug })}</span>
            {#if v.built_in}
              <span class="px-1 py-0.5 rounded-sm bg-(--bg-card) text-[10px] text-(--text-secondary)">{m.portal_qs_built_in()}</span>
            {/if}
            {#if v.connection_status === 'needs_connection'}
              <a
                href={pthref(slug, '/portal/mcp/connections')}
                data-testid="qs-connect-first"
                class="px-1 py-0.5 rounded-sm bg-(--warning-bg) text-[10px] text-(--warning-text) underline hover:no-underline"
              >{m.portal_qs_connect_first_action()}</a>
            {/if}
            {#if v.fwd_mount}
              <span
                class="px-1 py-0.5 rounded-sm bg-(--bg-card) text-[10px] text-(--text-secondary)"
                title={chosenMcpAuthMode() === 'spec_oauth' ? m.portal_qs_fwd_mount_oauth() : m.portal_qs_fwd_mount_note({ slug: v.slug })}
                data-testid="qs-fwd-mount">{m.portal_qs_fwd_mount()}</span>
            {/if}
            {#if v.client_headers.length > 0}
              <span class="text-[10px] text-(--text-tertiary) font-mono" data-testid="qs-client-headers">{m.portal_qs_client_headers({ headers: v.client_headers.join(', ') })}</span>
            {/if}
          </label>
        {/each}

        {#if sortedVirtualServers().some((v) => v.connection_status === 'needs_connection')}
          <p class="text-[11px] text-(--text-tertiary)">
            {m.portal_qs_connect_first_note()}
            <a href={pthref(slug, '/portal/mcp/connections')} class="text-(--accent) hover:underline">{m.portal_qs_connect_first_link()}</a>
          </p>
        {/if}

        {#if localServers.length > 0 && localMcp === 'none'}
          <p class="text-[11px] text-(--text-tertiary)" data-testid="qs-local-not-offered">{m.portal_qs_local_not_offered()}</p>
        {:else if localServers.length > 0}
          {@const projectOnly = localMcp === 'project'}
          <div class="space-y-2 pt-1" data-testid="qs-local-servers">
            <div class="text-xs font-semibold text-(--text-secondary)">{m.portal_qs_local_title()}</div>
            <p class="text-[11px] text-(--text-tertiary)">{m.portal_qs_local_help()}</p>
            {#if projectOnly}
              <p class="text-[11px] text-(--warning-text)" data-testid="qs-local-project-only">{m.portal_qs_local_project_only()}</p>
            {:else}
              <p class="text-[11px] text-(--text-tertiary)" data-testid="qs-local-runner">{m.portal_qs_local_runner()}</p>
            {/if}
            {#each localServers as l (l.id)}
              {@const toFill = localEnvToFill(l)}
              <label
                class="block space-y-1 text-sm text-(--text-primary) rounded-sm border border-(--border) bg-(--bg-secondary) p-3 {projectOnly ? 'opacity-60' : ''}"
                data-testid="qs-local-server"
              >
                <span class="flex flex-wrap items-center gap-2">
                  <input
                    type="checkbox"
                    checked={!projectOnly && (localSelected[l.id] ?? false)}
                    disabled={projectOnly}
                    onchange={(e) => (localSelected[l.id] = (e.target as HTMLInputElement).checked)}
                  />
                  <span class="font-semibold">{l.name}</span>
                  <span class="text-xs text-(--text-tertiary)">{m.portal_qs_slug_label({ slug: l.slug })}</span>
                  <span class="px-1 py-0.5 rounded-sm bg-(--bg-card) text-[10px] text-(--text-secondary)">{m.portal_qs_local_badge()}</span>
                </span>
                {#if l.description}
                  <span class="block text-xs text-(--text-secondary)">{l.description}</span>
                {/if}
                <span class="block text-[11px] text-(--text-tertiary)">
                  {m.portal_qs_local_command()}
                  <code class="font-mono break-all text-(--text-secondary)" data-testid="qs-local-command">{l.command_line}</code>
                </span>
                {#if toFill.length > 0 && !projectOnly}
                  <span class="block text-[11px] text-(--warning-text)" data-testid="qs-local-fill">
                    {m.portal_qs_local_fill_hint({ names: toFill.join(', ') })}
                  </span>
                {/if}
              </label>
            {/each}
          </div>
        {/if}

        {#if chosenMcpAuthMode() === 'spec_oauth'}
          <div class="text-[11px] text-(--text-tertiary)">
            {m.portal_qs_oauth_note()}
          </div>
          {#if sortedVirtualServers().some((v) => v.fwd_mount && mcpSelected[v.id])}
            <div class="text-[11px] text-(--warning-text)">{m.portal_qs_fwd_mount_oauth()}</div>
          {/if}
        {:else if !templateNeedsLlm(chosenTemplate())}
          <!-- MCP-only static path: the unified key is configured here. -->
          {@render workspaceLine()}
          {#if localOnlySelection}
            <!-- Only local servers are ticked: nothing reaches the gateway,
                 so no key is chosen or minted. -->
            <p class="text-xs text-(--text-secondary)" data-testid="qs-local-no-key">{m.portal_qs_local_no_key()}</p>
          {:else}
            <!-- No BYOK toggle here: whether an MCP server is reached through
                 /fwd is decided per server from the headers its client sends,
                 not by the key. -->
            {@render keyPicker(
              selectedClient.id,
              false,
              m.portal_qs_byok_fwd_label(),
              m.portal_qs_byok_fwd_help_mcp(),
            )}
          {/if}
        {/if}
      </div>

      <button
        type="button"
        onclick={nextFromMcp}
        disabled={rendering}
        class="px-3 py-1.5 rounded-sm bg-(--accent) hover:bg-(--accent-hover) text-(--accent-fg) text-sm disabled:opacity-50"
      >
        {rendering ? m.portal_qs_rendering() : m.portal_qs_render_snippet()}
      </button>
    </div>
  {/if}

  <!-- Step: snippet -->
  {#if step === 'render'}
    <div class="space-y-4">
      <div class="flex items-center justify-between">
        <button class="text-xs text-(--text-secondary) hover:text-(--text-primary)" onclick={startOver}>{m.portal_qs_start_over()}</button>
        <div class="text-xs text-(--text-secondary)">{selectedClient?.label}</div>
      </div>

      {#if switchedAway}
        <div
          role="status"
          data-testid="qs-switched-notice"
          class="flex items-center justify-between gap-3 rounded-sm border border-(--warning-border) bg-(--warning-bg) px-3 py-2 text-xs text-(--warning)"
        >
          <span>{m.portal_qs_switched_notice({ from: workspaceName(wizardWorkspaceId), to: workspaceName(headerWorkspaceId) })}</span>
          <button type="button" onclick={startOver} class="shrink-0 underline" data-testid="qs-start-over-for">
            {m.portal_qs_start_over_for({ workspace: workspaceName(headerWorkspaceId) })}
          </button>
        </div>
      {/if}

      {#if rendered}
        {#if rendered.warnings.length > 0}
          <Callout severity="warning" title={m.portal_qs_mcp_warnings_title()}>
            <ul class="space-y-1" data-testid="qs-mcp-warnings">
              {#each rendered.warnings as w (w.virtual_server_id ?? w.local_server_id ?? w.slug)}
                <li data-testid="qs-mcp-warning" data-reason={w.reason}>
                  <code class="font-mono">{w.local_server_id ? w.slug : `/mcp/${w.slug}`}</code> — {mcpWarningText(w)}
                </li>
              {/each}
            </ul>
          </Callout>
        {/if}
        {#if rendered.minted_keys.length > 0}
          <div class="rounded-sm border border-(--success-border) bg-(--success-bg) px-3 py-2 text-xs text-(--success-text)">
            {m.portal_qs_minted_pre({ count: rendered.minted_keys.length, names: rendered.minted_keys.map((k) => k.name).join(', ') })}
            {m.portal_qs_minted_clipboard_pre()} <strong>{m.portal_qs_copy_with_key()}</strong>{m.portal_qs_minted_clipboard_post()}
          </div>
          {#if renderedLocalFill.length > 0}
            <div class="rounded-sm border border-(--border) bg-(--bg-secondary) px-3 py-2 text-xs text-(--text-secondary)" data-testid="qs-own-values">
              {m.portal_qs_placeholder_own_values_also({ names: renderedLocalFill.join(', ') })}
            </div>
          {/if}
        {:else if !renderedLocalOnly}
          <div class="rounded-sm border border-(--border) bg-(--bg-secondary) px-3 py-2 text-xs text-(--text-secondary)">
            {m.portal_qs_placeholder_pre()}
            <code class="font-mono">&lt;paste-…&gt;</code>
            {m.portal_qs_placeholder_post()}
            {#if renderedLocalFill.length > 0}
              <span data-testid="qs-own-values">{m.portal_qs_placeholder_own_values_also({ names: renderedLocalFill.join(', ') })}</span>
            {/if}
          </div>
        {:else if renderedLocalFill.length > 0}
          <!-- No key in this config: every placeholder is the member's own value. -->
          <div class="rounded-sm border border-(--border) bg-(--bg-secondary) px-3 py-2 text-xs text-(--text-secondary)" data-testid="qs-own-values">
            {m.portal_qs_placeholder_own_values({ names: renderedLocalFill.join(', ') })}
          </div>
        {/if}

        <CodeSnippet
          title={rendered.template.title}
          filename={rendered.template.filename}
          format={rendered.template.format}
          instructions={rendered.template.instructions}
          body={rendered.template.body}
          substitutions={substitutionsFor()}
        />

        <!-- Companion files and steps: part of the config, not an extra. The
             tool reads its credential or its MCP servers from these, so a render
             that hid them would hand the user a config with neither in it. -->
        {#each rendered.companions as companion, i (i)}
          <CodeSnippet
            title={companion.title}
            filename={companion.filename}
            format={companion.format}
            instructions={companion.instructions}
            body={companion.body}
            substitutions={substitutionsFor()}
          />
        {/each}

        {#if keyIsUnreachable}
          <CodeSnippet
            title={m.portal_qs_key_only_title()}
            format="shell"
            instructions={m.portal_qs_key_only_instructions()}
            body={API_KEY_SENTINEL}
            substitutions={substitutionsFor()}
          />
        {/if}

        <div class="flex gap-3">
          <a
            href={pthref(slug, '/portal/keys')}
            class="px-3 py-1.5 rounded-sm border border-(--border) hover:bg-(--bg-elevated) text-sm text-(--text-primary)"
          >
            {m.portal_qs_done_back_to_keys()}
          </a>
          <button
            type="button"
            onclick={startOver}
            class="px-3 py-1.5 rounded-sm bg-(--accent) hover:bg-(--accent-hover) text-(--accent-fg) text-sm"
          >
            {m.portal_qs_build_another()}
          </button>
        </div>
      {/if}
    </div>
  {/if}
{/if}
{/if}
