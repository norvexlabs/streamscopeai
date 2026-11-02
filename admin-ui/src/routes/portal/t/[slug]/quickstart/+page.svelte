<script lang="ts">
  import { portalApi } from '#lib/portal-client.js';
  import { extractError, extractErrorCode, fetchAllPages } from '#lib/api-helpers.js';
  import { portalScope } from '#lib/scope.svelte.js';
  import CodeSnippet from '#lib/components/CodeSnippet.svelte';
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
    offersOpenAiAndAnthropic,
    sameGroup,
    templateNeedsLlm,
  } from '#lib/clientTemplates.js';
  import type { PageProps } from './$types';

  let { params }: PageProps = $props();

  let slug = $derived(params.slug);

  // ---------- Setup mode: web wizard vs the ssai CLI ----------
  type SetupTab = 'wizard' | 'cli';
  let setupTab = $state<SetupTab>(getTabFromUrl(['wizard', 'cli'], 'wizard'));
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
  type PortalWorkspace = components['schemas']['PortalWorkspaceInfo'];
  type QuickstartKey = components['schemas']['QuickstartKey'];

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
  let virtualServers = $state<PortalMcpVirtualServer[]>([]);
  let workspaces = $state<PortalWorkspace[]>([]);
  // BYOK pass-through downstreams (empty by default → no routes), offered in the
  // provider picker so a client can be provisioned host-only against them.
  let byokProviders = $state<{ id: string; name: string; upstreamProtocol: string | null }[]>([]);
  let loading = $state(true);
  let loadError = $state('');

  // ---------- Wizard state ----------
  let step = $state<WizardStep>('client');
  let renderError = $state('');
  let renderErrorCode = $state<string | null>(null);
  let rendering = $state(false);
  let rendered = $state<RenderResponse | null>(null);

  // Selected client + template
  let selectedClient = $state<ClientProfile | null>(null);
  let selectedTemplateIndex = $state<number>(0);
  // Whether the user picked the snippet variant themselves — then a provider
  // change never moves it.
  let variantPicked = $state(false);

  // The workspace the key is pinned to, and the one unified key for the render.
  let selectedWorkspaceId = $state<string>('');
  let keyCfg = $state<KeyConfig>(emptyKey());

  // LLM step — which provider the snippet defaults its model from.
  let llmProviderId = $state<string>('');
  type ExpiryChoice = 'never' | '30' | '90' | 'custom';
  let expiryChoice = $state<ExpiryChoice>('never');
  let expiresInDaysCustom = $state<number>(30);

  // MCP step — selection only; the unified key covers every ticked server.
  let mcpSelected = $state<Record<string, boolean>>({});

  $effect(() => {
    void loadInitial();
  });

  // Resolve the BYOK pass-through downstreams granted to the SELECTED workspace
  // (the render binds/validates against it, so the unscoped union would offer a
  // provider that then fails). Reads state only inside the async callback so the
  // effect depends solely on `selectedWorkspaceId` (no reactive loop on the
  // `byokProviders` it writes).
  $effect(() => {
    const ws = selectedWorkspaceId;
    if (!ws) return;
    let cancelled = false;
    void portalApi
      .GET('/api/v1/portal/auth/me', { params: { query: { workspace_id: ws } } })
      .then(({ data, error }) => {
        // Keep the current list on a transient failure — never wipe BYOK options
        // to empty just because one scoped re-fetch errored.
        if (cancelled || error || !data) return;
        const next = (data.downstream_providers ?? [])
          .filter((p) => p.byok)
          .map((p) => ({ id: p.id, name: p.name, upstreamProtocol: p.upstream_protocol ?? null }));
        const wasByok = byokProviders.some((p) => p.id === llmProviderId);
        byokProviders = next;
        // Clear a BYOK provider selection the new workspace no longer grants.
        if (wasByok && !next.some((p) => p.id === llmProviderId)) llmProviderId = '';
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
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

  async function loadInitial() {
    loading = true;
    loadError = '';
    try {
      const [clientsRes, routesList, vsList, meRes] = await Promise.all([
        portalApi.GET('/api/v1/portal/quickstart/clients'),
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
      if (clientsRes.error) {
        loadError = extractError(clientsRes.error, m.portal_qs_err_load_clients());
        return;
      }
      clients = clientsRes.data?.clients ?? [];
      routes = routesList;
      virtualServers = vsList;
      workspaces = meRes.data?.workspaces ?? [];
      // `byokProviders` is resolved per selected workspace by the effect below —
      // the unscoped `me` union would offer a provider the chosen workspace
      // doesn't grant (rejected at render). Default to the portal's active
      // workspace when the user is a member;
      // else fall back to the first membership. Overridable in the wizard.
      const active = portalScope.activeWorkspace;
      selectedWorkspaceId =
        (active && workspaces.some((w) => w.id === active) ? active : workspaces[0]?.id) ?? '';
      mcpSelected = Object.fromEntries(virtualServers.map((v) => [v.id, false]));
    } finally {
      loading = false;
    }
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
  /** Show the `config` step only when the client supports both shapes. */
  function clientNeedsConfigChoice(): boolean {
    return clientHasFull() && clientHasMcpOnly();
  }

  /** The chosen template's MCP auth mode; `static` when none is chosen. */
  function chosenMcpAuthMode(): McpAuthMode {
    return mcpAuthModeOf(chosenTemplate() ?? {});
  }

  /** `true` when the render needs a key minted/reused — every path except a
   *  pure spec-OAuth MCP template (OAuth mints no key). */
  function renderNeedsKey(): boolean {
    const t = chosenTemplate();
    if (templateNeedsLlm(t)) return true;
    if (t && templateNeedsMcp(t) && mcpAuthModeOf(t) === 'static') return true;
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
      const e = grouped.get(r.provider_id);
      if (e) e.count += 1;
      else grouped.set(r.provider_id, { name: r.provider_name, count: 1 });
    }
    return [...grouped.entries()].map(([id, v]) => ({ id, name: v.name, routeCount: v.count }));
  }

  /** Virtual servers for the Step-`mcp` checkbox list — built-in first, then
   *  alphabetical by name. */
  function sortedVirtualServers(): PortalMcpVirtualServer[] {
    return [...virtualServers].sort((a, b) => {
      if (a.built_in !== b.built_in) return a.built_in ? -1 : 1;
      return a.name.localeCompare(b.name);
    });
  }

  // ---------- Key reuse / mint loading ----------
  /** Load the keys already minted in the selected workspace so the user can
   *  reuse one instead of minting another. */
  async function loadWorkspaceKeys() {
    keyCfg.keys = [];
    if (!selectedWorkspaceId) return;
    const workspaceId = selectedWorkspaceId;
    const keys = await fetchAllPages<QuickstartKey>((offset, limit) =>
      portalApi.GET('/api/v1/portal/quickstart/keys', {
        params: { query: { workspace_id: workspaceId, offset, limit } },
      })).catch(() => []);
    // The user may have picked another workspace while this one loaded.
    if (selectedWorkspaceId !== workspaceId) return;
    keyCfg.keys = keys;
    keyCfg.mode = keyCfg.keys.length > 0 ? 'reuse' : 'mint';
    keyCfg.reuseKeyId = keyCfg.keys[0]?.id ?? '';
    // Name left blank — the input shows the suggested name as a placeholder;
    // an empty submit lets the backend pick the next free suffix.
  }

  async function selectWorkspace(id: string) {
    selectedWorkspaceId = id;
    await loadWorkspaceKeys();
  }

  // ---------- Navigation ----------
  async function pickClient(c: ClientProfileSummary) {
    renderError = '';
    renderErrorCode = null;
    rendered = null;
    selectedTemplateIndex = 0;
    variantPicked = false;
    const { data, error: err } = await portalApi.GET(
      '/api/v1/portal/quickstart/clients/{id}',
      { params: { path: { id: c.id } } },
    );
    if (err || !data) {
      renderError = extractError(err, m.portal_qs_err_load_client_profile());
      return;
    }
    selectedClient = data;
    await loadWorkspaceKeys();
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

  /** Enter the MCP-only path: select the first `kind = "mcp"` template and
   *  open the MCP step, skipping the LLM model entirely. */
  function enterMcpOnly() {
    if (!selectedClient) return;
    const firstMcp = selectedClient.templates.findIndex((t) => t.kind === 'mcp');
    selectedTemplateIndex = firstMcp >= 0 ? firstMcp : 0;
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
      if (!selectedWorkspaceId) return m.portal_qs_err_pick_workspace();
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
    const selected = virtualServers.filter((v) => mcpSelected[v.id]);
    if (tmpl?.kind === 'mcp' && selected.length === 0) {
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
    return virtualServers
      .filter((v) => mcpSelected[v.id])
      .map((v) => ({ virtual_server_id: v.id }));
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
      const body: components['schemas']['RenderRequest'] = {
        client_id: selectedClient.id,
        template_index: selectedTemplateIndex,
        workspace_id: selectedWorkspaceId,
        key: buildKeySpec(),
        llm_provider_id: templateNeedsLlm(tmpl) ? llmProviderId : undefined,
        mcp_servers: buildMcpServers(tmpl),
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
      rendered = data;
      step = 'render';
    } finally {
      rendering = false;
    }
  }

  function goBack() {
    renderError = '';
    const idx = shownSteps.indexOf(step);
    const prev = idx > 0 ? shownSteps[idx - 1] : undefined;
    if (prev) step = prev;
  }

  function reset() {
    selectedClient = null;
    selectedTemplateIndex = 0;
    variantPicked = false;
    rendered = null;
    renderError = '';
    renderErrorCode = null;
    llmProviderId = '';
    keyCfg = emptyKey();
    expiryChoice = 'never';
    expiresInDaysCustom = 30;
    mcpSelected = Object.fromEntries(virtualServers.map((v) => [v.id, false]));
    step = 'client';
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

{#snippet workspacePicker()}
  <label class="block text-xs text-(--text-secondary)">
    {m.portal_qs_workspace_label()}
    <SelectInput
      value={selectedWorkspaceId}
      onchange={(e) => selectWorkspace((e.target as HTMLSelectElement).value)}
      class="mt-1"
    >
      {#each workspaces as w (w.id)}
        <option value={w.id}>{w.name}</option>
      {/each}
    </SelectInput>
    <span class="block mt-1 opacity-70">
      {m.portal_qs_workspace_help()}
    </span>
  </label>
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
    { id: 'wizard', label: m.portal_qs_tab_wizard() },
    { id: 'cli', label: m.portal_qs_tab_cli() },
  ]}
  active={setupTab}
  onchange={(t) => (setupTab = t as SetupTab)}
/>

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
  <div class="mt-6 text-sm text-(--error)">{loadError}</div>
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
  {#if step === 'client'}
    <div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
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
          disabled={routes.length === 0}
          title={routes.length === 0 ? m.portal_qs_no_llm_provider() : ''}
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
          disabled={virtualServers.length === 0}
          title={virtualServers.length === 0 ? m.portal_qs_no_mcp_servers() : ''}
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

        {@render workspacePicker()}

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
              <span class="px-1 py-0.5 rounded-sm bg-(--warning-bg) text-[10px] text-(--warning-text)">{m.portal_qs_connect_first()}</span>
            {/if}
          </label>
        {/each}

        {#if sortedVirtualServers().some((v) => v.connection_status === 'needs_connection')}
          <p class="text-[11px] text-(--text-tertiary)">
            {m.portal_qs_connect_first_note()}
            <a href={pthref(slug, '/portal/mcp/connections')} class="text-(--accent) hover:underline">{m.portal_qs_connect_first_link()}</a>
          </p>
        {/if}

        {#if chosenMcpAuthMode() === 'spec_oauth'}
          <div class="text-[11px] text-(--text-tertiary)">
            {m.portal_qs_oauth_note()}
          </div>
        {:else if !templateNeedsLlm(chosenTemplate())}
          <!-- MCP-only static path: the unified key is configured here. -->
          {@render workspacePicker()}
          {@render keyPicker(
            selectedClient.id,
            true,
            m.portal_qs_byok_fwd_label(),
            m.portal_qs_byok_fwd_help_mcp(),
          )}
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
        <button class="text-xs text-(--text-secondary) hover:text-(--text-primary)" onclick={reset}>{m.portal_qs_start_over()}</button>
        <div class="text-xs text-(--text-secondary)">{selectedClient?.label}</div>
      </div>

      {#if rendered}
        {#if rendered.minted_keys.length > 0}
          <div class="rounded-sm border border-(--success-border) bg-(--success-bg) px-3 py-2 text-xs text-(--success-text)">
            {m.portal_qs_minted_pre({ count: rendered.minted_keys.length, names: rendered.minted_keys.map((k) => k.name).join(', ') })}
            {m.portal_qs_minted_clipboard_pre()} <strong>{m.portal_qs_copy_with_key()}</strong>{m.portal_qs_minted_clipboard_post()}
          </div>
        {:else}
          <div class="rounded-sm border border-(--border) bg-(--bg-secondary) px-3 py-2 text-xs text-(--text-secondary)">
            {m.portal_qs_placeholder_pre()}
            <code class="font-mono">&lt;paste-…&gt;</code>
            {m.portal_qs_placeholder_post()}
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
            onclick={reset}
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
