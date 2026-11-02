<script lang="ts">
  import KeyBudgetFields from '#lib/components/KeyBudgetFields.svelte';
  import RevealKeyContent from '#lib/components/RevealKeyContent.svelte';
  import ExpiryPicker from '#lib/components/forms/ExpiryPicker.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import { buildKeyBudget, type KeyBudget } from '#lib/keyBudget.js';
  import { presetToExpiresAt } from '#lib/keyExpiry.js';
  import { byokKeySnippet, gatewayKeySnippet } from '#lib/keySnippets.js';
  import FormError from '#lib/components/forms/FormError.svelte';
  import { m } from '#lib/paraglide/messages.js';

  /** Workspace the key can be bound to. The key carries the workspace
   *  forever; the workspace allowlist gates which providers / MCP servers
   *  the key reaches at request time. */
  interface WorkspaceOption {
    id: string;
    name: string;
  }

  /** A BYOK pass-through downstream a vk- key can bind to. */
  interface ByokProvider {
    id: string;
    name: string;
  }

  /** A priority class the key may be minted on. */
  interface QosClassOption {
    id: string;
    name: string;
  }

  interface Props {
    /** Workspaces the target user belongs to. The key is pinned to one. */
    workspaces: WorkspaceOption[];
    /** Pre-selected workspace (the portal's active workspace). Still
     *  overridable from the picker; auto-select wins only when unset. */
    defaultWorkspaceId?: string;
    /** When true, show the per-key budget controls. Admins and workspace
     *  managers may cap a key; self-service members may not. */
    allowBudget?: boolean;
    /** Resolver for the BYOK downstreams a vk- key may bind to, scoped to the
     *  SELECTED workspace (the binding is validated against that workspace, so
     *  offering the caller's whole union would let a non-granted provider 400).
     *  Re-invoked whenever the workspace changes. Absent = no BYOK picker. */
    loadByokProviders?: (workspaceId: string) => Promise<ByokProvider[]>;
    /** The tenant's priority classes, when the caller may choose one. Absent =
     *  no picker, and the key takes the class its minter's principal implies. */
    qosClasses?: QosClassOption[];
    onSubmit: (body: {
      name: string;
      workspace_id: string;
      forward_auth: boolean;
      expires_at?: string;
      budget?: KeyBudget;
      downstream_provider_id?: string;
      qos_class_id?: string;
    }) => Promise<{ id: string; key: string; name: string | null; proxy_base_url?: string | null }>;
    onDone: () => void;
  }

  let { workspaces, defaultWorkspaceId, allowBudget = false, loadByokProviders, qosClasses = [], onSubmit, onDone }: Props = $props();

  let name = $state('');
  let workspaceId = $state('');
  let forwardAuth = $state(false);
  /** BYOK downstreams granted to the selected workspace, resolved on change. */
  let byokProviders = $state<ByokProvider[]>([]);
  /** Chosen BYOK downstream binding (empty = unbound — MCP bring-your-own-token only). */
  let downstreamProviderId = $state('');
  /** Empty = inherit the workspace's own class. */
  let qosClassId = $state('');
  let dailyBudget = $state<string | number>('');
  let monthlyBudget = $state<string | number>('');
  let budgetMode = $state<'enforce' | 'alert_only'>('enforce');

  // Returns the budget payload (or undefined when budgets are not allowed here).
  function computeBudget(): KeyBudget | undefined {
    if (!allowBudget) return undefined;
    return buildKeyBudget(dailyBudget, monthlyBudget, budgetMode);
  }

  // Pre-select the active workspace when it's one the user belongs to, else
  // auto-select when the user belongs to exactly one workspace.
  $effect(() => {
    if (workspaceId) return;
    if (defaultWorkspaceId && workspaces.some((w) => w.id === defaultWorkspaceId)) {
      workspaceId = defaultWorkspaceId;
    } else if (workspaces.length === 1) {
      workspaceId = workspaces[0].id;
    }
  });

  // Resolve the BYOK downstreams granted to the SELECTED workspace so the picker
  // never offers a provider the backend would 400 on. Re-runs on workspace change
  // and drops a binding that the new workspace doesn't grant.
  $effect(() => {
    const ws = workspaceId;
    if (!ws || !loadByokProviders) {
      byokProviders = [];
      return;
    }
    let cancelled = false;
    void loadByokProviders(ws)
      .then((list) => {
        if (cancelled) return;
        byokProviders = list;
        if (downstreamProviderId && !list.some((p) => p.id === downstreamProviderId)) {
          downstreamProviderId = '';
        }
      })
      .catch(() => {
        if (!cancelled) byokProviders = [];
      });
    return () => {
      cancelled = true;
    };
  });
  let expiresAt = $state<'never' | '30d' | '90d' | '1y' | 'custom'>('never');
  let customExpiry = $state('');
  let creating = $state(false);
  let error = $state('');
  let newKeyValue = $state<string | null>(null);
  // Configured gateway origin for the BYOK connection URL; null when the
  // tenant has no `proxy_public_url` set (we then show a relative hint).
  let newKeyProxyBase = $state<string | null>(null);

  function computeExpiresAt(): string | undefined {
    if (expiresAt === 'custom') {
      if (!customExpiry) return undefined;
      return new Date(customExpiry).toISOString();
    }
    return presetToExpiresAt(expiresAt);
  }

  async function handleCreate() {
    creating = true;
    error = '';
    try {
      const result = await onSubmit({
        name: name.trim(),
        workspace_id: workspaceId,
        forward_auth: forwardAuth,
        expires_at: computeExpiresAt(),
        budget: computeBudget(),
        downstream_provider_id:
          forwardAuth && downstreamProviderId ? downstreamProviderId : undefined,
        qos_class_id: qosClassId || undefined,
      });
      newKeyValue = result.key;
      newKeyProxyBase = result.proxy_base_url ?? null;
    } catch (e: unknown) {
      error = e instanceof Error ? e.message : m.portal_comp_failed_create_key();
    } finally {
      creating = false;
    }
  }

  // BYOK keys (vk-) authenticate the /fwd/{key}/... mount where the client
  // supplies its own upstream credential.
  let isByokKey = $derived(newKeyValue?.startsWith('vk-') ?? false);
  // Connection URL for the BYOK mount. Prefer the tenant's configured gateway
  // origin; when unset, show a relative path (served on the gateway origin).
  let byokUrl = $derived(
    newKeyValue
      ? (newKeyProxyBase ? `${newKeyProxyBase}/fwd/${newKeyValue}` : `/fwd/${newKeyValue}`)
      : ''
  );
  let revealSnippet = $derived(
    newKeyValue
      ? (isByokKey ? byokKeySnippet(newKeyValue, newKeyProxyBase) : gatewayKeySnippet(newKeyValue, newKeyProxyBase))
      : ''
  );
</script>

{#if newKeyValue}
  <!-- Reveal-once mode — shared content, identical to RevealKeyModal. -->
  <RevealKeyContent
    keyValue={newKeyValue}
    snippet={revealSnippet}
    byokUrl={isByokKey ? byokUrl : ''}
    byokHint={isByokKey
      ? `${m.portal_comp_byok_hint()}${newKeyProxyBase ? '' : ` ${m.portal_comp_byok_hint_relative()}`}`
      : ''}
    onDone={onDone}
  />
{:else}
  <!-- Form mode -->
  <div class="space-y-3">
    <label class="block">
      <span class="text-[10px] text-(--text-secondary) uppercase tracking-wider mb-1.5 block">{m.portal_comp_key_name()} <span class="text-(--error)">*</span></span>
      <input
        type="text"
        bind:value={name}
        placeholder={m.portal_comp_key_name_required()}
        class="w-full px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-sm text-(--text-primary) placeholder:text-(--text-secondary) focus:outline-hidden focus:border-(--accent)"
      />
    </label>

    <div>
      <label class="text-[10px] text-(--text-secondary) uppercase tracking-wider mb-1.5 block">{m.portal_comp_workspace()} <span class="text-(--error)">*</span>
        <SelectInput
          bind:value={workspaceId}
        >
          <option value="" disabled>{m.portal_comp_select_workspace()}</option>
          {#each workspaces as w}
            <option value={w.id}>{w.name}</option>
          {/each}
        </SelectInput>
      </label>
      <p class="text-[10px] text-(--text-secondary) mt-1">
        {m.portal_comp_key_pinned_workspace()}
      </p>
    </div>

    <div>
      <span class="text-[10px] text-(--text-secondary) uppercase tracking-wider mb-1.5 block">{m.portal_comp_key_type()}</span>
      <div class="flex items-center gap-1">
        <button onclick={() => { forwardAuth = false; }}
          class="px-3 py-1.5 rounded-lg text-sm font-medium transition-colors
            {!forwardAuth ? 'bg-(--accent) text-(--accent-fg) border border-(--accent)' : 'bg-(--bg-primary) text-(--text-secondary) border border-(--border) hover:text-(--text-primary)'}"
        >{m.portal_comp_standard_sk()}</button>
        <button onclick={() => { forwardAuth = true; }}
          class="px-3 py-1.5 rounded-lg text-sm font-medium transition-colors
            {forwardAuth ? 'bg-(--warning) text-(--warning-fg) border border-(--warning)' : 'bg-(--bg-primary) text-(--text-secondary) border border-(--border) hover:text-(--text-primary)'}"
        >{m.portal_comp_byok_vk()}</button>
      </div>
      {#if forwardAuth}
        <p class="text-[10px] text-(--text-secondary) mt-1">{m.portal_comp_byok_client_credential()} <code class="font-mono">/fwd/{'{key}'}/</code> {m.portal_comp_byok_route_suffix()}</p>
      {/if}
    </div>

    {#if forwardAuth && byokProviders.length > 0}
      <div>
        <label class="text-[10px] text-(--text-secondary) uppercase tracking-wider mb-1.5 block">{m.portal_comp_byok_provider_label()}
          <SelectInput
            bind:value={downstreamProviderId}
          >
            <option value="">{m.portal_comp_byok_provider_none()}</option>
            {#each byokProviders as p}
              <option value={p.id}>{p.name}</option>
            {/each}
          </SelectInput>
        </label>
        <p class="text-[10px] text-(--text-secondary) mt-1">
          {m.portal_comp_byok_provider_help_prefix()} <em>{m.portal_comp_byok_provider_none_word()}</em> {m.portal_comp_byok_provider_help_suffix()}
        </p>
      </div>
    {/if}

    {#if qosClasses.length > 0}
      <div>
        <label class="text-[10px] text-(--text-secondary) uppercase tracking-wider mb-1.5 block">
          {m.portal_comp_qos_class_label()}
          <SelectInput bind:value={qosClassId}>
            <option value="">{m.portal_comp_qos_class_inherit()}</option>
            {#each qosClasses as c (c.id)}
              <option value={c.id}>{c.name}</option>
            {/each}
          </SelectInput>
        </label>
        <p class="text-[10px] text-(--text-secondary) mt-1">{m.portal_comp_qos_class_help()}</p>
      </div>
    {/if}

    <ExpiryPicker bind:value={expiresAt} bind:customValue={customExpiry} allowCustom={true} />

    {#if allowBudget}
      <KeyBudgetFields bind:daily={dailyBudget} bind:monthly={monthlyBudget} bind:mode={budgetMode} />
    {/if}

    {#if error}
      <div data-testid="create-error"><FormError message={error} /></div>
    {/if}

    <div class="flex items-center justify-end gap-2">
      <button
        onclick={onDone}
        class="px-4 py-1.5 text-sm rounded-lg text-(--text-secondary) hover:text-(--text-primary) transition-colors"
      >
        {m.portal_comp_cancel()}
      </button>
      <button
        onclick={handleCreate}
        disabled={creating || !name.trim() || !workspaceId}
        class="px-4 py-1.5 text-sm rounded-lg bg-(--accent) text-(--accent-fg) hover:bg-(--accent-hover) transition-opacity disabled:opacity-50"
      >
        {creating ? m.portal_comp_creating() : m.portal_comp_create()}
      </button>
    </div>
  </div>
{/if}
