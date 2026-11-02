<script lang="ts">
  /**
   * Mint a key for a SERVICE ACCOUNT — admin automation (`ak-`) or gateway
   * (`sk-`/`vk-`). The single mint surface for service-account keys (Keys page);
   * humans use `CreateKeyForm`. Reveal-once + resolved curl snippet via the
   * shared `RevealKeyModal`. In SYSTEM scope only the Operator (super-admin)
   * `ak-` shape is offered — the SYSTEM tenant runs no workloads.
   */
  import { adminApi } from '#lib/api-client.js';
  import { extractError } from '#lib/api-helpers.js';
  import { page } from '$app/state';
  import Modal from '#lib/components/Modal.svelte';
  import FormField from '#lib/components/forms/FormField.svelte';
  import TextInput from '#lib/components/forms/TextInput.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import ScopePicker, { type ScopeOption } from '#lib/components/forms/ScopePicker.svelte';
  import ExpiryPicker from '#lib/components/forms/ExpiryPicker.svelte';
  import FormError from '#lib/components/forms/FormError.svelte';
  import KeyBudgetFields from '#lib/components/KeyBudgetFields.svelte';
  import RevealKeyModal from '#lib/components/RevealKeyModal.svelte';
  import { buildKeyBudget } from '#lib/keyBudget.js';
  import { mintedKeySnippet } from '#lib/keySnippets.js';
  import { presetToExpiresAt, type ExpiryPreset } from '#lib/keyExpiry.js';

  let {
    open,
    serviceAccountId,
    serviceAccountName = '',
    onClose,
    onMinted,
  }: {
    open: boolean;
    serviceAccountId: string | null;
    serviceAccountName?: string;
    onClose: () => void;
    /** Called after a successful mint (post-reveal refresh hook). */
    onMinted: () => void;
  } = $props();

  const tenantSlug = $derived(page.data.user?.tenant_slug ?? 'system');
  const isSystemTenant = $derived(tenantSlug === 'system');
  // The operator scope is only mintable by a super-admin in the SYSTEM tenant.
  const canOperator = $derived(!!page.data.user?.is_super_admin && isSystemTenant);

  interface WorkspaceOpt { id: string; name: string }

  let keyType = $state<'admin' | 'gateway'>('admin');
  let keyName = $state('');
  let adminScope = $state('read_only');
  let forwardAuth = $state(false);
  let gwWorkspaceId = $state('');
  let dailyBudget = $state<string | number>('');
  let monthlyBudget = $state<string | number>('');
  let budgetMode = $state<'enforce' | 'alert_only'>('enforce');
  let expiresAt = $state<ExpiryPreset | 'custom'>('never');
  let minting = $state(false);
  let mintError = $state('');
  let workspaces = $state<WorkspaceOpt[]>([]);

  // Reveal-once
  let revealed = $state<{
    key: string;
    plane: string;
    proxyBaseUrl: string | null;
    apiBaseUrl: string | null;
  } | null>(null);

  // Reset + (lazily) load workspaces each time the modal opens.
  let openedFor = $state<string | null>(null);
  $effect(() => {
    if (open && serviceAccountId && openedFor !== serviceAccountId) {
      openedFor = serviceAccountId;
      keyType = 'admin';
      keyName = '';
      adminScope = isSystemTenant ? 'super_admin' : 'read_only';
      forwardAuth = false;
      gwWorkspaceId = '';
      dailyBudget = '';
      monthlyBudget = '';
      budgetMode = 'enforce';
      expiresAt = 'never';
      mintError = '';
      if (!isSystemTenant) {
        adminApi
          .GET('/api/v1/admin/workspaces', { params: { query: { offset: 0, limit: 200 } } })
          .then(({ data }) => {
            workspaces = (data?.items ?? []).map((w) => ({ id: w.id, name: w.name }));
            if (workspaces.length === 1) gwWorkspaceId = workspaces[0].id;
          });
      }
    } else if (!open) {
      openedFor = null;
    }
  });

  async function mintKey() {
    if (!serviceAccountId || !keyName.trim()) return;
    if (keyType === 'gateway' && !gwWorkspaceId) {
      mintError = 'Select a workspace for the gateway key.';
      return;
    }
    minting = true;
    mintError = '';
    const budget = keyType === 'gateway' ? buildKeyBudget(dailyBudget, monthlyBudget, budgetMode) : undefined;
    const { data, error } = await adminApi.POST('/api/v1/admin/service-accounts/{id}/keys', {
      params: { path: { id: serviceAccountId } },
      body: {
        type: keyType,
        name: keyName.trim(),
        admin_scope: keyType === 'admin' ? adminScope : undefined,
        workspace_id: keyType === 'gateway' ? gwWorkspaceId : undefined,
        forward_auth: keyType === 'gateway' ? forwardAuth : undefined,
        budget,
        expires_at: expiresAt === 'custom' ? undefined : presetToExpiresAt(expiresAt),
      },
    });
    if (error) {
      mintError = extractError(error, 'Failed to mint key');
    } else if (data) {
      revealed = {
        key: data.key,
        plane: data.plane,
        proxyBaseUrl: data.proxy_base_url ?? null,
        apiBaseUrl: data.api_base_url ?? null,
      };
      onClose();
      onMinted();
    }
    minting = false;
  }

  const revealSnippet = $derived(
    revealed
      ? mintedKeySnippet(revealed.plane, revealed.key, {
          proxyBaseUrl: revealed.proxyBaseUrl,
          apiBaseUrl: revealed.apiBaseUrl,
        })
      : '',
  );

  // The same authority vocabulary as console roles (ScopePicker everywhere).
  const scopeOptions = $derived.by((): ScopeOption[] => {
    if (isSystemTenant) {
      return [{
        value: 'super_admin',
        label: 'Operator (super-admin)',
        description: 'Cross-tenant control plane — the only scope minted in the system tenant.',
      }];
    }
    const opts: ScopeOption[] = [
      { value: 'read_only', label: 'Read-only', description: 'View everything; mutations are refused.' },
      { value: 'admin', label: 'Admin', description: 'Manage everything in this tenant.' },
    ];
    if (canOperator) {
      opts.push({
        value: 'super_admin',
        label: 'Operator (super-admin)',
        description: 'Cross-tenant control plane (system tenant only).',
      });
    }
    return opts;
  });
</script>

<Modal {open} title={`Add key${serviceAccountName ? ` — ${serviceAccountName}` : ''}`} onclose={onClose} maxWidth="max-w-md">
  <div class="space-y-4">
    {#if isSystemTenant}
      <p class="text-xs text-(--text-secondary)">
        The system tenant mints only <strong>Operator (super-admin)</strong> automation keys —
        cross-tenant control-plane credentials. No gateway keys exist here.
      </p>
    {:else}
      <div>
        <span class="text-[10px] text-(--text-secondary) uppercase tracking-wider mb-1.5 block">Key Type</span>
        <div class="flex items-center gap-1">
          <button onclick={() => { keyType = 'admin'; }}
            class="px-3 py-1.5 rounded-lg text-sm font-medium transition-colors {keyType === 'admin' ? 'bg-(--accent) text-(--accent-fg) border border-(--accent)' : 'bg-(--bg-primary) text-(--text-secondary) border border-(--border) hover:text-(--text-primary)'}"
          >Admin automation (ak-)</button>
          <button onclick={() => { keyType = 'gateway'; }}
            class="px-3 py-1.5 rounded-lg text-sm font-medium transition-colors {keyType === 'gateway' ? 'bg-(--accent) text-(--accent-fg) border border-(--accent)' : 'bg-(--bg-primary) text-(--text-secondary) border border-(--border) hover:text-(--text-primary)'}"
          >Gateway (sk-)</button>
        </div>
      </div>
    {/if}

    <FormField label="Key Name *">
      <TextInput bind:value={keyName} placeholder="ci-deploy" />
    </FormField>

    {#if keyType === 'admin'}
      <ScopePicker label="Scope" options={scopeOptions} bind:value={adminScope} />
    {:else}
      <FormField label="Workspace *" help="Gateway keys bind to a workspace — its provider/MCP allowlist + budget govern the key. The account joins the workspace automatically.">
        <SelectInput bind:value={gwWorkspaceId}>
          <option value="" disabled>-- Select workspace --</option>
          {#each workspaces as w}
            <option value={w.id}>{w.name}</option>
          {/each}
        </SelectInput>
      </FormField>
      <div>
        <span class="text-[10px] text-(--text-secondary) uppercase tracking-wider mb-1.5 block">Gateway Type</span>
        <div class="flex items-center gap-1">
          <button onclick={() => { forwardAuth = false; }}
            class="px-3 py-1.5 rounded-lg text-sm font-medium transition-colors {!forwardAuth ? 'bg-(--accent) text-(--accent-fg) border border-(--accent)' : 'bg-(--bg-primary) text-(--text-secondary) border border-(--border) hover:text-(--text-primary)'}"
          >Standard (sk-)</button>
          <button onclick={() => { forwardAuth = true; }}
            class="px-3 py-1.5 rounded-lg text-sm font-medium transition-colors {forwardAuth ? 'bg-(--warning) text-(--warning-fg) border border-(--warning)' : 'bg-(--bg-primary) text-(--text-secondary) border border-(--border) hover:text-(--text-primary)'}"
          >BYOK (vk-)</button>
        </div>
      </div>
      <KeyBudgetFields bind:daily={dailyBudget} bind:monthly={monthlyBudget} bind:mode={budgetMode} />
    {/if}

    <ExpiryPicker bind:value={expiresAt} />

    <FormError message={mintError} />

    <div class="flex items-center justify-end gap-2">
      <button onclick={onClose} class="px-4 py-1.5 text-sm rounded-lg text-(--text-secondary) hover:text-(--text-primary) transition-colors">Cancel</button>
      <button onclick={mintKey} disabled={minting || !keyName.trim()} class="px-4 py-1.5 text-sm rounded-lg bg-(--accent) text-(--accent-fg) hover:bg-(--accent-hover) transition-opacity disabled:opacity-50">
        {minting ? 'Creating…' : 'Create Key'}
      </button>
    </div>
  </div>
</Modal>

<RevealKeyModal
  open={!!revealed}
  keyValue={revealed?.key ?? null}
  snippet={revealSnippet}
  onclose={() => (revealed = null)}
/>
