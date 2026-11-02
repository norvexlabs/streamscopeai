<script lang="ts">
  /**
   * Workspace **automation** panel (manager-only).
   *
   * A workspace manager provisions long-lived `ak-` automation keys for this
   * workspace — credentials that survive offboarding because they hang off a
   * non-human service account, not a person. Each key authenticates to the portal
   * API as that account with exactly this one workspace's manager authority.
   *
   * Principal-first, mirroring the admin Service Accounts surface: the account is
   * the resource, keys are a sub-resource. Reuses the shared reveal-once modal so
   * the "save it now" UX matches everywhere a key is minted.
   */
  import type { WsAutomationAccount, WsAutomationKeyItem } from '#lib/api-types.js';
  import { portalApi } from '#lib/portal-client.js';
  import { extractError } from '#lib/api-helpers.js';
  import { formatTimeAgo, formatDateTime } from '#lib/formatters.js';
  import { toast } from '#lib/toast.svelte.js';
  import Icon from '#lib/components/Icon.svelte';
  import Modal from '#lib/components/Modal.svelte';
  import FormField from '#lib/components/forms/FormField.svelte';
  import TextInput from '#lib/components/forms/TextInput.svelte';
  import ConfirmDialog from '#lib/components/ConfirmDialog.svelte';
  import RevealKeyModal from '#lib/components/RevealKeyModal.svelte';
  import { portalKeySnippet } from '#lib/keySnippets.js';
  import { presetToExpiresAt, type ExpiryPreset } from '#lib/keyExpiry.js';
  import ExpiryPicker from '#lib/components/forms/ExpiryPicker.svelte';
  import FormError from '#lib/components/forms/FormError.svelte';

  let {
    workspaceId,
    onChanged,
  }: {
    workspaceId: string;
    /** Fired after an automation account is created or revoked — both change the
     *  workspace's membership, so the host page must refresh its roster too. */
    onChanged?: () => void;
  } = $props();

  let accounts = $state<WsAutomationAccount[]>([]);
  let loading = $state(true);
  let selectedId = $state<string | null>(null);
  let keys = $state<WsAutomationKeyItem[]>([]);
  let keysLoading = $state(false);

  // Create-account modal
  let showCreate = $state(false);
  let newName = $state('');
  let creating = $state(false);
  let createError = $state('');

  // Mint-key modal
  let showMint = $state(false);
  let keyName = $state('');
  let keyExpiry = $state<ExpiryPreset | 'custom'>('never');
  let minting = $state(false);
  let mintError = $state('');

  let confirmRevokeAccount = $state<WsAutomationAccount | null>(null);
  let confirmRevoke = $state<{ saId: string; key: WsAutomationKeyItem } | null>(null);
  let revealed = $state<{ key: string; apiBaseUrl: string | null } | null>(null);

  const revealSnippet = $derived(
    revealed ? portalKeySnippet(revealed.key, workspaceId, revealed.apiBaseUrl) : '',
  );

  async function loadAccounts() {
    if (!workspaceId) return;
    loading = true;
    const { data } = await portalApi.GET('/api/v1/portal/workspaces/{id}/automation-accounts', {
      params: { path: { id: workspaceId }, query: { limit: 200 } },
    });
    accounts = data?.items ?? [];
    loading = false;
  }

  async function loadKeys(saId: string) {
    keysLoading = true;
    keys = [];
    const { data } = await portalApi.GET(
      '/api/v1/portal/workspaces/{id}/automation-accounts/{said}/keys',
      { params: { path: { id: workspaceId, said: saId }, query: { limit: 200 } } },
    );
    keys = data?.items ?? [];
    keysLoading = false;
  }

  function toggle(saId: string) {
    if (selectedId === saId) {
      selectedId = null;
      keys = [];
    } else {
      selectedId = saId;
      loadKeys(saId);
    }
  }

  async function createAccount() {
    if (!newName.trim()) return;
    creating = true;
    createError = '';
    const { error } = await portalApi.POST('/api/v1/portal/workspaces/{id}/automation-accounts', {
      params: { path: { id: workspaceId } },
      body: { name: newName.trim() },
    });
    if (error) {
      createError = extractError(error, 'Failed to create automation account');
    } else {
      showCreate = false;
      newName = '';
      await loadAccounts();
      onChanged?.();
    }
    creating = false;
  }

  async function mintKey() {
    if (!selectedId || !keyName.trim()) return;
    minting = true;
    mintError = '';
    const { data, error } = await portalApi.POST(
      '/api/v1/portal/workspaces/{id}/automation-accounts/{said}/keys',
      {
        params: { path: { id: workspaceId, said: selectedId } },
        body: { name: keyName.trim(), expires_at: keyExpiry === 'custom' ? undefined : presetToExpiresAt(keyExpiry) },
      },
    );
    if (error || !data) {
      mintError = extractError(error, 'Failed to mint key');
    } else {
      showMint = false;
      keyName = '';
      revealed = { key: data.key, apiBaseUrl: data.api_base_url ?? null };
      await Promise.all([loadKeys(selectedId), loadAccounts()]);
    }
    minting = false;
  }

  async function doRevokeKey() {
    const target = confirmRevoke;
    confirmRevoke = null;
    if (!target) return;
    const { error } = await portalApi.POST(
      '/api/v1/portal/workspaces/{id}/automation-accounts/{said}/keys/{key_id}/actions/revoke',
      { params: { path: { id: workspaceId, said: target.saId, key_id: target.key.id } } },
    );
    if (error) toast.error(extractError(error, 'Failed to revoke key'));
    else {
      toast.success('Key revoked.');
      await Promise.all([loadKeys(target.saId), loadAccounts()]);
    }
  }

  async function doRevokeAccount() {
    const acct = confirmRevokeAccount;
    confirmRevokeAccount = null;
    if (!acct) return;
    const { error } = await portalApi.POST(
      '/api/v1/portal/workspaces/{id}/automation-accounts/{said}/actions/revoke',
      { params: { path: { id: workspaceId, said: acct.id } } },
    );
    if (error) toast.error(extractError(error, 'Failed to remove account'));
    else {
      toast.success('Automation account removed from this workspace.');
      if (selectedId === acct.id) {
        selectedId = null;
        keys = [];
      }
      await loadAccounts();
      onChanged?.();
    }
  }

  function keyLive(k: WsAutomationKeyItem): boolean {
    return !k.revoked_at && (!k.expires_at || new Date(k.expires_at) > new Date());
  }

  $effect(() => {
    void workspaceId;
    selectedId = null;
    keys = [];
    loadAccounts();
  });
</script>

<div class="bg-(--bg-card) rounded-xl border border-(--border)">
  <div class="flex items-center justify-between px-6 py-4 border-b border-(--border) gap-3">
    <div>
      <h2 class="text-sm font-semibold text-(--text-primary)">Automation</h2>
      <p class="text-xs text-(--text-secondary) mt-0.5">
        Long-lived <code class="font-mono">ak-</code> keys for scripts &amp; agents — they keep
        working after a person leaves. Each acts with this workspace's manager authority.
      </p>
    </div>
    <button
      onclick={() => { newName = ''; createError = ''; showCreate = true; }}
      class="px-3 py-1.5 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-xs font-medium transition-colors shrink-0"
    >+ New account</button>
  </div>

  {#if loading}
    <div class="px-6 py-8 text-center text-xs text-(--text-secondary)">Loading…</div>
  {:else if accounts.length === 0}
    <div class="px-6 py-8 text-center text-sm text-(--text-secondary)">
      No automation accounts yet. Create one to issue <code class="font-mono">ak-</code> keys for this workspace.
    </div>
  {:else}
    <div class="divide-y divide-(--border)">
      {#each accounts as a (a.id)}
        <div class="px-6 py-3">
          <div class="flex items-center justify-between gap-4">
            <span class="min-w-0">
              <span class="inline-flex items-center gap-2">
                <Icon name="key" size="sm" tone="neutral" />
                <span class="text-sm text-(--text-primary)">{a.display_name || a.email}</span>
              </span>
              <span class="block text-xs text-(--text-secondary) font-mono mt-0.5">{a.email}</span>
            </span>
            <span class="flex items-center gap-3 shrink-0">
              <span class="text-xs text-(--text-secondary)">{a.active_keys} key{a.active_keys === 1 ? '' : 's'}</span>
              <button onclick={() => toggle(a.id)} class="text-xs text-(--accent) hover:underline">
                {selectedId === a.id ? 'Hide keys' : 'Manage keys'}
              </button>
              <button onclick={() => (confirmRevokeAccount = a)} class="text-xs text-(--text-secondary) hover:text-(--error) transition-colors">Revoke</button>
            </span>
          </div>

          {#if selectedId === a.id}
            <div class="mt-3 rounded-lg bg-(--bg-primary)/40 p-3">
              <div class="flex items-center justify-between mb-2">
                <span class="text-xs font-semibold text-(--text-secondary) uppercase tracking-wider">Keys</span>
                <button
                  onclick={() => { keyName = ''; keyExpiry = 'never'; mintError = ''; showMint = true; }}
                  class="px-2.5 py-1 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-xs font-medium transition-colors"
                >+ Mint key</button>
              </div>
              {#if keysLoading}
                <div class="py-3 text-center text-xs text-(--text-secondary)">Loading…</div>
              {:else if keys.length === 0}
                <div class="py-3 text-center text-xs text-(--text-secondary)">No keys yet. Mint one above.</div>
              {:else}
                <div class="space-y-1.5">
                  {#each keys as k (k.id)}
                    <div class="flex items-center justify-between px-3 py-2 rounded-lg bg-(--bg-card) border border-(--border) {k.revoked_at ? 'opacity-50' : ''}">
                      <span class="flex items-center gap-3 min-w-0">
                        <span class="text-sm text-(--text-primary)">{k.name || '(unnamed)'}</span>
                        <span class="font-mono text-xs text-(--text-secondary)">{k.key_prefix}…</span>
                        <span class="text-[10px] text-(--text-tertiary)">used {k.last_used_at ? formatTimeAgo(k.last_used_at) : 'never'}{#if k.expires_at} · expires {formatDateTime(k.expires_at)}{/if}</span>
                      </span>
                      <span class="flex items-center gap-3 shrink-0">
                        {#if keyLive(k)}
                          <span class="px-2 py-0.5 text-[10px] rounded-full text-(--success) bg-(--success-bg)">Active</span>
                          <button onclick={() => (confirmRevoke = { saId: a.id, key: k })} class="text-xs text-(--error) hover:underline">Revoke</button>
                        {:else}
                          <span class="px-2 py-0.5 text-[10px] rounded-full text-(--error) bg-(--error-bg)">{k.revoked_at ? 'Revoked' : 'Expired'}</span>
                        {/if}
                      </span>
                    </div>
                  {/each}
                </div>
              {/if}
            </div>
          {/if}
        </div>
      {/each}
    </div>
  {/if}
</div>

<!-- Create account modal -->
<Modal open={showCreate} title="New automation account" onclose={() => (showCreate = false)} maxWidth="max-w-md">
  <div class="space-y-4">
    <FormField label="Name *" help="A non-human identity (e.g. “CI bot”). It manages this workspace and owns the ak- keys you mint.">
      <TextInput bind:value={newName} placeholder="ci-bot" />
    </FormField>
    {#if createError}<FormError message={createError} />{/if}
    <div class="flex items-center justify-end gap-2">
      <button onclick={() => (showCreate = false)} class="px-4 py-1.5 text-sm rounded-lg text-(--text-secondary) hover:text-(--text-primary) transition-colors">Cancel</button>
      <button onclick={createAccount} disabled={creating || !newName.trim()} class="px-4 py-1.5 text-sm rounded-lg bg-(--accent) text-(--accent-fg) hover:bg-(--accent-hover) transition-opacity disabled:opacity-50">
        {creating ? 'Creating…' : 'Create'}
      </button>
    </div>
  </div>
</Modal>

<!-- Mint key modal -->
<Modal open={showMint} title="Mint automation key" onclose={() => (showMint = false)} maxWidth="max-w-md">
  <div class="space-y-4">
    <FormField label="Key name *">
      <TextInput bind:value={keyName} placeholder="ci-deploy" />
    </FormField>
    <ExpiryPicker bind:value={keyExpiry} />
    {#if mintError}<FormError message={mintError} />{/if}
    <div class="flex items-center justify-end gap-2">
      <button onclick={() => (showMint = false)} class="px-4 py-1.5 text-sm rounded-lg text-(--text-secondary) hover:text-(--text-primary) transition-colors">Cancel</button>
      <button onclick={mintKey} disabled={minting || !keyName.trim()} class="px-4 py-1.5 text-sm rounded-lg bg-(--accent) text-(--accent-fg) hover:bg-(--accent-hover) transition-opacity disabled:opacity-50">
        {minting ? 'Creating…' : 'Create key'}
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

<ConfirmDialog
  open={confirmRevoke !== null}
  title="Revoke automation key"
  message="Revoke this key? Anything using it stops working immediately. This cannot be undone."
  confirmLabel="Revoke"
  destructive
  onconfirm={doRevokeKey}
  oncancel={() => (confirmRevoke = null)}
/>

<ConfirmDialog
  open={confirmRevokeAccount !== null}
  title="Revoke automation account"
  message="Revoke this account's workspace access? Its keys here are revoked and it loses manager authority. This cannot be undone."
  confirmLabel="Revoke"
  destructive
  onconfirm={doRevokeAccount}
  oncancel={() => (confirmRevokeAccount = null)}
/>
