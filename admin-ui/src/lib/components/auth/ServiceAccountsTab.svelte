<script lang="ts">
  // Service accounts — non-human principals for automation. This tab manages
  // the ACCOUNT lifecycle only (create, disable/enable, revoke, and the two
  // built-in managed-key rotations: agent, and inline-AI whose rotate reveals
  // the new key once); all key management lives on the Keys page, which this
  // tab deep-links into per account.
  import { adminApi } from '#lib/api-client.js';
  import { extractError, fetchAllPages } from '#lib/api-helpers.js';
  import { goto } from '$app/navigation';
  import { page } from '$app/state';
  import { thref } from '#lib/tenant.js';
  import Icon from '#lib/components/Icon.svelte';
  import Modal from '#lib/components/Modal.svelte';
  import FormField from '#lib/components/forms/FormField.svelte';
  import TextInput from '#lib/components/forms/TextInput.svelte';
  import FormError from '#lib/components/forms/FormError.svelte';
  import ConfirmDialog from '#lib/components/ConfirmDialog.svelte';
  import EmptyState from '#lib/components/EmptyState.svelte';
  import RevealKeyModal from '#lib/components/RevealKeyModal.svelte';
  import Skeleton from '#lib/components/Skeleton.svelte';
  import TagBadge from '#lib/components/TagBadge.svelte';
  import { formatTimeAgo } from '#lib/formatters.js';
  import { toast } from '#lib/toast.svelte.js';
  import { usePeriodicLoad } from '#lib/hooks.svelte.js';

  interface SaItem {
    id: string;
    email: string;
    display_name?: string | null;
    is_active: boolean;
    is_builtin: boolean;
    created_at: string;
    active_keys: number;
    last_used_at?: string | null;
  }

  let isSystemTenant = $derived(page.data?.user?.tenant_slug === 'system');
  let slug = $derived(page.params.slug ?? '');

  let accounts = $state<SaItem[]>([]);
  let loading = $state(true);
  let loadError = $state('');

  // Create form
  let showCreate = $state(false);
  let newName = $state('');
  let newEmail = $state('');
  let creating = $state(false);
  let createError = $state('');

  // Action confirms
  let confirmAction = $state<{ sa: SaItem; verb: 'disable' | 'enable' | 'revoke' | 'rotate' } | null>(null);
  let actionBusy = $state(false);
  // The built-in inline-AI account: its rotate reveals the new key once (the
  // credential the operator pastes into the external analyzer).
  const INLINE_AI_EMAIL = 'inline-ai@streamscope.internal';
  let revealedKey = $state<string | null>(null);

  async function load() {
    loading = accounts.length === 0;
    loadError = '';
    try {
      accounts = await fetchAllPages<SaItem>((offset, limit) =>
        adminApi.GET('/api/v1/admin/service-accounts', { params: { query: { offset, limit } } }));
    } catch (e: unknown) {
      loadError = e instanceof Error ? e.message : 'Failed to load service accounts';
    }
    loading = false;
  }

  function openCreate() {
    newName = '';
    newEmail = '';
    createError = '';
    showCreate = true;
  }

  async function createAccount() {
    if (!newName.trim()) return;
    creating = true;
    createError = '';
    const { data, error } = await adminApi.POST('/api/v1/admin/service-accounts', {
      body: {
        name: newName.trim(),
        email: newEmail.trim() || undefined,
      },
    });
    if (error) {
      createError = extractError(error, 'Failed to create service account');
    } else {
      showCreate = false;
      await load();
      // Keys are attached on the Keys page — jump straight there, filtered.
      if (data?.id) await goto(thref(slug, `/users?owner=${data.id}`));
    }
    creating = false;
  }

  const confirmCopy = $derived.by(() => {
    if (!confirmAction) return { title: '', message: '', label: '', destructive: false };
    const name = confirmAction.sa.display_name || confirmAction.sa.email;
    switch (confirmAction.verb) {
      case 'disable':
        return {
          title: 'Disable service account',
          message: `Disable "${name}"? Its keys stop authenticating but are kept — enabling the account restores them.`,
          label: 'Disable',
          destructive: true,
        };
      case 'enable':
        return {
          title: 'Enable service account',
          message: `Enable "${name}"? All its non-revoked keys start authenticating again.`,
          label: 'Enable',
          destructive: false,
        };
      case 'revoke':
        return {
          title: 'Revoke service account',
          message: `Revoke "${name}"? The account is disabled and ALL its keys are permanently revoked. This cannot be undone.`,
          label: 'Revoke',
          destructive: true,
        };
      case 'rotate':
        if (confirmAction.sa.email === INLINE_AI_EMAIL) {
          return {
            title: 'Rotate inline-AI key',
            message: 'Mint a fresh inline-AI key and revoke the current one? The new key is shown ONCE — paste it into your external analyzer\'s configuration. The analyzer keeps working on the old key until the next config sync, then must use the new one.',
            label: 'Rotate & reveal',
            destructive: false,
          };
        }
        return {
          title: 'Rotate agent key',
          message: 'Mint a fresh key for the built-in agent and revoke the current one? The agent picks the new key up automatically; edges receive it on the next config sync.',
          label: 'Rotate',
          destructive: false,
        };
    }
  });

  async function runAction() {
    if (!confirmAction) return;
    const { sa, verb } = confirmAction;
    actionBusy = true;
    // The inline-AI rotate is reveal-once: a distinct route whose response
    // carries the new plaintext, shown in the standard reveal modal.
    if (verb === 'rotate' && sa.email === INLINE_AI_EMAIL) {
      const { data, error } = await adminApi.POST(
        '/api/v1/admin/service-accounts/{id}/actions/rotate-inline-ai-key',
        { params: { path: { id: sa.id } } }
      );
      if (error) {
        toast.error(extractError(error, 'Failed to rotate'));
      } else if (data) {
        revealedKey = data.key;
        await load();
      }
      actionBusy = false;
      confirmAction = null;
      return;
    }
    const path =
      verb === 'rotate'
        ? ('/api/v1/admin/service-accounts/{id}/actions/rotate-agent-key' as const)
        : verb === 'disable'
          ? ('/api/v1/admin/service-accounts/{id}/actions/disable' as const)
          : verb === 'enable'
            ? ('/api/v1/admin/service-accounts/{id}/actions/enable' as const)
            : ('/api/v1/admin/service-accounts/{id}/actions/revoke' as const);
    const { data, error } = await adminApi.POST(path, { params: { path: { id: sa.id } } });
    if (error) {
      toast.error(extractError(error, `Failed to ${verb}`));
    } else {
      toast.success(data?.message ?? 'Done');
      await load();
    }
    actionBusy = false;
    confirmAction = null;
  }

  usePeriodicLoad(load, load);
</script>

<div class="space-y-4">
  <div class="flex items-start justify-between gap-4">
    <p class="text-sm text-(--text-secondary) max-w-2xl">
      Non-human identities for agents, applications, and automation. A service account never signs
      in and isn't tied to any person — its keys keep working after someone leaves.
      {#if isSystemTenant}
        System-tenant service accounts hold <strong>Operator (super-admin)</strong> automation keys only.
      {:else}
        Attach admin automation keys (<code class="font-mono">ak-</code>) or gateway keys
        (<code class="font-mono">sk-</code>) on the <a href={thref(slug, '/users')} class="text-(--accent) hover:underline">Keys</a> page.
      {/if}
    </p>
    <button
      onclick={openCreate}
      class="shrink-0 px-3 py-1.5 bg-(--accent) hover:bg-(--accent-hover) text-(--accent-fg) rounded-lg text-sm font-medium transition-colors"
    >
      + New Service Account
    </button>
  </div>

  <FormError message={loadError} />

  {#if loading}
    <div class="space-y-2">
      <Skeleton variant="row" />
      <Skeleton variant="row" />
    </div>
  {:else if accounts.length === 0}
    <EmptyState title="No service accounts" body="Create one to give an agent or script a durable, auditable credential that survives offboarding.">
      {#snippet icon()}<Icon name="key" size="lg" tone="neutral" />{/snippet}
    </EmptyState>
  {:else}
    <div class="bg-(--bg-card) rounded-xl border border-(--border) overflow-hidden">
      <table class="w-full text-sm">
        <thead>
          <tr class="border-b border-(--border) bg-(--bg-primary)/30">
            <th class="px-4 py-2.5 text-left text-xs text-(--text-secondary) uppercase tracking-wider">Name</th>
            <th class="px-4 py-2.5 text-left text-xs text-(--text-secondary) uppercase tracking-wider">Email</th>
            <th class="px-4 py-2.5 text-left text-xs text-(--text-secondary) uppercase tracking-wider">Status</th>
            <th class="px-4 py-2.5 text-right text-xs text-(--text-secondary) uppercase tracking-wider">Active Keys</th>
            <th class="px-4 py-2.5 text-right text-xs text-(--text-secondary) uppercase tracking-wider">Last Used</th>
            <th class="px-4 py-2.5 text-right text-xs text-(--text-secondary) uppercase tracking-wider">Actions</th>
          </tr>
        </thead>
        <tbody>
          {#each accounts as sa (sa.id)}
            <tr class="border-b border-(--border) last:border-0">
              <td class="px-4 py-3">
                <span class="inline-flex items-center gap-2 text-(--text-primary) font-medium">
                  <Icon name="key" size="sm" tone="neutral" />
                  {sa.display_name || sa.email}
                  {#if sa.is_builtin}
                    <TagBadge color="cyan">Built-in agent</TagBadge>
                  {/if}
                </span>
              </td>
              <td class="px-4 py-3 font-mono text-xs text-(--text-secondary)">{sa.email}</td>
              <td class="px-4 py-3">
                {#if sa.is_active}
                  <TagBadge color="teal">Active</TagBadge>
                {:else}
                  <TagBadge color="neutral">Disabled</TagBadge>
                {/if}
              </td>
              <td class="px-4 py-3 text-right">
                <a
                  href={thref(slug, `/users?owner=${sa.id}`)}
                  class="font-mono tabular-nums text-(--accent) hover:underline"
                  title="Manage this account's keys"
                >{sa.active_keys}</a>
              </td>
              <td class="px-4 py-3 text-right text-(--text-secondary)">
                {sa.last_used_at ? formatTimeAgo(sa.last_used_at) : '—'}
              </td>
              <td class="px-4 py-3 text-right whitespace-nowrap">
                {#if sa.is_builtin}
                  <button onclick={() => (confirmAction = { sa, verb: 'rotate' })}
                    class="text-xs px-2 py-1 rounded-sm text-(--text-secondary) hover:text-(--accent) transition-colors">Rotate key</button>
                {:else}
                  {#if sa.is_active}
                    <button onclick={() => (confirmAction = { sa, verb: 'disable' })}
                      class="text-xs px-2 py-1 rounded-sm text-(--text-secondary) hover:text-(--warning) transition-colors">Disable</button>
                  {:else}
                    <button onclick={() => (confirmAction = { sa, verb: 'enable' })}
                      class="text-xs px-2 py-1 rounded-sm text-(--text-secondary) hover:text-(--success) transition-colors">Enable</button>
                  {/if}
                  <button onclick={() => (confirmAction = { sa, verb: 'revoke' })}
                    class="text-xs px-2 py-1 rounded-sm text-(--text-secondary) hover:text-(--error) transition-colors">Revoke</button>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>

<Modal open={showCreate} title="New Service Account" onclose={() => (showCreate = false)} maxWidth="max-w-md">
  <div class="space-y-4">
    <FormField label="Name *">
      <TextInput bind:value={newName} placeholder="CI bot" />
    </FormField>
    <FormField label="Email" help="Login-less identity. Leave blank to auto-derive (svc-…@<tenant>.service).">
      <TextInput bind:value={newEmail} placeholder="(auto)" />
    </FormField>
    <FormError message={createError} />
    <div class="flex items-center justify-end gap-2">
      <button
        onclick={() => (showCreate = false)}
        class="px-4 py-1.5 text-sm rounded-lg text-(--text-secondary) hover:text-(--text-primary) transition-colors"
      >
        Cancel
      </button>
      <button
        onclick={createAccount}
        disabled={creating || !newName.trim()}
        class="px-4 py-1.5 text-sm rounded-lg bg-(--accent) text-(--accent-fg) hover:bg-(--accent-hover) transition-opacity disabled:opacity-50"
      >
        {creating ? 'Creating…' : 'Create'}
      </button>
    </div>
  </div>
</Modal>

<ConfirmDialog
  open={confirmAction !== null}
  title={confirmCopy.title}
  message={confirmCopy.message}
  confirmLabel={actionBusy ? '…' : confirmCopy.label}
  destructive={confirmCopy.destructive}
  onconfirm={runAction}
  oncancel={() => (confirmAction = null)}
/>

<RevealKeyModal
  open={revealedKey !== null}
  keyValue={revealedKey}
  title="Inline-AI key rotated — save it now"
  onclose={() => (revealedKey = null)}
/>
