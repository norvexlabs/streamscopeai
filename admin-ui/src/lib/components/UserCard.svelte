<script lang="ts">
  import type { UserResponse, KeyListItem } from '#lib/api-types.js';
  import { formatCount, formatSpend, type Spend } from '#lib/formatters.js';
  import { adminApi } from '#lib/api-client.js';
  import { extractError } from '#lib/api-helpers.js';
  import KeyCard from '#lib/components/KeyCard.svelte';
  import CreateKeyForm from '#lib/components/CreateKeyForm.svelte';
  import KeyBudgetModal from '#lib/components/KeyBudgetModal.svelte';
  import Modal from '#lib/components/Modal.svelte';
  import MintAutomationKeyModal from '#lib/components/MintAutomationKeyModal.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import TagBadge from '#lib/components/TagBadge.svelte';
  import { toast } from '#lib/toast.svelte.js';
  import { page } from '$app/state';
  import { thref } from '#lib/tenant.js';
  import type { KeyBudget } from '#lib/keyBudget.js';

  let slug = $derived(page.params.slug ?? '');
  import { ownerKindLabel } from '#lib/keyScopes.js';
  import FormError from '#lib/components/forms/FormError.svelte';

  interface Props {
    user: UserResponse;
    /** `user` (human) | `service` (service account) | `agent` (built-in agent).
     *  Non-human owners mint via the automation modal and manage their account
     *  lifecycle on the Auth → Service Accounts tab, not here. */
    ownerKind?: 'user' | 'service' | 'agent';
    userKeys: KeyListItem[];
    usageData: { request_count: number; spend: Spend | null } | null;
    keyUsageMap: Record<string, { total_requests: number; spend: Spend | null; last_used_at: string | null }>;
    expanded: boolean;
    onToggleExpand: () => void;
    onUserUpdate: (id: string, data: { email?: string; display_name?: string }) => Promise<void>;
    onKeyCreate: (result: { key: string; id: string; name: string | null }) => void;
    onKeyRevoke: (key: KeyListItem) => void;
    onKeyUpdate?: () => void;
    /** Rotate a service-account key (transactional server action). */
    onKeyRotate?: (key: KeyListItem) => void;
  }

  let {
    user,
    ownerKind = 'user',
    userKeys,
    usageData,
    keyUsageMap,
    expanded,
    onToggleExpand,
    onUserUpdate,
    onKeyCreate,
    onKeyRevoke,
    onKeyUpdate,
    onKeyRotate,
  }: Props = $props();

  const isHuman = $derived(ownerKind === 'user');
  const isSystemTenant = $derived(page.data?.user?.tenant_slug === 'system');
  let showMintAutomation = $state(false);

  // Edit-budget modal for an existing key.
  let budgetKey = $state<KeyListItem | null>(null);
  async function saveKeyBudget(budget: KeyBudget | null) {
    if (!budgetKey) return;
    const { error: err } = await adminApi.PATCH('/api/v1/admin/keys/{id}', {
      params: { path: { id: budgetKey.id } },
      // `null` clears the per-key cap; a present object replaces the triple.
      body: { budget: budget ?? { daily_budget: null, monthly_budget: null, budget_mode: 'enforce' } },
    });
    if (err) throw new Error(extractError(err, 'Failed to update budget'));
    toast.success('Budget updated');
    onKeyUpdate?.();
  }

  let editing = $state(false);
  let editValue = $state('');
  let editSaving = $state(false);
  let showCreateKey = $state(false);
  let workspaces = $state<{ id: string; name: string }[]>([]);
  let workspacesError = $state('');

  async function openCreateKey() {
    workspacesError = '';
    // The key is pinned to a workspace the user belongs to.
    const { data, error: err } = await adminApi.GET('/api/v1/admin/users/{id}', {
      params: { path: { id: user.id } },
    });
    if (err || !data) {
      workspacesError = extractError(err, 'Failed to load workspaces');
      return;
    }
    workspaces = data.workspace_memberships.map((m) => ({
      id: m.workspace_id,
      name: m.workspace_name,
    }));
    showCreateKey = true;
  }

  /** The tenant's priority classes, for the key form's picker. An admin may put
   *  a key on any of them; the API records an elevation above the workspace. */
  let qosClasses = $state<{ id: string; name: string }[]>([]);
  $effect(() => {
    if (!showCreateKey || qosClasses.length > 0) return;
    void adminApi.GET('/api/v1/admin/qos-classes', {}).then(({ data }) => {
      qosClasses = (data?.items ?? []).map((c) => ({ id: c.id, name: c.name }));
    });
  });

  async function handleCreateKeySubmit(body: {
    name: string;
    workspace_id: string;
    forward_auth: boolean;
    expires_at?: string;
    budget?: { daily_budget?: number | null; monthly_budget?: number | null; budget_mode: string };
    qos_class_id?: string;
  }): Promise<{ id: string; key: string; name: string | null; proxy_base_url?: string | null }> {
    const { data, error: err } = await adminApi.POST('/api/v1/admin/keys', {
      body: {
        user_id: user.id,
        workspace_id: body.workspace_id,
        name: body.name,
        expires_at: body.expires_at,
        forward_auth: body.forward_auth || undefined,
        budget: body.budget,
        qos_class_id: body.qos_class_id,
      },
    });
    if (err || !data) throw new Error(extractError(err, 'Failed to create key'));
    onKeyCreate({ key: data.key, id: data.id, name: data.name ?? null });
    return { id: data.id, key: data.key, name: data.name ?? null, proxy_base_url: data.proxy_base_url };
  }

  const avatarLetter = $derived((user.email || '?')[0].toUpperCase());
  const activeKeyCount = $derived(userKeys.filter((k: KeyListItem) => !k.revoked_at).length);

  function startEdit() {
    editValue = user.display_name || '';
    editing = true;
  }

  function cancelEdit() {
    editing = false;
  }

  async function saveEdit() {
    if (editSaving) return;
    const trimmed = editValue.trim();
    if (trimmed === (user.display_name || '')) {
      editing = false;
      return;
    }
    editSaving = true;
    try {
      await onUserUpdate(user.id, { email: user.email, display_name: trimmed || undefined });
      editing = false;
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : 'Failed to save display name');
    } finally {
      editSaving = false;
    }
  }

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Enter') {
      saveEdit();
    } else if (e.key === 'Escape') {
      cancelEdit();
    }
  }

</script>

<div class="hover:bg-(--bg-elevated) transition-colors">
  <!-- Row is mouse-click shortcut; chevron button is the sole focus target so the
       row-wide focus ring (giant blue rectangle) never appears. -->
  <!-- svelte-ignore a11y_click_events_have_key_events -->
  <!-- svelte-ignore a11y_no_static_element_interactions -->
  <div class="px-4 py-3 flex items-center gap-3 cursor-pointer" onclick={onToggleExpand}>
    <!-- Avatar -->
    <div class="w-8 h-8 rounded-full bg-(--accent)/10 flex items-center justify-center text-xs font-medium text-(--accent) shrink-0">
      {avatarLetter}
    </div>

    <!-- Info -->
    <div class="flex-1 min-w-0">
      <div class="flex items-center gap-2">
        <span class="text-sm text-(--text-primary) font-medium truncate">
          {user.email}
        </span>
        {#if user.display_name}
          <span class="text-xs text-(--text-secondary) truncate">({user.display_name})</span>
        {/if}
        {#if ownerKind !== 'user'}
          <TagBadge color={ownerKind === 'agent' ? 'cyan' : 'violet'}>{ownerKindLabel(ownerKind)}</TagBadge>
        {/if}
      </div>
      <div class="flex items-center gap-2 mt-0.5 text-[10px] text-(--text-secondary)">
        <span class="px-1.5 py-0.5 rounded-full font-medium shrink-0
          {user.is_active
            ? 'bg-(--success)/10 text-(--success) border border-(--success)'
            : 'bg-(--error)/10 text-(--error) border border-(--error)'}">
          {user.is_active ? 'Active' : 'Disabled'}
        </span>
        <span class="opacity-40">&middot;</span>
        <span class="font-mono tabular-nums">{activeKeyCount} key{activeKeyCount === 1 ? '' : 's'}</span>
        {#if usageData}
          <span class="opacity-40">&middot;</span>
          <span class="font-mono tabular-nums">{formatCount(usageData.request_count)} reqs</span>
          <span class="opacity-40">&middot;</span>
          <span class="font-mono tabular-nums">{formatSpend(usageData.spend)}</span>
        {/if}
      </div>
    </div>

    <!-- Chevron — the official disclosure button and sole focus target -->
    <button
      type="button"
      class="shrink-0 p-1 text-(--text-secondary) hover:text-(--text-primary) rounded-sm"
      aria-expanded={expanded}
      aria-label="{expanded ? 'Collapse' : 'Expand'} details for {user.email}"
      onclick={(e) => { e.stopPropagation(); onToggleExpand(); }}
    >
      <span class="inline-flex transition-transform duration-200 {expanded ? 'rotate-180' : ''}">
        <Icon name="chevronDown" size="sm" tone="neutral" />
      </span>
    </button>
  </div>

  <!-- Expanded details -->
  {#if expanded}
    <div class="border-t border-(--border) px-4 py-4 space-y-4">
      <!-- User info: display name + status toggle -->
      <div class="flex items-center justify-between gap-4">
        <div class="flex items-center gap-2 text-sm min-w-0">
          <span class="text-(--text-secondary) shrink-0">Display Name:</span>
          {#if editing}
            <input
              bind:value={editValue}
              class="px-2 py-1 bg-(--bg-primary) border border-(--accent) rounded-sm text-sm text-(--text-primary) focus:outline-hidden"
              onkeydown={handleKeydown}
              onblur={saveEdit}
            />
          {:else}
            <span
              class="cursor-pointer hover:text-(--accent) text-(--text-primary) truncate transition-colors"
              onclick={startEdit}
              role="button"
              tabindex="0"
              onkeydown={(e) => { if (e.key === 'Enter') startEdit(); }}
            >
              {user.display_name || 'No name'}
            </span>
          {/if}
        </div>
        <div class="flex items-center gap-2 shrink-0">
          <!-- Account LIFECYCLE (disable/enable/revoke) lives on the Auth page —
               this page manages keys only. -->
          {#if isHuman}
            <a href={thref(slug, '/auth?tab=accounts')} class="text-xs text-(--accent) hover:underline">
              Manage account in Auth → Accounts
            </a>
          {:else}
            <a href={thref(slug, '/auth?tab=service-accounts')} class="text-xs text-(--accent) hover:underline">
              Manage account in Auth → Service Accounts
            </a>
          {/if}
        </div>
      </div>

      <!-- Keys section -->
      <div>
        <div class="flex items-center justify-between mb-3">
          <span class="text-sm font-medium text-(--text-primary)">
            Keys ({userKeys.length})
          </span>
        </div>

        {#if userKeys.length > 0}
          <div class="space-y-2">
            {#each userKeys as key (key.id)}
              <KeyCard
                key_data={key}
                usage={keyUsageMap[key.id] || null}
                onRevoke={onKeyRevoke}
                onEditBudget={(k) => { budgetKey = k; }}
                onRotate={ownerKind === 'service' ? onKeyRotate : undefined}
              />
            {/each}
          </div>
        {:else}
          <p class="text-xs text-(--text-secondary) py-2">No keys</p>
        {/if}

        {#if ownerKind === 'agent'}
          <p class="mt-3 text-xs text-(--text-secondary)">
            The agent's key is managed automatically — rotate it from Auth → Service Accounts.
          </p>
        {:else if isHuman && isSystemTenant}
          <p class="mt-3 text-xs text-(--text-secondary)">
            The system tenant runs no gateway workloads — no gateway keys here.
          </p>
        {:else}
          <button
            class="mt-3 flex items-center gap-1.5 text-xs text-(--accent) hover:text-(--accent-hover) transition-colors font-medium"
            onclick={() => (isHuman ? openCreateKey() : (showMintAutomation = true))}
          >
            <Icon name="plus" size="sm" tone="neutral" />
            New Key
          </button>
        {/if}
        {#if workspacesError}
          <div class="mt-2"><FormError message={workspacesError} /></div>
        {/if}
      </div>
    </div>
  {/if}
</div>

<Modal open={showCreateKey} title="Create API Key" onclose={() => showCreateKey = false} maxWidth="max-w-lg">
  {#if workspaces.length === 0}
    <p class="text-sm text-(--text-secondary)">
      This user is not a member of any workspace. Add them to a workspace first.
    </p>
  {:else}
    <CreateKeyForm
      {workspaces}
      {qosClasses}
      allowBudget={true}
      onSubmit={handleCreateKeySubmit}
      onDone={() => showCreateKey = false}
    />
  {/if}
</Modal>

<MintAutomationKeyModal
  open={showMintAutomation}
  serviceAccountId={user.id}
  serviceAccountName={user.display_name || user.email}
  onClose={() => (showMintAutomation = false)}
  onMinted={() => onKeyUpdate?.()}
/>

<KeyBudgetModal
  open={budgetKey !== null}
  keyId={budgetKey?.id ?? null}
  keyName={budgetKey?.name ?? null}
  daily={budgetKey?.daily_budget}
  monthly={budgetKey?.monthly_budget}
  mode={budgetKey?.budget_mode}
  dailySpent={budgetKey?.daily_spent}
  monthlySpent={budgetKey?.monthly_spent}
  onSave={saveKeyBudget}
  onClose={() => { budgetKey = null; }}
/>
