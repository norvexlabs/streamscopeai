<script module lang="ts">
  import type { UserResponse } from '#lib/api-types.js';

  /** A key owner — a human user, a service account, or the built-in agent. */
  export interface KeyOwner extends UserResponse {
    owner_kind: 'user' | 'service' | 'agent';
  }
</script>

<script lang="ts">
  import type { KeyListItem, UsersKeysDashboardResponse } from '#lib/api-types.js';
  import type { Spend } from '#lib/formatters.js';
  import { toast } from '#lib/toast.svelte.js';
  import { extractError } from '#lib/api-helpers.js';
  import { page } from '$app/state';
  import { thref } from '#lib/tenant.js';
  import UserCard from '#lib/components/UserCard.svelte';

  let slug = $derived(page.params.slug ?? '');
  import ConfirmDialog from '#lib/components/ConfirmDialog.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import FilterBar from '#lib/components/filter/FilterBar.svelte';
  import FilterField from '#lib/components/filter/FilterField.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import { UrlFilters } from '#lib/hooks.svelte.js';
  import { keyKindLabel } from '#lib/keyScopes.js';

  interface Props {
    owners: KeyOwner[];
    keys: KeyListItem[];
    dashboardData: UsersKeysDashboardResponse | null;
    onUserUpdate: (id: string, data: { email?: string; display_name?: string }) => Promise<void>;
    onKeyCreate: (result: { key: string; id: string; name: string | null }) => void;
    onKeyRevoke: (key: KeyListItem) => Promise<void>;
    onKeyUpdate?: () => void;
    onKeyRotate?: (key: KeyListItem) => void;
  }

  let {
    owners,
    keys,
    dashboardData,
    onUserUpdate,
    onKeyCreate,
    onKeyRevoke,
    onKeyUpdate,
    onKeyRotate,
  }: Props = $props();

  // URL-bound filters — refresh / copy-paste preserves the view, and the
  // Service Accounts tab deep-links here with ?owner=<id>.
  const filters = new UrlFilters(['q', 'status', 'kind', 'owner', 'workspace'] as const);
  filters.arm();

  let expandedOwnerId = $state<string | null>(null);

  // Revoke confirmation
  let revokeTarget = $state<KeyListItem | null>(null);

  // Group keys by owner id
  let keysByOwner = $derived.by(() => {
    const map = new Map<string, KeyListItem[]>();
    for (const key of keys) {
      const uid = key.user_id;
      if (!map.has(uid)) map.set(uid, []);
      map.get(uid)!.push(key);
    }
    return map;
  });

  // Workspace options derived from the key inventory itself.
  let workspaceOptions = $derived.by(() => {
    const map = new Map<string, string>();
    for (const k of keys) {
      if (k.workspace_id && k.workspace_name) map.set(k.workspace_id, k.workspace_name);
    }
    return [...map.entries()].sort((a, b) => a[1].localeCompare(b[1]));
  });

  // Usage lookups from dashboardData
  let userUsageMap = $derived.by(() => {
    const map = new Map<string, { request_count: number; spend: Spend | null }>();
    if (dashboardData?.top_users_by_cost) {
      for (const u of dashboardData.top_users_by_cost) {
        map.set(u.user_id, { request_count: u.request_count ?? 0, spend: u.spend ?? null });
      }
    }
    return map;
  });

  let keyUsageLookup = $derived.by(() => {
    const map: Record<string, { total_requests: number; spend: Spend | null; last_used_at: string | null }> = {};
    if (dashboardData?.top_keys_by_requests) {
      for (const k of dashboardData.top_keys_by_requests) {
        map[k.key_id] = { total_requests: k.request_count ?? 0, spend: k.spend ?? null, last_used_at: k.last_used_at ?? null };
      }
    }
    return map;
  });

  function getKeyStatus(key: KeyListItem): 'active' | 'expired' | 'revoked' {
    if (key.revoked_at) return 'revoked';
    if (key.expires_at && new Date(key.expires_at) < new Date()) return 'expired';
    return 'active';
  }

  /** Filters apply PER KEY: a key matches every active key-level criterion or
   *  it is hidden inside its owner group — never "owner matched, show all". */
  function keyMatches(key: KeyListItem, q: string): boolean {
    const status = filters.get('status');
    if (status && ['active', 'expired', 'revoked'].includes(status) && getKeyStatus(key) !== status) {
      return false;
    }
    const kind = filters.get('kind');
    if (kind && key.kind !== kind) return false;
    const workspace = filters.get('workspace');
    if (workspace && key.workspace_id !== workspace) return false;
    if (q) {
      const ownerHit =
        key.owner_email?.toLowerCase().includes(q) ||
        key.owner_display_name?.toLowerCase().includes(q);
      const keyHit =
        key.name?.toLowerCase().includes(q) || key.key_prefix?.toLowerCase().includes(q);
      if (!ownerHit && !keyHit) return false;
    }
    return true;
  }

  let visibleKeysByOwner = $derived.by(() => {
    const q = filters.get('q').trim().toLowerCase();
    const map = new Map<string, KeyListItem[]>();
    for (const [uid, ks] of keysByOwner) {
      map.set(uid, ks.filter((k) => keyMatches(k, q)));
    }
    return map;
  });

  /** Whether any KEY-level criterion is active (drives per-key narrowing +
   *  auto-expansion of matching owners). */
  let keyFilterActive = $derived(
    !!(filters.get('status') && filters.get('status') !== 'disabled_owner') ||
      !!filters.get('kind') ||
      !!filters.get('workspace'),
  );

  let filteredOwners = $derived.by(() => {
    const q = filters.get('q').trim().toLowerCase();
    const ownerFilter = filters.get('owner');
    const status = filters.get('status');
    return owners.filter((o) => {
      if (ownerFilter && o.id !== ownerFilter) return false;
      if (status === 'disabled_owner' && o.is_active) return false;
      const visible = visibleKeysByOwner.get(o.id) ?? [];
      if (keyFilterActive && visible.length === 0) return false;
      if (q) {
        const ownerHit = o.email?.toLowerCase().includes(q) || o.display_name?.toLowerCase().includes(q);
        if (!ownerHit && visible.length === 0) return false;
      }
      return true;
    });
  });

  // Auto-expand owners when narrowing per key, or when deep-linked to one owner.
  let autoExpandedIds = $derived.by(() => {
    if (filters.get('owner') || keyFilterActive) return new Set(filteredOwners.map((o) => o.id));
    return new Set<string>();
  });

  function isExpanded(ownerId: string): boolean {
    return expandedOwnerId === ownerId || autoExpandedIds.has(ownerId);
  }

  /** Keys handed to a card: narrowed when any key-level filter or search is
   *  active, full set otherwise. */
  function cardKeys(ownerId: string): KeyListItem[] {
    const q = filters.get('q').trim();
    if (keyFilterActive || q) return visibleKeysByOwner.get(ownerId) ?? [];
    return keysByOwner.get(ownerId) ?? [];
  }

  const anyFilterActive = $derived(
    !!(filters.get('q') || filters.get('status') || filters.get('kind') || filters.get('owner') || filters.get('workspace')),
  );

  function confirmRevoke(key: KeyListItem) {
    revokeTarget = key;
  }

  async function handleRevoke() {
    if (!revokeTarget) return;
    try {
      await onKeyRevoke(revokeTarget);
    } catch (e) {
      toast.error(extractError(e));
    } finally {
      revokeTarget = null;
    }
  }

</script>

<FilterBar class="mb-5">
  <FilterField label="Search" class="flex-1 min-w-50">
    <input
      type="text"
      bind:value={filters.values.q}
      placeholder="Owner, key name, prefix…"
      class="w-full px-3 py-1.5 bg-(--bg-primary) border border-(--border) rounded-lg text-sm text-(--text-primary) placeholder:text-(--text-secondary)"
    />
  </FilterField>
  <FilterField label="Status" class="min-w-32.5">
    <SelectInput bind:value={filters.values.status}>
      <option value="">All</option>
      <option value="active">Active keys</option>
      <option value="expired">Expired keys</option>
      <option value="revoked">Revoked keys</option>
      <option value="disabled_owner">Disabled owners</option>
    </SelectInput>
  </FilterField>
  <FilterField label="Type" class="min-w-37.5">
    <SelectInput bind:value={filters.values.kind}>
      <option value="">All</option>
      <option value="sk">{keyKindLabel('sk')} (sk-)</option>
      <option value="vk">{keyKindLabel('vk')} (vk-)</option>
      <option value="ak_admin">{keyKindLabel('ak_admin')} (ak-)</option>
      <option value="ak_portal">{keyKindLabel('ak_portal')} (ak-)</option>
    </SelectInput>
  </FilterField>
  <FilterField label="Owner" class="min-w-42.5">
    <SelectInput bind:value={filters.values.owner}>
      <option value="">All</option>
      {#each owners as o (o.id)}
        <option value={o.id}>{o.display_name || o.email}</option>
      {/each}
    </SelectInput>
  </FilterField>
  <FilterField label="Workspace" class="min-w-37.5">
    <SelectInput bind:value={filters.values.workspace}>
      <option value="">All</option>
      {#each workspaceOptions as [id, name] (id)}
        <option value={id}>{name}</option>
      {/each}
    </SelectInput>
  </FilterField>
  {#if anyFilterActive}
    <button
      onclick={() => filters.clear()}
      class="px-3 py-1.5 text-xs text-(--text-secondary) hover:text-(--text-primary) transition-colors"
    >Clear</button>
  {/if}
</FilterBar>

<!-- Owner card list -->
{#if filteredOwners.length > 0}
  <div class="bg-(--bg-card) rounded-xl border border-(--border) divide-y divide-(--border) overflow-hidden">
    {#each filteredOwners as owner (owner.id)}
      <UserCard
        user={owner}
        ownerKind={owner.owner_kind}
        userKeys={cardKeys(owner.id)}
        usageData={userUsageMap.get(owner.id) ?? null}
        keyUsageMap={keyUsageLookup}
        expanded={isExpanded(owner.id)}
        onToggleExpand={() => expandedOwnerId = expandedOwnerId === owner.id ? null : owner.id}
        onUserUpdate={onUserUpdate}
        onKeyCreate={onKeyCreate}
        onKeyRevoke={confirmRevoke}
        {onKeyUpdate}
        {onKeyRotate}
      />
    {/each}
  </div>
{:else}
  <div class="bg-(--bg-card) rounded-xl border border-(--border) p-12 text-center">
    <div class="mx-auto mb-3 inline-block">
      <Icon name="users" size="lg" tone="neutral" />
    </div>
    {#if anyFilterActive}
      <p class="text-sm text-(--text-secondary)">No keys or owners match the filters</p>
    {:else}
      <p class="text-sm text-(--text-secondary)">
        No key owners yet — create accounts under
        <a href={thref(slug, '/auth?tab=accounts')} class="text-(--accent) hover:underline">Auth → Accounts</a>
        or
        <a href={thref(slug, '/auth?tab=service-accounts')} class="text-(--accent) hover:underline">Service Accounts</a>.
      </p>
    {/if}
  </div>
{/if}

<!-- Revoke confirmation -->
<ConfirmDialog
  open={revokeTarget !== null}
  title="Revoke API Key?"
  message={revokeTarget
    ? `This will immediately disable ${revokeTarget.key_prefix}...${revokeTarget.name ? ` (${revokeTarget.name})` : ''}. This action cannot be undone.`
    : ''}
  confirmLabel="Revoke"
  destructive
  onconfirm={handleRevoke}
  oncancel={() => revokeTarget = null}
/>
