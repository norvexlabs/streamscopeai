<script lang="ts">
  // Keys — THE key management surface: every key in the tenant (user gateway
  // keys, service-account gateway + automation keys, the agent's key) in one
  // filterable inventory grouped by owner. Account lifecycle lives elsewhere
  // (humans + service accounts: Auth page); this page manages keys.
  import { adminApi } from '#lib/api-client.js';
  import { extractError, fetchAllPages } from '#lib/api-helpers.js';
  import type { UserResponse, KeyListItem, UsersKeysDashboardResponse } from '#lib/api-types.js';
  import { CONFIG_USAGE_WINDOW_DAYS } from '#lib/constants.js';
  import UsersManagement, { type KeyOwner } from '#lib/components/UsersManagement.svelte';
  import RevealKeyModal from '#lib/components/RevealKeyModal.svelte';
  import { mintedKeySnippet } from '#lib/keySnippets.js';
  import { usePeriodicLoad } from '#lib/hooks.svelte.js';
  import { toast } from '#lib/toast.svelte.js';

  interface SaListItem {
    id: string;
    email: string;
    display_name?: string | null;
    is_active: boolean;
    is_builtin: boolean;
    created_at: string;
  }

  let owners = $state<KeyOwner[]>([]);
  let keys = $state<KeyListItem[]>([]);
  let dashboardData = $state<UsersKeysDashboardResponse | null>(null);

  async function fetchOwners(): Promise<KeyOwner[]> {
    const [humans, saItems] = await Promise.all([
      fetchAllPages<UserResponse>((offset, limit) =>
        adminApi.GET('/api/v1/admin/users', { params: { query: { offset, limit, kind: 'human' } } })),
      fetchAllPages<SaListItem>((offset, limit) =>
        adminApi.GET('/api/v1/admin/service-accounts', { params: { query: { offset, limit } } })),
    ]);
    const sas: KeyOwner[] = saItems.map((sa) => ({
      id: sa.id,
      email: sa.email,
      display_name: sa.display_name ?? null,
      tenant_id: '',
      is_active: sa.is_active,
      created_at: sa.created_at,
      workspaces: [],
      owner_kind: sa.is_builtin ? ('agent' as const) : ('service' as const),
    }));
    const humanOwners: KeyOwner[] = humans.map((u) => ({ ...u, owner_kind: 'user' as const }));
    return [...humanOwners, ...sas].sort((a, b) => a.email.localeCompare(b.email));
  }

  async function fetchAllKeys(): Promise<KeyListItem[]> {
    return fetchAllPages<KeyListItem>((offset, limit) =>
      adminApi.GET('/api/v1/admin/keys', { params: { query: { offset, limit, plane: 'all' } } }));
  }

  // Only the latest read lands: a refresh read before a save must not put the
  // old state back after the save's own re-read.
  let keysGen = 0;
  let ownersGen = 0;
  async function reloadOwners() {
    const gen = ++ownersGen;
    const o = await fetchOwners();
    if (gen === ownersGen) owners = o;
  }
  async function reloadKeys() {
    const gen = ++keysGen;
    const k = await fetchAllKeys();
    if (gen === keysGen) keys = k;
  }

  async function loadAll() {
    const kGen = ++keysGen;
    const oGen = ++ownersGen;
    try {
      const [o, k] = await Promise.all([fetchOwners(), fetchAllKeys()]);
      // Each lands only if no re-read of it started since (a save's own).
      if (oGen === ownersGen) owners = o;
      if (kGen === keysGen) keys = k;
    } catch (e) {
      toast.error(extractError(e));
    }
    try {
      // Keys is a management page — its usage tile renders over a fixed recent
      // window (tenant-wide), not the dashboard header lens.
      const { data } = await adminApi.GET('/api/v1/admin/analytics/users-keys', { params: { query: { days: CONFIG_USAGE_WINDOW_DAYS } } });
      if (data) dashboardData = data;
    } catch (e) {
      toast.error(extractError(e));
    }
  }

  async function handleUserUpdate(id: string, data: { email?: string; display_name?: string }) {
    const { error: err } = await adminApi.PATCH('/api/v1/admin/users/{id}', { params: { path: { id } }, body: data });
    if (err) throw new Error(extractError(err, 'Failed to update user'));
    await reloadOwners();
  }

  // Revoke routes by key family: automation keys live under the owning
  // service account; gateway keys have their own action.
  async function handleKeyRevoke(key: KeyListItem) {
    const isAutomation = key.kind === 'ak_admin' || key.kind === 'ak_portal';
    const { error: err } = isAutomation
      ? await adminApi.POST('/api/v1/admin/service-accounts/{id}/keys/{key_id}/actions/revoke', {
          params: { path: { id: key.user_id, key_id: key.id } },
        })
      : await adminApi.POST('/api/v1/admin/keys/{id}/actions/revoke', { params: { path: { id: key.id } } });
    if (err) { toast.error(extractError(err, 'Failed to revoke key')); return; }
    await reloadKeys();
  }

  // Rotate a service-account key: ONE transactional server action mints the
  // same-shape replacement (lifetime restarted from now) and revokes the old —
  // a mid-way failure can never leave the old credential dangling.
  let rotated = $state<{
    key: string;
    plane: string;
    proxyBaseUrl: string | null;
    apiBaseUrl: string | null;
    workspaceId: string | null;
  } | null>(null);
  const rotatedSnippet = $derived(
    rotated
      ? mintedKeySnippet(rotated.plane, rotated.key, {
          proxyBaseUrl: rotated.proxyBaseUrl,
          apiBaseUrl: rotated.apiBaseUrl,
          workspaceId: rotated.workspaceId,
        })
      : '',
  );

  async function handleKeyRotate(key: KeyListItem) {
    const { data, error: err } = await adminApi.POST(
      '/api/v1/admin/service-accounts/{id}/keys/{key_id}/actions/rotate',
      { params: { path: { id: key.user_id, key_id: key.id } } },
    );
    if (err) { toast.error(extractError(err, 'Failed to rotate key')); return; }
    if (data) {
      rotated = {
        key: data.key,
        plane: data.plane,
        proxyBaseUrl: data.proxy_base_url ?? null,
        apiBaseUrl: data.api_base_url ?? null,
        workspaceId: key.workspace_id ?? null,
      };
      await reloadKeys();
    }
  }

  function handleKeyCreate() {
    void reloadKeys();
  }

  usePeriodicLoad(loadAll);
</script>

<div>
  <!-- Header -->
  <div class="flex items-center justify-between mb-6">
    <div>
      <h1 class="text-2xl font-semibold text-(--text-primary)">Keys</h1>
      <p class="text-sm text-(--text-secondary) mt-1">{owners.length} owners, {keys.length} keys — every gateway and automation key in one place</p>
    </div>
  </div>

  <UsersManagement
    {owners}
    {keys}
    {dashboardData}
    onUserUpdate={handleUserUpdate}
    onKeyCreate={handleKeyCreate}
    onKeyRevoke={handleKeyRevoke}
    onKeyUpdate={handleKeyCreate}
    onKeyRotate={handleKeyRotate}
  />
</div>

<RevealKeyModal
  open={!!rotated}
  keyValue={rotated?.key ?? null}
  snippet={rotatedSnippet}
  title="Key rotated — save the new key now"
  onclose={() => (rotated = null)}
/>
