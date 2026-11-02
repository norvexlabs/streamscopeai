<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import type { UsersKeysDashboardResponse } from '#lib/api-types.js';
  import { consoleScope, currentWorkspaceQuery, currentPeriodQuery } from '#lib/scope.svelte.js';
  import { usePeriodicLoad } from '#lib/hooks.svelte.js';
  import DashboardScaffold from '#lib/components/dashboard/DashboardScaffold.svelte';
  import UsersDashboard from '#lib/components/UsersDashboard.svelte';

  let data = $state<UsersKeysDashboardResponse | null>(null);
  let loading = $state(true);

  // Only the latest read lands: a refresh read before a revoke must not list
  // the revoked key again after the revoke's own re-read.
  let loadGen = 0;
  async function loadDashboard() {
    const gen = ++loadGen;
    loading = true;
    try {
      const res = await adminApi.GET('/api/v1/admin/analytics/users-keys', {
        params: { query: { ...currentPeriodQuery(), ...currentWorkspaceQuery() } },
      });
      if (gen !== loadGen) return;
      if (res.data) data = res.data;
    } finally {
      if (gen === loadGen) loading = false;
    }
  }

  async function revokeDormantKey(keyId: string) {
    const { error } = await adminApi.POST('/api/v1/admin/keys/{id}/actions/revoke', {
      params: { path: { id: keyId } },
    });
    if (!error) await loadDashboard();
  }

  usePeriodicLoad(loadDashboard);
</script>

<DashboardScaffold title="Users" subtitle="Per-user activity, key usage, dormant keys">
  <UsersDashboard {data} {loading} periodDays={consoleScope.periodDays} onRevokeDormantKey={revokeDormantKey} />
</DashboardScaffold>
