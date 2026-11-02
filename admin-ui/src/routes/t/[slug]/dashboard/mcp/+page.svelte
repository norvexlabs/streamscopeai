<script lang="ts">
  import { useLoadView } from '#lib/loadView.svelte.js';
  import { adminApi } from '#lib/api-client.js';
  import type { components } from '#lib/generated/api-types.js';
  import { usePeriodicLoad } from '#lib/hooks.svelte.js';
  import DashboardScaffold from '#lib/components/dashboard/DashboardScaffold.svelte';
  import McpDashboardView from '#lib/components/mcp/DashboardView.svelte';

  type VirtualServerRow = components['schemas']['McpVirtualServerRow'];
  type UpstreamRow = components['schemas']['McpUpstreamServerRow'];

  let virtualServers = $state<VirtualServerRow[]>([]);
  let upstreams = $state<UpstreamRow[]>([]);
  let loading = $state(true);

  // McpDashboardView fetches the 11 /mcp/dashboard/* endpoints itself;
  // we only feed it the lookup tables it joins against.
  async function loadLookups() {
    loading = true;
    try {
      const [vs, up] = await Promise.all([
        adminApi.GET('/api/v1/admin/mcp/virtual-servers', { params: { query: { limit: 200 } } }),
        adminApi.GET('/api/v1/admin/mcp/upstream-servers', { params: { query: { limit: 200 } } }),
      ]);
      virtualServers = vs.data?.items ?? [];
      upstreams = up.data?.items ?? [];
    } finally {
      loading = false;
    }
  }

  // Skeleton on the first load and after a scope change only (`#lib/loadView.js`):
  // a refresh keeps what is shown, the empty state included.
  const lookupView = useLoadView(() => loading);

  usePeriodicLoad(loadLookups);
</script>

<DashboardScaffold
  title="MCP"
  subtitle="Method distribution, JSON-RPC errors, top tools/resources/prompts, OAuth health"
>
  {#if lookupView.skeleton}
    <div class="flex items-center justify-center py-16">
      <div
        class="w-6 h-6 border-2 border-(--text-secondary) border-t-(--accent) rounded-full animate-spin"
      ></div>
    </div>
  {:else}
    <McpDashboardView {virtualServers} {upstreams} />
  {/if}
</DashboardScaffold>
