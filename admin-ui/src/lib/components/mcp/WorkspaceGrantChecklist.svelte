<!--
  The workspaces a new server is granted to, picked while creating it or
  adopting it from the catalog. Loads the tenant's workspaces when it mounts;
  `selected` holds the picked workspace ids. With `developersOnly` the Agent
  and Inline AI workspaces are left out: they have no developers, and the
  server refuses a local MCP server granted to either.
-->
<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import { extractError } from '#lib/api-helpers.js';
  import type { components } from '#lib/generated/api-types.js';
  import Spinner from '#lib/components/Spinner.svelte';
  import FormError from '#lib/components/forms/FormError.svelte';
  import { onMount } from 'svelte';

  type Workspace = components['schemas']['WorkspaceSummary'];

  let {
    selected = $bindable(),
    note,
    developersOnly = false,
  }: {
    selected: Set<string>;
    /** Leave out the Agent and Inline AI workspaces. */
    developersOnly?: boolean;
    /** What a grant gives the workspace's members, said under the list. */
    note: string;
  } = $props();

  let workspaces = $state<Workspace[]>([]);
  let loading = $state(true);
  let loadError = $state('');

  onMount(async () => {
    const { data, error } = await adminApi.GET('/api/v1/admin/workspaces', {
      params: { query: { limit: 200 } },
    });
    if (error) loadError = extractError(error, 'Failed to load workspaces');
    else if (data) {
      workspaces = developersOnly
        ? data.items.filter((ws) => ws.role !== 'agent' && ws.role !== 'inline')
        : data.items;
    }
    loading = false;
  });

  function toggle(id: string) {
    const next = new Set(selected);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    selected = next;
  }
</script>

<div class="space-y-1" data-testid="adopt-workspaces">
  <span class="block text-xs uppercase tracking-wide text-(--text-secondary)">Grant to workspaces</span>
  {#if loading}
    <div class="py-2"><Spinner /></div>
  {:else if loadError}
    <FormError message={loadError} />
  {:else if workspaces.length === 0}
    <p class="text-xs text-(--text-secondary)">No workspaces yet. You can grant access later.</p>
  {:else}
    <div class="max-h-40 space-y-1 overflow-y-auto rounded-lg border border-(--border) p-2">
      {#each workspaces as ws (ws.id)}
        <label class="flex items-center gap-2 rounded-sm px-1 py-0.5 hover:bg-(--bg-primary)">
          <input
            type="checkbox"
            class="accent-(--accent)"
            checked={selected.has(ws.id)}
            onchange={() => toggle(ws.id)}
          />
          <span class="text-(--text-primary)">{ws.name}</span>
          {#if ws.role === 'default'}
            <span class="text-xs text-(--text-secondary)">(default)</span>
          {/if}
        </label>
      {/each}
    </div>
  {/if}
  <span class="text-xs text-(--text-secondary)">{note}</span>
</div>
