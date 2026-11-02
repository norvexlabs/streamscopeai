<script lang="ts">
  // Dashboard workspace-scope selector — lives in the header, before the period
  // picker. Pins the dashboards (`/dashboard/*` + `/admin/overview`) to one
  // workspace, or "All workspaces" (default). The layout route-gates where this
  // renders (the dashboard surface only); the audit pages own a self-contained
  // inline workspace filter instead. Self-hides when the tenant has a single
  // workspace (nothing to choose). Mirrors the `<PeriodSelector>` chrome.
  import { consoleScope } from '#lib/scope.svelte.js';

  // Default workspace first, Agent and Inline AI workspaces last, others by
  // name in between.
  const sorted = $derived(
    [...consoleScope.workspaces].sort((a, b) => {
      const aAgent = a.role === 'agent';
      const bAgent = b.role === 'agent';
      if (aAgent !== bAgent) return aAgent ? 1 : -1;
      const aInline = a.role === 'inline';
      const bInline = b.role === 'inline';
      if (aInline !== bInline) return aInline ? 1 : -1;
      const aDefault = a.role === 'default';
      const bDefault = b.role === 'default';
      if (aDefault !== bDefault) return aDefault ? -1 : 1;
      return a.name.localeCompare(b.name);
    })
  );
</script>

{#if consoleScope.workspaceCount > 1}
  <div class="flex items-center gap-2">
    <span class="text-xs text-(--text-secondary) uppercase tracking-wider">Workspace</span>
    <select
      bind:value={consoleScope.workspace}
      aria-label="Workspace scope"
      class="px-2.5 py-1.5 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm font-medium focus:outline-hidden focus:border-(--accent) transition-colors"
    >
      <option value="all">All except agent</option>
      {#each sorted as w (w.id)}
        <option value={w.id}>{w.name}{w.role === 'agent' ? ' (Agent)' : w.role === 'inline' ? ' (Inline AI)' : w.role === 'default' && w.name.toLowerCase() !== 'default' ? ' (Default)' : ''}</option>
      {/each}
    </select>
  </div>
{/if}
