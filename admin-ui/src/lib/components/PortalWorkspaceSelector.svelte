<script lang="ts">
  // Portal active-workspace selector — lives in the portal header. The portal
  // always operates inside one of the signed-in user's workspaces (keys are
  // workspace-bound; the manager Team panel targets one workspace), so there
  // is no "All" aggregate. Self-hides when the user belongs to a single
  // workspace (nothing to choose). Mirrors the admin `<WorkspaceSelector>`
  // chrome.
  import { portalScope } from '#lib/scope.svelte.js';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import { m } from '#lib/paraglide/messages.js';

  // Memberships arrive Default-first from the `me` query; keep that order.
  const list = $derived(portalScope.workspaces);
</script>

{#if portalScope.workspaceCount > 1}
  <div class="flex items-center gap-2">
    <span class="text-xs text-(--text-secondary) uppercase tracking-wider">{m.portal_comp_workspace()}</span>
    <SelectInput
      bind:value={portalScope.activeWorkspace}
      aria-label={m.portal_comp_active_workspace()}
      fluid={false}
    >
      {#each list as w (w.id)}
        <option value={w.id}>{w.name}{w.role === 'manager' ? ` · ${m.portal_comp_manager()}` : ''}</option>
      {/each}
    </SelectInput>
  </div>
{/if}
