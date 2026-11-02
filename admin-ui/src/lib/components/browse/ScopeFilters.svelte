<script lang="ts">
  // Whose rows a browse view shows, as each plane names it. The console picks
  // a user and workspaces over the whole tenant. The portal shows the
  // caller's own rows, or — where the header workspace shares with its
  // members — the team's (Me/Team), and only in a team view a teammate filter:
  // the server ignores one on the caller's own rows.
  import type { BrowsePlane } from '#lib/browse/planes.js';
  import type { UrlFilters } from '#lib/hooks.svelte.js';
  import UserEmailFilter from '#lib/components/UserEmailFilter.svelte';
  import WorkspaceFilter from '#lib/components/filter/WorkspaceFilter.svelte';
  import PortalScopeSelector from '#lib/components/portal/PortalScopeSelector.svelte';

  interface Props {
    plane: BrowsePlane;
    filters: UrlFilters<string>;
    /** A teammate (portal) or user (console) filter applies in this scope. */
    userFilter: boolean;
    /** A filter changed: reload. */
    onchange: () => void;
    /** The portal's Me/Team choice changed. */
    onteam: (workspaceId: string | undefined) => void;
  }

  let { plane, filters, userFilter, onchange, onteam }: Props = $props();
</script>

{#if plane.portal}
  <div class="pb-px">
    <PortalScopeSelector workspaceId={filters.values.workspace_id || undefined} onChange={onteam} />
  </div>
  {#if userFilter}
    <UserEmailFilter bind:value={filters.values.user_email} onfilter={onchange} />
  {/if}
{:else}
  <UserEmailFilter bind:value={filters.values.user_email} onfilter={onchange} />
  <WorkspaceFilter bind:value={filters.values.workspace_ids} onchange={onchange} />
{/if}
