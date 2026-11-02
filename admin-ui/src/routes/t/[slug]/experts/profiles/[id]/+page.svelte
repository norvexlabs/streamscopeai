<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import { fetchAllPages } from '#lib/api-helpers.js';
  import type { AgentExpert } from '#lib/api-types.js';
  import ProfileDetailShell from '#lib/components/policy/ProfileDetailShell.svelte';
  import ExpertProfileEditor from '#lib/components/experts/ExpertProfileEditor.svelte';

  // `null` while loading, so the editor never reads "no experts" off a list
  // that has not arrived (or failed).
  let experts = $state<AgentExpert[] | null>(null);
  let expertsError = $state('');

  async function loadExperts() {
    try {
      experts = await fetchAllPages((offset, limit) =>
        adminApi.GET('/api/v1/admin/experts', { params: { query: { offset, limit } } }));
    } catch (e: unknown) {
      expertsError = e instanceof Error ? e.message : String(e);
    }
  }

  $effect(() => {
    loadExperts();
  });
</script>

<ProfileDetailShell kind="expert">
  {#snippet children({ id, isDefault, standalone })}
    <ExpertProfileEditor profileId={id} {isDefault} {standalone} {experts} {expertsError} />
  {/snippet}
</ProfileDetailShell>
