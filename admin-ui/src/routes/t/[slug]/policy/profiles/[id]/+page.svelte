<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import ProfileDetailShell from '#lib/components/policy/ProfileDetailShell.svelte';
  import ToolRulesSection from '#lib/components/policy/ToolRulesSection.svelte';
  import type { PageProps } from './$types';

  let { params }: PageProps = $props();

  const id = $derived(params.id);

  // Resolve the tenant's Default tool profile + whether this profile is Layered,
  // so inherited Default rules render read-only (Default-as-base model).
  let baselineProfileId = $state<string | undefined>(undefined);
  let layered = $state(false);

  async function loadMeta() {
    const { data } = await adminApi.GET('/api/v1/admin/profiles', {
      params: { query: { kind: 'tools', offset: 0, limit: 200 } },
    });
    const items = data?.items ?? [];
    baselineProfileId = items.find((p) => p.is_default)?.id;
    const self = items.find((p) => p.id === id);
    layered = self ? !self.is_default && !self.standalone : false;
  }

  $effect(() => {
    if (id) loadMeta();
  });
</script>

<ProfileDetailShell kind="tools">
  {#snippet children({ id: profileId })}
    <ToolRulesSection profileId={profileId} {baselineProfileId} {layered} activate />
  {/snippet}
</ProfileDetailShell>
