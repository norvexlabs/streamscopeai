<script lang="ts">
  import ProfileDetailShell from '#lib/components/policy/ProfileDetailShell.svelte';
  import ClientAccessEditor from '#lib/components/clients/ClientAccessEditor.svelte';
</script>

<ProfileDetailShell kind="client_access">
  {#snippet children({ id })}
    <ClientAccessEditor profileId={id} />
  {/snippet}
</ProfileDetailShell>
