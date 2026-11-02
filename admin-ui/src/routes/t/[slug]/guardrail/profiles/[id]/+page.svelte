<script lang="ts">
  import ProfileDetailShell from '#lib/components/policy/ProfileDetailShell.svelte';
  import GuardrailPolicyEditor from '#lib/components/settings/GuardrailPolicyEditor.svelte';
</script>

<ProfileDetailShell kind="guardrail">
  {#snippet children({ id })}
    <GuardrailPolicyEditor profileId={id} />
  {/snippet}
</ProfileDetailShell>
