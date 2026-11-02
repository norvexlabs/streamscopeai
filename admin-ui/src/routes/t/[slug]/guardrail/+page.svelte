<script lang="ts">
  import ProfilesManager from '#lib/components/policy/ProfilesManager.svelte';
</script>

<div class="mb-6">
  <h1 class="text-2xl font-semibold text-(--text-primary)">Guardrail</h1>
  <p class="text-sm text-(--text-secondary) mt-1">
    Per-workspace guardrail posture — injection mode, sensitivity, inbound scanning, and PII
    policy. Each workspace selects a profile; the shared classifier backend is configured under
    Settings → Guardrail.
  </p>
</div>

<ProfilesManager kind="guardrail" activate />
