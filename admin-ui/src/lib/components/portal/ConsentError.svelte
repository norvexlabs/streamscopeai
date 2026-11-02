<script lang="ts">
  /** Error panel shared by the OAuth consent pages: message + optional
   *  machine-readable code. */
  import { m } from '#lib/paraglide/messages.js';
  let { error, errorCode }: { error: string; errorCode?: string } = $props();
</script>

<div class="bg-(--error)/10 border border-(--error) text-(--error) p-3 rounded-lg text-sm space-y-1">
  <div class="font-medium">{error}</div>
  {#if errorCode}
    <div class="text-xs text-(--error)">{m.portal_comp_code_label({ code: errorCode })}</div>
  {/if}
</div>
