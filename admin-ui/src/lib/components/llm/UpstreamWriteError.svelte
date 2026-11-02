<script lang="ts">
  // A refused server write, with the override the backend offers. Saving a
  // server carries a reachability check, and its two refusals are both ones an
  // operator may legitimately overrule: an upstream that did not answer, and
  // one that answered by refusing the credential — a provider may well refuse
  // the model list to a key that works for chat. Every other code is not.
  // Shared by the create wizard and the server's settings so the two cannot
  // describe the same refusal differently.
  import Icon from '#lib/components/Icon.svelte';
  import { isOverridableUpstreamError } from '#lib/api-helpers.js';

  let {
    message,
    code,
    retryLabel,
    onretry,
    busy = false,
  }: {
    message: string;
    /** The `ApiErrorCode`; only an overridable check failure offers the button. */
    code: string | null;
    /** What the override reads as — "Create anyway" / "Save anyway". */
    retryLabel: string;
    onretry: () => void;
    busy?: boolean;
  } = $props();

  const overridable = $derived(isOverridableUpstreamError(code));
</script>

<div class="flex flex-col gap-2 px-3.5 py-3 bg-(--error-bg) border border-(--error-border) rounded-lg">
  <div class="flex items-start gap-2">
    <span class="shrink-0 mt-0.5"><Icon name="errorCircle" size="sm" tone="error" /></span>
    <p class="text-sm text-(--error-text)">{message}</p>
  </div>
  {#if overridable}
    <button
      onclick={onretry}
      disabled={busy}
      class="self-start text-xs px-3 py-1.5 border border-(--error-border) rounded-md text-(--error-text) hover:bg-(--error)/10 transition-colors disabled:opacity-50"
    >{retryLabel}</button>
  {/if}
</div>
