<script lang="ts">
  // Compact in-form/modal error notice — the small sibling of `Callout` (which
  // stays the page-level banner). Renders nothing when `message` is empty, so
  // callers can bind their error state directly without an `{#if}` wrapper.
  import Icon from '#lib/components/Icon.svelte';

  let { message }: { message: string | null | undefined } = $props();
</script>

{#if message}
  <div
    class="flex items-start gap-2 rounded-lg border px-3 py-2"
    style="background-color: var(--error-bg); border-color: var(--error-border)"
    role="alert"
    aria-live="polite"
  >
    <div class="shrink-0 mt-px">
      <Icon name="blocked" tone="error" size="xs" />
    </div>
    <p class="text-xs" style="color: var(--error-text)">{message}</p>
  </div>
{/if}
