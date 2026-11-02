<script lang="ts">
  import { onDestroy } from 'svelte';
  import { toast } from '#lib/toast.svelte.js';
  import Icon from '#lib/components/Icon.svelte';

  /**
   * Inline value renderer with a copy-on-click affordance. Hover (or focus
   * via keyboard) reveals a copy icon; clicking it puts the underlying
   * `value` on the clipboard and emits a toast. Use anywhere a long
   * identifier or hash appears in dense UI — request_ids, session_ids,
   * model names, content hashes.
   *
   * Renders inline by default; pass `block` for paragraph-style spacing.
   */
  let {
    value,
    label,
    block = false,
    mono = true,
  }: {
    value: string;
    /** Visible text — defaults to the value. Useful for truncated displays. */
    label?: string;
    block?: boolean;
    mono?: boolean;
  } = $props();

  let copied = $state(false);
  let timer: ReturnType<typeof setTimeout> | null = null;

  onDestroy(() => {
    if (timer) clearTimeout(timer);
  });

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      copied = true;
      toast.info('Copied');
      if (timer) clearTimeout(timer);
      timer = setTimeout(() => (copied = false), 1500);
    } catch {
      toast.error('Could not copy', { body: 'Clipboard access denied.' });
    }
  }
</script>

<span
  class="inline-flex items-center gap-1 group {block ? 'block' : ''}"
>
  <span class={mono ? 'font-mono' : ''}>{label ?? value}</span>
  <button
    onclick={copy}
    aria-label={`Copy ${value}`}
    class="opacity-0 group-hover:opacity-100 focus-visible:opacity-100 text-(--text-tertiary) hover:text-(--text-primary) transition-opacity shrink-0"
  >
    {#if copied}
      <Icon name="check" size="sm" tone="success" />
    {:else}
      <Icon name="copy" size="sm" tone="neutral" />
    {/if}
  </button>
</span>
