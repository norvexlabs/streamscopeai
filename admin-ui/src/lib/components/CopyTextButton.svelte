<script lang="ts">
  import { onDestroy } from 'svelte';
  import { toast } from '#lib/toast.svelte.js';

  /**
   * Prominent copy-to-clipboard button with built-in "Copied" feedback.
   * Use for any visible labelled copy action (invite links, freshly-minted
   * keys, base URLs) — the dense, hover-revealed inline variant is
   * `<Copyable>`. Swaps to a success style + label for 1.5s on success and
   * surfaces a toast if clipboard access is denied.
   */
  let {
    value,
    label = 'Copy',
    copiedLabel = 'Copied',
    size = 'md',
  }: {
    value: string;
    label?: string;
    copiedLabel?: string;
    size?: 'sm' | 'md' | 'lg';
  } = $props();

  let copied = $state(false);
  let timer: ReturnType<typeof setTimeout> | null = null;

  onDestroy(() => {
    if (timer) clearTimeout(timer);
  });

  const pad = $derived(
    size === 'sm' ? 'px-2 py-1' : size === 'lg' ? 'px-4 py-2' : 'px-3 py-2',
  );

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      copied = true;
      if (timer) clearTimeout(timer);
      timer = setTimeout(() => (copied = false), 1500);
    } catch {
      toast.error('Could not copy', { body: 'Clipboard access denied.' });
    }
  }
</script>

<button
  onclick={copy}
  class="{pad} text-xs font-medium rounded-lg border transition-colors shrink-0
    {copied
      ? 'bg-(--success)/10 text-(--success) border-(--success)'
      : 'bg-(--bg-primary) text-(--text-secondary) border-(--border) hover:text-(--text-primary)'}"
>
  {copied ? copiedLabel : label}
</button>
