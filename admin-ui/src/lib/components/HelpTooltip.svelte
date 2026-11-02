<script lang="ts">
  /**
   * Inline info icon that reveals a popover on hover/focus. Use to attach
   * supporting context to a field label without inflating the visible
   * description. ESC dismisses; keyboard reaches it via Tab.
   */
  import Icon from '#lib/components/Icon.svelte';

  let { body, ariaLabel = 'More info' }: { body: string; ariaLabel?: string } = $props();

  let open = $state(false);
  let containerRef: HTMLSpanElement | undefined;

  function handleBlur(e: FocusEvent) {
    const next = e.relatedTarget as Node | null;
    if (!next || !containerRef?.contains(next)) open = false;
  }
</script>

<span class="relative inline-block" bind:this={containerRef}>
  <button
    type="button"
    aria-label={ariaLabel}
    aria-expanded={open}
    onmouseenter={() => (open = true)}
    onmouseleave={() => (open = false)}
    onfocus={() => (open = true)}
    onblur={handleBlur}
    onkeydown={(e) => { if (e.key === 'Escape') open = false; }}
    class="inline-flex items-center justify-center w-4 h-4 rounded-full align-text-bottom"
  >
    <Icon name="info" size="sm" tone="info" />
  </button>
  {#if open}
    <span
      role="tooltip"
      class="absolute z-50 left-1/2 -translate-x-1/2 top-full mt-1.5 w-64 p-2.5 rounded-lg bg-(--bg-elevated) border border-(--border) text-xs text-(--text-primary) leading-relaxed shadow-(--shadow-pop) text-left"
    >
      {body}
    </span>
  {/if}
</span>
