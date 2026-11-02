<script lang="ts">
  import { useLoadView } from '#lib/loadView.svelte.js';
  import type { Snippet } from 'svelte';

  let {
    title,
    aside,
    loading = false,
    empty = false,
    children,
  }: {
    title: string;
    /** A short figure at the right of the title — the value now, say. */
    aside?: string;
    loading?: boolean;
    empty?: boolean;
    children: Snippet;
  } = $props();

  // Skeleton on the first load and after a scope change only
  // (`#lib/loadView.js`); a refresh keeps the chart — or its empty state.
  const view = useLoadView(() => loading);
  let settledEmpty = $state(false);
  $effect(() => {
    if (!loading) settledEmpty = empty;
  });
  const shownEmpty = $derived(view.reloading ? settledEmpty : empty);
</script>

<div class="bg-(--bg-card) rounded-xl border border-(--border)">
  <div class="px-5 py-3 border-b border-(--border) flex items-baseline gap-3 min-w-0">
    <h3 class="text-sm font-semibold text-(--text-primary) truncate">{title}</h3>
    {#if aside}
      <span class="ml-auto text-xs font-mono text-(--text-secondary) whitespace-nowrap truncate" data-chart-aside>{aside}</span>
    {/if}
  </div>
  <div class="px-5 py-4" style="height: 240px;">
    {#if view.skeleton}
      <div class="w-full h-full bg-(--bg-primary) rounded-sm animate-pulse"></div>
    {:else if shownEmpty}
      <div class="w-full h-full flex items-center justify-center">
        <p class="text-sm text-(--text-secondary)">No data for this period</p>
      </div>
    {:else}
      <div class="w-full h-full relative">
        {@render children()}
      </div>
    {/if}
  </div>
</div>
