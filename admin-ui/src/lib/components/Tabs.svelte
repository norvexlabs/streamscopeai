<script lang="ts">
  import { setTabParam } from '#lib/tabs.js';
  import type { Snippet } from 'svelte';

  interface Tab {
    id: string;
    label: string;
  }

  let { tabs, active, onchange, class: extraClass = '', badge }: {
    tabs: Tab[];
    active: string;
    onchange: (tab: string) => void;
    class?: string;
    badge?: Snippet<[string]>;
  } = $props();

  function switchTab(tab: string) {
    onchange(tab);
    setTabParam(tab);
  }
</script>

<div class="flex gap-1 border-b border-(--border) {extraClass}">
  {#each tabs as tab}
    <button
      onclick={() => switchTab(tab.id)}
      class="px-4 py-2 text-sm font-medium border-b-2 transition-colors {active === tab.id ? 'border-(--accent) text-(--accent)' : 'border-transparent text-(--text-secondary) hover:text-(--text-primary)'}"
    >
      {tab.label}
      {#if badge}
        {@render badge(tab.id)}
      {/if}
    </button>
  {/each}
</div>
