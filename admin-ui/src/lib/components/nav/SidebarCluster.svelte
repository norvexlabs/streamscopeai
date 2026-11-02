<script lang="ts">
  import type { Snippet } from 'svelte';

  let {
    label,
    showDivider,
    collapsed,
    children,
  }: {
    label: string;
    showDivider: boolean;
    collapsed: boolean;
    children: Snippet;
  } = $props();
</script>

{#if showDivider}
  <li class="py-2"><div class="border-t border-(--border)"></div></li>
{/if}
<!-- A cluster without a label (the portal's Home) is a bare group. -->
{#if !collapsed && label}
  <li
    class="px-3 pt-2 pb-1 text-[10px] font-semibold tracking-[0.16em] uppercase text-(--text-secondary) select-none"
  >
    {label}
  </li>
{/if}
{@render children()}
