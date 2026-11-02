<script lang="ts">
  import type { NavLeaf } from '#lib/nav.js';
  import Icon from '#lib/components/Icon.svelte';

  let {
    item,
    active,
    collapsed,
  }: {
    item: NavLeaf;
    active: boolean;
    collapsed: boolean;
  } = $props();
</script>

<li>
  <a
    href={item.href}
    class="flex items-center gap-3 px-3 py-2 rounded-lg transition-colors group relative
      {active
      ? 'bg-(--accent)/10 text-(--accent)'
      : 'text-(--text-secondary) hover:bg-(--bg-elevated) hover:text-(--text-primary)'}"
    title={collapsed ? item.label : ''}
  >
    {#if active}
      <span
        class="absolute left-0 top-1/2 -translate-y-1/2 w-0.75 h-5 bg-(--accent) rounded-r-full"
      ></span>
    {/if}
    <Icon name={item.icon} color={active ? 'var(--accent)' : 'currentColor'} />
    {#if !collapsed}
      <span class="text-sm font-medium truncate">{item.label}</span>
    {/if}
  </a>
</li>
