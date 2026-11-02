<script lang="ts">
  import type { NavSubtree } from '#lib/nav.js';
  import Icon from '#lib/components/Icon.svelte';

  let {
    item,
    active,
    open,
    collapsed,
    flyoutOpen,
    isLeafActive,
    onclick,
    onmouseenter,
    onmouseleave,
  }: {
    item: NavSubtree;
    active: boolean;
    open: boolean;
    collapsed: boolean;
    flyoutOpen: boolean;
    isLeafActive: (href: string) => boolean;
    onclick: (ev: MouseEvent) => void;
    onmouseenter: (ev: MouseEvent) => void;
    onmouseleave: () => void;
  } = $props();
</script>

<li>
  <button
    type="button"
    {onclick}
    {onmouseenter}
    {onmouseleave}
    aria-haspopup={collapsed ? 'menu' : undefined}
    aria-expanded={collapsed ? flyoutOpen : open}
    aria-controls={collapsed ? `flyout-${item.label}` : undefined}
    class="w-full flex items-center gap-3 px-3 py-2 rounded-lg transition-colors group relative
      {active
      ? 'text-(--text-primary)'
      : 'text-(--text-secondary) hover:bg-(--bg-elevated) hover:text-(--text-primary)'}"
    title={collapsed ? item.label : ''}
  >
    <Icon name={item.icon} color="currentColor" />
    {#if !collapsed}
      <span class="text-sm font-medium truncate flex-1 text-left">{item.label}</span>
      <span class="shrink-0 transition-transform {open ? 'rotate-90' : ''}">
        <Icon name="chevronRight" size="sm" color="currentColor" />
      </span>
    {/if}
  </button>
  {#if open && !collapsed}
    <ul class="mt-0.5 mb-1 space-y-0.5">
      {#each item.children as child (child.href)}
        {@const childActive = isLeafActive(child.href)}
        <li>
          <a
            href={child.href}
            class="flex items-center gap-2 pl-11 pr-3 py-1.5 rounded-lg text-[13px] transition-colors
              {childActive
              ? 'text-(--accent) bg-(--accent)/10'
              : 'text-(--text-secondary) hover:text-(--text-primary) hover:bg-(--bg-elevated)'}"
          >
            <span
              class="w-1.5 h-1.5 rounded-full {childActive
                ? 'bg-(--accent)'
                : 'bg-(--text-secondary) group-hover:bg-(--text-primary)'}"
            ></span>
            <span class="truncate">{child.label}</span>
          </a>
        </li>
      {/each}
    </ul>
  {/if}
</li>
