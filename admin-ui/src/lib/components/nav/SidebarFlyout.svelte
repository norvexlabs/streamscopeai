<script lang="ts">
  import type { NavSubtree } from '#lib/nav.js';
  import Icon from '#lib/components/Icon.svelte';

  let {
    subtree,
    anchor,
    isLeafActive,
    onmouseenter,
    onmouseleave,
    ondismiss,
  }: {
    subtree: NavSubtree;
    anchor: DOMRect;
    isLeafActive: (href: string) => boolean;
    onmouseenter: () => void;
    onmouseleave: () => void;
    ondismiss: () => void;
  } = $props();
</script>

<div
  data-flyout
  role="menu"
  tabindex="-1"
  id="flyout-{subtree.label}"
  aria-label={subtree.label}
  class="fixed z-50 min-w-55 rounded-lg border border-(--border) bg-(--bg-card) shadow-2xl py-1.5"
  style="left: {anchor.right + 8}px; top: {anchor.top}px;"
  {onmouseenter}
  {onmouseleave}
>
  <div
    class="px-3 pt-1 pb-2 text-[10px] font-semibold tracking-[0.14em] uppercase text-(--text-secondary) border-b border-(--border) mb-1"
  >
    {subtree.label}
  </div>
  {#each subtree.children as child (child.href)}
    {@const childActive = isLeafActive(child.href)}
    <a
      role="menuitem"
      data-flyout-item
      data-flyout-href={subtree.href}
      href={child.href}
      onclick={ondismiss}
      class="flex items-center gap-2 px-3 py-1.5 text-sm transition-colors
        {childActive
        ? 'text-(--accent) bg-(--accent)/10'
        : 'text-(--text-secondary) hover:text-(--text-primary) hover:bg-(--bg-elevated)'}"
    >
      <Icon name={child.icon} size="sm" color={childActive ? 'var(--accent)' : 'currentColor'} />
      <span class="truncate">{child.label}</span>
    </a>
  {/each}
</div>
