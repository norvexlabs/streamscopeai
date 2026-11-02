<script lang="ts">
  // A card that is one link: an icon tile, a title and one line on what it
  // does — a landing page's "go do this" entries (the portal Home's quick
  // actions). The href is tenant-relative and scoped here, once.
  import { page } from '$app/state';
  import IconTile from '#lib/components/IconTile.svelte';
  import { scopeHref } from '#lib/tenant.js';
  import type { IconName } from '#lib/icons.js';

  interface Props {
    href: string;
    icon: IconName;
    title: string;
    body: string;
  }

  let { href, icon, title, body }: Props = $props();

  const scoped = $derived(scopeHref(page.params.slug ?? '', page.url.pathname, href));
</script>

<a
  href={scoped}
  class="group flex flex-col gap-3 rounded-xl border border-(--border) bg-(--bg-card) p-5 transition-colors hover:border-(--accent) hover:bg-(--bg-elevated)"
>
  <IconTile name={icon} tone="info" size="md" />
  <span class="text-sm font-semibold text-(--text-primary) group-hover:text-(--accent) transition-colors">{title}</span>
  <span class="text-xs text-(--text-secondary) leading-relaxed">{body}</span>
</a>
