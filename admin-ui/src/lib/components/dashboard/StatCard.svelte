<script lang="ts">
  import { useLoadView } from '#lib/loadView.svelte.js';
  // Shared chrome for every dashboard stat card — <MetricCard>,
  // <AttentionCard> and <ProtocolCard> differ only in the value row they pass
  // as `children`. Typography is FIXED (never scaled with the card width) and
  // every text line is single-line with an ellipsis and a hover title
  // (`STAT_TEXT_FIT`; it wraps instead on a touch screen, which cannot hover),
  // so a row of cards reads identically on every dashboard. Width is
  // <MetricGrid>'s job: its minimum card width is sized for this chrome, and it
  // switches the cards to the denser `compact` chrome on a narrow screen.
  import type { Snippet } from 'svelte';
  import IconTile from '#lib/components/IconTile.svelte';
  import PeriodBadge from '#lib/components/dashboard/PeriodBadge.svelte';
  import type { IconName, Tone } from '#lib/icons.js';
  import { STAT_TEXT_FIT, useStatCompact } from '#lib/components/dashboard/statCard.js';
  import { page } from '$app/state';
  import { scopeHref } from '#lib/tenant.js';

  let {
    label,
    period,
    icon,
    iconTone,
    subtitle,
    subtitle2,
    href,
    loading = false,
    children,
  }: {
    label: string;
    period?: string;
    icon: IconName;
    iconTone?: Tone;
    subtitle?: string;
    subtitle2?: string;
    /** Tenant-relative (`/sessions`) or already scoped — `scopeHref` is
     *  idempotent, so every caller gets a link under its plane's prefix. */
    href?: string;
    loading?: boolean;
    children: Snippet;
  } = $props();

  // Skeleton on the first load and after a scope change only (`#lib/loadView.js`):
  // a refresh keeps the value mounted, so <TrendingValue> keeps its previous
  // reading and can show the ↑/↓ chip.
  const view = useLoadView(() => loading);
  const skeleton = $derived(view.skeleton);
  const isCompact = useStatCompact();
  const compact = $derived(isCompact());
  // The session cookie is path-scoped to the plane's tenant prefix; an
  // unscoped link would arrive without it.
  const scopedHref = $derived(href ? scopeHref(page.params.slug ?? '', page.url.pathname, href) : undefined);
</script>

<svelte:element
  this={scopedHref ? 'a' : 'div'}
  href={scopedHref}
  data-stat-card
  class="flex flex-col min-w-0 bg-(--bg-card) rounded-xl border border-(--border) {compact ? 'p-4' : 'p-5'} transition-colors {scopedHref ? 'cursor-pointer hover:border-(--accent) hover:bg-(--bg-elevated)' : ''}"
>
  {#if skeleton}
    <div class="flex items-center justify-between mb-3">
      <div class="w-20 h-3 bg-(--bg-primary) rounded-sm animate-pulse"></div>
      <div class="w-9 h-9 bg-(--bg-primary) rounded-lg animate-pulse"></div>
    </div>
    <div class="w-28 h-8 bg-(--bg-primary) rounded-sm animate-pulse mb-1.5"></div>
    <div class="w-24 h-4 bg-(--bg-primary) rounded-sm animate-pulse"></div>
  {:else}
    <div class="flex items-center justify-between gap-2 mb-3">
      <div class="flex items-center gap-2 min-w-0">
        <p class="text-[11px] font-medium text-(--text-secondary) uppercase tracking-wide {STAT_TEXT_FIT} min-w-0" title={label}>{label}</p>
        {#if period}
          <span class="shrink-0"><PeriodBadge {period} /></span>
        {/if}
      </div>
      <IconTile name={icon} tone={iconTone} size={compact ? 'sm' : 'md'} />
    </div>
    {@render children()}
    <!-- The subtitle line is always reserved so a row of cards stays aligned. -->
    <p class="min-h-4 mt-1.5 text-xs leading-4 text-(--text-secondary) font-mono {STAT_TEXT_FIT}" title={subtitle}>{subtitle ?? ''}</p>
    {#if subtitle2}
      <p class="mt-0.5 text-xs leading-4 text-(--text-secondary) font-mono {STAT_TEXT_FIT}" title={subtitle2}>{subtitle2}</p>
    {/if}
  {/if}
</svelte:element>
