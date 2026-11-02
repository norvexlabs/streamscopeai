<script lang="ts">
  // The one layout for a row of dashboard stat cards (<MetricCard>,
  // <AttentionCard>, <ProtocolCard>). Cards keep a fixed minimum width so
  // their fixed typography never wraps; the set takes one row when it fits
  // and otherwise the fewest balanced rows (`metricGridColumns`). Until the
  // container is measured (SSR, first frame) a CSS auto-fill track stands in
  // (empty tracks kept, like the MIN_TRACKS floor).
  // Every row takes the tallest card's height, so a wrapped set stays uniform.
  // A container too narrow for two regular cards side by side (a phone) turns
  // compact: denser chrome and a smaller minimum, so two cards still share a
  // row — and never more than two, so narrowing the screen never adds columns.
  import type { Snippet } from 'svelte';
  import { metricGridColumns } from '#lib/metricGrid.js';
  import { provideStatCompact } from '#lib/components/dashboard/statCard.js';

  let {
    children,
    class: klass = '',
    ...rest
  }: { children: Snippet; class?: string; [attr: `data-${string}`]: string } = $props();

  // Keep in sync with the card chrome in <StatCard>: the narrowest card
  // that holds an 11-char value at text-2xl, and a ~20-char label (~15 beside
  // a period badge).
  const MIN_CARD_PX = 240;
  const GAP_PX = 16;
  // The same for the compact chrome (p-4, 28px icon tile, text-xl value).
  const COMPACT_MIN_CARD_PX = 150;
  const COMPACT_GAP_PX = 12;
  // A set of fewer than four cards stays quarter-width tiles, not a banner.
  const MIN_TRACKS = 4;

  let el = $state<HTMLDivElement | undefined>();
  let width = $state(0);
  let count = $state(0);

  // Cards are rendered by the caller's snippet (conditionally, from `{#each}`),
  // so the count is read from the DOM and kept current as children change.
  // Only <StatCard> roots count — any other child element is not a card.
  $effect(() => {
    if (!el) return;
    const node = el;
    const sync = () => (count = node.querySelectorAll(':scope > [data-stat-card]').length);
    sync();
    const observer = new MutationObserver(sync);
    observer.observe(node, { childList: true });
    return () => observer.disconnect();
  });

  const compact = $derived(width > 0 && width < 2 * MIN_CARD_PX + GAP_PX);
  provideStatCompact(() => compact);
  const minPx = $derived(compact ? COMPACT_MIN_CARD_PX : MIN_CARD_PX);
  const gapPx = $derived(compact ? COMPACT_GAP_PX : GAP_PX);
  const cols = $derived(metricGridColumns(count, width, minPx, gapPx, MIN_TRACKS, compact ? 2 : Infinity));
  const template = $derived(
    cols > 0 ? `repeat(${cols}, minmax(0, 1fr))` : `repeat(auto-fill, minmax(min(${MIN_CARD_PX}px, 100%), 1fr))`,
  );
</script>

<div
  bind:this={el}
  bind:clientWidth={width}
  class="grid {klass}"
  style:gap="{gapPx}px"
  style:grid-template-columns={template}
  style:grid-auto-rows="1fr"
  data-metric-grid
  {...rest}
>
  {@render children()}
</div>
