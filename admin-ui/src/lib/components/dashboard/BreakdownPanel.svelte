<script module lang="ts">
  import type { RowMeta } from './BreakdownRow.svelte';

  /** Spec returned by `getRow` for each item — mirrors BreakdownRow's props
   *  one-for-one. */
  export interface BreakdownRowSpec {
    label: string;
    value: string;
    sub?: string;
    valueColor?: string;
    meta?: RowMeta[];
    percent: number;
    href?: string;
    title?: string;
    mono?: boolean;
    barColor?: string;
    animateBar?: boolean;
  }
</script>

<script lang="ts" generics="T">
  import type { Snippet } from 'svelte';
  import Panel from './Panel.svelte';
  import BreakdownRow from './BreakdownRow.svelte';
  import Skeleton from '#lib/components/Skeleton.svelte';
  import { niceMax } from '#lib/chartHelpers.js';

  // Panel wrapped around a list of BreakdownRow. Folds the
  // header / skeleton / space-y wrapper / nice-number max boilerplate
  // that was duplicated ~19 times across the dashboards.

  interface Props {
    // ── Panel passthrough ───────────────────────────────────────────────
    title: string;
    subtitle?: string;
    action?: string;
    actionHref?: string;
    flush?: boolean;
    loading?: boolean;
    error?: string;
    /** Defaults to `!loading && items.length === 0`. Override only for
     *  cases where "empty" means something different (e.g. data hasn't
     *  loaded yet vs. genuinely zero rows). */
    empty?: boolean;
    emptyMessage?: string;
    headerExtra?: Snippet;
    emptySlot?: Snippet;

    // ── Data ────────────────────────────────────────────────────────────
    items: readonly T[];
    /** Optional row cap. */
    limit?: number;

    /** Build the BreakdownRow spec for each item. Receives the panel-wide
     *  `max` so `getRow` can compute its own `percent`. */
    getRow: (item: T, max: number) => BreakdownRowSpec;

    /** Used to compute panel max via `niceMax(Math.max(0, ...items.map(getValue)))`.
     *  Skip if `maxValue` is set or `getRow` builds its own percent. */
    getValue?: (item: T) => number;
    /** Explicit max override (e.g. a totals counter). Wins over getValue. */
    maxValue?: number;

    /** Stable per-row identity. REQUIRED on panels with `animateBar: true`,
     *  otherwise period-driven reorders animate bar widths between rows
     *  representing different entities (slot 0 bar morphs from userA's
     *  percent to userB's percent over 500ms). Defaults to index for
     *  static / unsorted lists. */
    getKey?: (item: T, i: number) => PropertyKey;

    /** Skeleton row count while loading. */
    skeletonCount?: number;
  }

  let {
    title,
    subtitle,
    action,
    actionHref,
    flush,
    loading = false,
    error,
    empty,
    emptyMessage,
    headerExtra,
    emptySlot,
    items,
    limit,
    getRow,
    getValue,
    maxValue,
    getKey,
    skeletonCount = 5,
  }: Props = $props();

  const rows = $derived(limit != null ? items.slice(0, limit) : items);
  const max = $derived(
    maxValue ?? (getValue ? niceMax(Math.max(0, ...items.map(getValue))) : 0)
  );
  const isEmpty = $derived(empty ?? (!loading && items.length === 0));
</script>

<Panel
  {title}
  {subtitle}
  {action}
  {actionHref}
  {flush}
  {loading}
  {error}
  empty={isEmpty}
  {emptyMessage}
  {headerExtra}
  {emptySlot}
>
  {#snippet skeleton()}
    <Skeleton variant="row" count={skeletonCount} />
  {/snippet}
  <div class="space-y-3">
    {#each rows as item, i (getKey ? getKey(item, i) : i)}
      {@const spec = getRow(item, max)}
      <BreakdownRow {...spec} />
    {/each}
  </div>
</Panel>
