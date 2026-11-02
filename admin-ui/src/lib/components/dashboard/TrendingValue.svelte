<script lang="ts">
  // Headline value with a small ↑/↓ trend chip rendered **before** the
  // number when the value moved in the latest refresh (button, R key or
  // auto-refresh tick). Mount, a scope change and a page's own loads only
  // move the baseline — the rules are in `#lib/trend.js`. The chip uses the
  // accent color (never the value color) so it pops against the digits
  // regardless of severity. Trend state is browser-local per tab.
  //
  // The value row of <MetricCard> and <AttentionCard> (chrome: <StatCard>).
  import { untrack } from 'svelte';
  import { statValueClass, useStatCompact } from '#lib/components/dashboard/statCard.js';
  import { refreshCycle } from '#lib/refreshCycle.svelte.js';
  import { initialTrend, observeTrend, rescopeTrend, settleTrend, type Trend, type TrendEpoch } from '#lib/trend.js';

  let {
    value,
    trendValue,
    color = 'var(--text-primary)',
  }: {
    /** The displayed text (already formatted — `formatCount(…)`, `formatCost(…)`,
     *  `formatDuration(…)`). */
    value: string | number;
    /** Numeric for trend tracking. Omit to disable the chip entirely
     *  (e.g. for static labels); `undefined` while the reading is missing
     *  (not loaded, failed fetch) — never a placeholder `0`, which would
     *  read as a real movement. */
    trendValue?: number;
    /** Color for the digits only. The trend chip ignores this and uses
     *  `--accent` so it stays visually distinct from the number. */
    color?: string;
  } = $props();

  const compact = useStatCompact();

  const epoch = (): TrendEpoch => ({ refresh: refreshCycle.sequence, scope: refreshCycle.scopeGeneration });

  // `tracker` is a plain `let`, NOT `$state`: both effects read and write it,
  // and only `trendValue` / `refreshCycle.scopeGeneration` / `refreshCycle.loadsSettled` may
  // re-run them.
  let tracker = initialTrend(epoch());
  let trend = $state<Trend>(null);
  $effect(() => {
    const v = trendValue;
    untrack(() => {
      tracker = observeTrend(tracker, v, epoch());
      trend = tracker.trend;
    });
  });
  $effect(() => {
    void refreshCycle.scopeGeneration;
    untrack(() => {
      tracker = rescopeTrend(tracker, epoch());
      trend = tracker.trend;
    });
  });
  $effect(() => {
    const settled = refreshCycle.loadsSettled.refresh;
    untrack(() => {
      tracker = settleTrend(tracker, settled, trendValue);
      trend = tracker.trend;
    });
  });

  // Fixed size (`statValueClass`), never scaled with the card: every stat
  // card on every dashboard shows its number at the same size.
</script>

<p class={statValueClass(compact())} style="color: {color}" title={String(value)}>
  {#if trend}<span
      class="text-lg mr-2 align-middle"
      style="color: var(--accent)"
      aria-label={trend === 'up' ? 'increasing' : 'decreasing'}
    >{trend === 'up' ? '↑' : '↓'}</span
    >{/if}{value}
</p>
