<script lang="ts" module>
  /** One plot of a {@link LiveHistoryChart}: its rows and how to read them. */
  export type LiveHistoryPane = {
    rows: ChartRow[];
    /** The caption over the plot ("Last 15 min", "Last 7 days"). */
    label: string;
    loading?: boolean;
    /** Override the default emptiness (no plotted value above zero). */
    empty?: boolean;
    /** What the pane says when it is empty. */
    emptyText?: string;
    /** A short figure for the card's header — the value now, say. Read from
     *  the recent pane only: "now" belongs to the live window. */
    note?: string;
    /** Why the pane's data could not be read; shown instead of its empty text,
     *  which would state a fact nobody observed. */
    error?: string;
  };
</script>

<script lang="ts">
  // One figure seen at two time scales in ONE card the size of any other
  // chart: the last few minutes at the grain the figure is read (left, a
  // third), and the page's period (right). Both plots share the series, the
  // y-scale and the legend, so a value reads the same height in either.
  // Nothing here knows what the figure is; the page passes rows and series.
  import ChartCard from './ChartCard.svelte';
  import TimeSeriesPlot from './TimeSeriesPlot.svelte';
  import ChartLegend from './ChartLegend.svelte';
  import type { ChartReference, ChartRow, ChartSeries } from './TimeSeriesChart.svelte';
  import {
    chartHasValue,
    chartYMax,
    referencesInReach,
    formatBucketTick,
    formatBucketTooltip,
    formatClockTick,
    formatClockTooltip,
  } from '#lib/chartHelpers.js';

  let {
    title,
    series,
    formatY,
    recent,
    history,
    hourly,
    yFloor = 0,
    references = [],
    legend = false,
    counts = false,
  }: {
    title: string;
    series: ChartSeries[];
    formatY: (v: number) => string;
    /** The short window, in second-grained buckets ending now. */
    recent: LiveHistoryPane;
    /** The page's period, in its hour or day buckets. */
    history: LiveHistoryPane;
    /** The period's buckets are hours (else days). */
    hourly: boolean;
    /** Both y-axes reach at least this, e.g. a capacity. */
    yFloor?: number;
    /** Labelled horizontal rules drawn on both plots. The axes reach those
     *  near the data; one far above it is marked at the top edge instead of
     *  flattening every line under it. */
    references?: ChartReference[];
    /** The value axis counts things: no tick step below one. */
    counts?: boolean;
    legend?: boolean;
  } = $props();

  const drawn = $derived(series.filter((s) => !s.tooltipOnly));
  const dataTop = $derived(chartYMax([recent.rows, history.rows], drawn, yFloor, counts));
  const yMax = $derived(
    chartYMax([recent.rows, history.rows], drawn, Math.max(yFloor, ...referencesInReach(references, dataTop).map((r) => r.value)), counts),
  );
  // A pane with no rows has no time axis to draw, whatever its caller says.
  const recentEmpty = $derived(recent.rows.length === 0 || (recent.empty ?? !chartHasValue(recent.rows, drawn)));
  const historyEmpty = $derived(history.rows.length === 0 || (history.empty ?? !chartHasValue(history.rows, drawn)));
</script>

<div data-chart={title}>
  <ChartCard
    {title}
    aside={recent.note && recent.error ? `${recent.note} · stale` : recent.note}
    loading={(recent.loading ?? false) && (history.loading ?? false)}
  >
    <div class="w-full h-full flex flex-col sm:flex-row gap-3">
      {#each [
        { pane: recent, empty: recentEmpty, fallback: 'No reading lately', live: true },
        { pane: history, empty: historyEmpty, fallback: 'No data for this period', live: false },
      ] as p (p.live)}
        <div
          class="flex flex-col min-w-0 min-h-0 {p.live ? 'sm:w-1/3 flex-1 sm:flex-none sm:pr-3 sm:border-r border-(--border)' : 'flex-1'}"
          data-pane={p.live ? 'recent' : 'history'}
        >
          <p class="text-[10px] uppercase tracking-wide text-(--text-tertiary) mb-0.5 flex items-center gap-1.5 min-w-0">
            {#if p.live}
              <span
                class="w-1.5 h-1.5 rounded-full shrink-0 {p.pane.error ? 'bg-(--warning)' : 'bg-(--success)'}"
                aria-hidden="true"
              ></span>
            {/if}
            <span class="truncate" title={p.pane.label}>{p.pane.label}</span>
            {#if p.pane.error && !p.empty}
              <!-- The last figures stay drawn: say they are no longer current. -->
              <span class="normal-case tracking-normal text-(--warning-text) whitespace-nowrap" title={p.pane.error} data-pane-stale>stale</span>
            {/if}
          </p>
          <div class="relative flex-1 min-h-0">
            {#if p.pane.loading && p.pane.rows.length === 0}
              <div class="w-full h-full bg-(--bg-primary) rounded-sm animate-pulse"></div>
            {:else if p.empty && p.pane.error}
              <div class="w-full h-full flex items-center justify-center" data-pane-error>
                <p class="text-xs text-(--warning-text) text-center">Could not load: {p.pane.error}</p>
              </div>
            {:else if p.empty}
              <div class="w-full h-full flex items-center justify-center">
                <p class="text-xs text-(--text-secondary) text-center">{p.pane.emptyText ?? p.fallback}</p>
              </div>
            {:else if p.live}
              <TimeSeriesPlot
                rows={p.pane.rows}
                {series}
                {formatY}
                {yMax}
                {references}
                {counts}
                formatTick={formatClockTick}
                formatTooltip={formatClockTooltip}
                ticks={3}
              />
            {:else}
              <TimeSeriesPlot
                rows={p.pane.rows}
                {series}
                {formatY}
                {yMax}
                {references}
                {counts}
                formatTick={(d: Date) => formatBucketTick(d, hourly)}
                formatTooltip={(d: Date) => formatBucketTooltip(d, hourly)}
                ticks={hourly ? 6 : undefined}
              />
            {/if}
          </div>
        </div>
      {/each}
    </div>
  </ChartCard>
  {#if legend}<ChartLegend series={drawn} />{/if}
</div>
