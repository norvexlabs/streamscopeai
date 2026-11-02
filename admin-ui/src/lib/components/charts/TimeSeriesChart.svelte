<script lang="ts" module>
  /** One series of a time-series chart. `tooltipOnly` names a figure the
   *  tooltip shows beside the plotted ones without drawing it. */
  export type ChartSeries = {
    key: string;
    label: string;
    color: string;
    width?: number;
    dashArray?: string;
    fill?: boolean;
    tooltipOnly?: boolean;
  };
  /** A row per bucket: its start, and each series' value — `null` where there
   *  is no reading (drawn as a gap, shown as "—"). */
  export type ChartRow = { timestamp: Date } & Record<string, number | null | Date>;
  /** A labelled horizontal rule: a limit or capacity the series are read
   *  against. The y-axis always reaches it. */
  export type ChartReference = {
    value: number;
    label: string;
    color: string;
    /** What a narrow plot shows instead of `label` (the figure alone, say). */
    short?: string;
  };
</script>

<script lang="ts">
  // The one time-series chart every dashboard draws: a card, the bucket axis,
  // a y-axis from zero to a nice-number max, one line per series and a
  // hover tooltip. Pages pass rows and series; nothing here knows what the
  // figures are.
  import ChartCard from './ChartCard.svelte';
  import TimeSeriesPlot from './TimeSeriesPlot.svelte';
  import ChartLegend from './ChartLegend.svelte';
  import { chartHasValue, chartYMax, formatBucketTick, formatBucketTooltip } from '#lib/chartHelpers.js';

  let {
    title,
    rows,
    series,
    formatY,
    hourly,
    loading = false,
    empty,
    yFloor = 0,
    nowRule = false,
    legend = false,
    counts = false,
  }: {
    title: string;
    rows: ChartRow[];
    series: ChartSeries[];
    formatY: (v: number) => string;
    /** Hourly buckets (else daily) — decides the tick and tooltip labels. */
    hourly: boolean;
    loading?: boolean;
    /** Override the default emptiness (no plotted value above zero). */
    empty?: boolean;
    /** The y-axis reaches at least this, e.g. a capacity the data is read
     *  against. */
    yFloor?: number;
    /** Mark "now" on a window that ends in the present. */
    nowRule?: boolean;
    /** A key under the card, for charts with more than one plotted series. */
    legend?: boolean;
    /** The value axis counts things (requests, holds): no tick step below one. */
    counts?: boolean;
  } = $props();

  const drawn = $derived(series.filter((s) => !s.tooltipOnly));
  const yMax = $derived(chartYMax([rows], drawn, yFloor, counts));
  const isEmpty = $derived(empty ?? !chartHasValue(rows, drawn));
</script>

<div>
  <ChartCard {title} {loading} empty={isEmpty}>
    <TimeSeriesPlot
      {rows}
      {series}
      {formatY}
      {yMax}
      {nowRule}
      {counts}
      formatTick={(d: Date) => formatBucketTick(d, hourly)}
      formatTooltip={(d: Date) => formatBucketTooltip(d, hourly)}
      ticks={hourly ? 6 : undefined}
    />
  </ChartCard>
  {#if legend}<ChartLegend series={drawn} />{/if}
</div>
