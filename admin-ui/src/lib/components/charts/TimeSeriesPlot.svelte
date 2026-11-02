<script lang="ts">
  // The plot inside a time-series card: the bucket axis, a y-axis from zero to
  // `yMax`, one line per drawn series and a hover tooltip naming every series
  // (the `tooltipOnly` ones included). No card, title or legend — the card
  // around it owns those, so one card can hold more than one plot.
  import { LayerCake, Svg, Html } from 'layercake';
  import { scaleTime, scaleLinear } from 'd3-scale';
  import AxisX from './AxisX.svelte';
  import AxisY from './AxisY.svelte';
  import MultiLine from './MultiLine.svelte';
  import NowRule from './NowRule.svelte';
  import ReferenceLines from './ReferenceLines.svelte';
  import Tooltip from './Tooltip.svelte';
  import type { ChartReference, ChartRow, ChartSeries } from './TimeSeriesChart.svelte';

  let {
    rows,
    series,
    formatY,
    formatTick,
    formatTooltip,
    yMax,
    ticks,
    nowRule = false,
    references = [],
    counts = false,
  }: {
    rows: ChartRow[];
    series: ChartSeries[];
    formatY: (v: number) => string;
    formatTick: (d: Date) => string;
    formatTooltip: (d: Date) => string;
    /** The top of the y-axis; the caller decides it, so plots side by side
     *  can share one scale. */
    yMax: number;
    /** Approximate x-axis tick count (d3 picks round instants near it). */
    ticks?: number;
    nowRule?: boolean;
    /** Labelled horizontal rules. One above `yMax` is drawn at the top edge,
     *  its label marked ↑ — off the scale, not left out. */
    references?: ChartReference[];
    /** The value axis counts things: no tick step below one. */
    counts?: boolean;
  } = $props();

  const drawn = $derived(series.filter((s) => !s.tooltipOnly));
  let w = $state(0);
  let h = $state(0);
</script>

<!-- LayerCake measures its container: drawn only once that has a size (a pane
     still being laid out has none, and would be drawn into nothing). -->
<div class="w-full h-full" bind:clientWidth={w} bind:clientHeight={h}>
{#if w > 0 && h > 0}
<LayerCake
  data={rows}
  x="timestamp"
  y={drawn.map((s) => s.key)}
  xScale={scaleTime()}
  yScale={scaleLinear()}
  yDomain={[0, yMax]}
  padding={{ top: 10, right: 12, bottom: 26, left: 48 }}
>
  <Svg>
    <AxisX {formatTick} {ticks} />
    <AxisY formatTick={formatY} {counts} />
    <MultiLine series={drawn} />
    <!-- By position: two references may read alike (endpoints labelled the same). -->
    <!-- A narrow plot cannot fit a long label: it shows the short form, the
         full one stays in the label's tooltip. -->
    <ReferenceLines {references} {yMax} narrow={w < 320} />
    {#if nowRule}<NowRule />{/if}
  </Svg>
  <Html>
    <Tooltip
      formatX={formatTooltip}
      lines={series.map((s) => ({ key: s.key, label: s.label, color: s.color, format: formatY }))}
    />
  </Html>
</LayerCake>
{/if}
</div>
