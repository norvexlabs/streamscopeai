<script lang="ts">
  // Vertical "now" rule for a LayerCake time-series chart. Renders a faint
  // dashed line plus a small label inside the chart's plot area whenever
  // `Date.now()` falls inside the x-scale domain. Communicates which bucket
  // is partial / which side of the chart is future for charts that don't
  // explicitly split settled-vs-partial data segments.
  import { getLayerCakeContext } from 'layercake';

  let {
    color = 'var(--text-tertiary)',
    label = 'now',
  }: {
    color?: string;
    label?: string;
  } = $props();

  const k = getLayerCakeContext();

  const x = $derived.by(() => {
    const domain = k.xScale.domain?.() ?? [];
    if (domain.length < 2) return null;
    const now = Date.now();
    const lo = +domain[0];
    const hi = +domain[1];
    if (now < lo || now > hi) return null;
    return k.xScale(new Date(now));
  });
</script>

{#if x !== null}
  <line
    x1={x}
    x2={x}
    y1={0}
    y2={k.height}
    stroke={color}
    stroke-width="1"
    stroke-dasharray="3 3"
    opacity="0.55"
  />
  <text
    x={x + 4}
    y={10}
    fill={color}
    font-size="9"
    font-family="ui-monospace, SFMono-Regular, Menlo, monospace"
    opacity="0.7"
  >
    {label}
  </text>
{/if}
