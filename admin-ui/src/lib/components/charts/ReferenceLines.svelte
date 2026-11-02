<script lang="ts">
  // Every labelled horizontal rule of a plot, its labels laid out TOGETHER:
  // from the top of the plot down, each label goes just above its rule — or
  // just below when there is no room above — and never higher than one line
  // under the label before it, so no two labels can print on each other
  // however close their rules are, nor past the plot's bottom (the lowest move
  // up together; one that still cannot fit keeps its rule and tooltip). A rule
  // above the scale is drawn at the top edge, its label marked ↑.
  import { getLayerCakeContext } from 'layercake';
  import type { ChartReference } from './TimeSeriesChart.svelte';

  let {
    references,
    yMax,
    narrow = false,
  }: {
    references: ChartReference[];
    yMax: number;
    /** Too narrow for the long labels: each shows its `short` form. */
    narrow?: boolean;
  } = $props();

  const k = getLayerCakeContext();

  const LINE = 12;
  const placed = $derived.by(() => {
    const rules = references
      .map((r) => {
        const off = r.value > yMax;
        return {
          y: k.yScale(off ? yMax : r.value),
          color: r.color,
          full: r.label,
          text: `${off ? '↑ ' : ''}${narrow ? (r.short ?? r.label) : r.label}`,
        };
      })
      .sort((a, b) => a.y - b.y);
    let floor = -Infinity;
    const laid = rules.map((r) => {
      const above = r.y - 4;
      const wanted = above >= 10 ? above : r.y + LINE;
      const labelY = Math.max(wanted, floor + LINE);
      floor = labelY;
      return { ...r, labelY };
    });
    // Labels pushed past the bottom of the plot move up together, keeping
    // their spacing; any that still cannot fit keep their rule and tooltip.
    const overflow = floor - (k.height - 2);
    if (overflow > 0) {
      for (const r of laid) r.labelY -= overflow;
    }
    return laid.map((r) => ({ ...r, show: r.labelY >= 10 }));
  });
</script>

{#each placed as r, i (i)}
  <g class="reference-line" data-reference={r.full}>
    <title>{r.full}</title>
    <line x1="0" x2={k.width} y1={r.y} y2={r.y} stroke={r.color} stroke-width="1.5" stroke-dasharray="2,3" />
    {#if r.show}
    <text
      x={k.width - 2}
      y={r.labelY}
      text-anchor="end"
      style="fill: {r.color}; font-size: 10px; font-family: ui-monospace, monospace;"
    >
      {r.text}
    </text>
    {/if}
  </g>
{/each}
