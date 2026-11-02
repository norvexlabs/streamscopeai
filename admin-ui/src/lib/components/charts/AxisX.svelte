<script lang="ts">
  import { getLayerCakeContext } from 'layercake';

  let {
    formatTick = (d: any) => d,
    ticks: tickCount = 5,
  }: {
    formatTick?: (d: any) => string;
    ticks?: number;
  } = $props();

  const k = getLayerCakeContext();
  // Never more ticks than fit: a label is ~70 px wide, so a narrow pane gets
  // fewer, whatever it asked for — labels that overprint read as noise.
  const fit = $derived(Math.max(2, Math.min(tickCount, Math.floor(k.width / 70))));
</script>

<g class="axis x-axis">
  {#each k.xScale.ticks(fit) as tick}
    {@const x = k.xScale(tick)}
    <g transform="translate({x}, {k.height})">
      <line y1="0" y2="6" stroke="var(--border)" stroke-width="1" />
      <text
        y="18"
        text-anchor="middle"
        style="fill: var(--text-secondary); font-size: 10px; font-family: ui-monospace, monospace;"
      >
        {formatTick(tick)}
      </text>
    </g>
  {/each}
  <!-- Baseline -->
  <line
    x1="0"
    x2={k.xScale.range()[1]}
    y1={k.height}
    y2={k.height}
    stroke="var(--border)"
    stroke-width="1"
  />
</g>
