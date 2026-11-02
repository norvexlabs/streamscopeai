<script lang="ts">
  // The value axis: ticks at every multiple of one nice step (1, 2 or 5 × 10ⁿ)
  // from 0 to the top of the domain — which `niceMax` set to such a multiple,
  // so the top is always labelled and no label sits off the scale.
  import { getLayerCakeContext } from 'layercake';
  import { niceTicks } from '#lib/chartHelpers.js';

  let {
    formatTick = (d: number) => String(d),
    ticks: intervals = 4,
    counts = false,
  }: {
    formatTick?: (d: number) => string;
    /** At most this many intervals between 0 and the top. */
    ticks?: number;
    /** The axis counts things: no step below one. */
    counts?: boolean;
  } = $props();

  const k = getLayerCakeContext();
  const tickValues = $derived(niceTicks(k.yScale.domain()[1] ?? 0, intervals, counts));
</script>

<g class="axis y-axis">
  {#each tickValues as tick (tick)}
    {@const y = k.yScale(tick)}
    <g transform="translate(0, {y})">
      <!-- Grid line -->
      <line
        x1="0"
        x2={k.width}
        stroke="var(--border)"
        stroke-width="0.5"
        stroke-dasharray="3,3"
        opacity="0.5"
      />
      <text
        x="-8"
        dy="3"
        text-anchor="end"
        style="fill: var(--text-secondary); font-size: 10px; font-family: ui-monospace, monospace;"
      >
        {formatTick(tick)}
      </text>
    </g>
  {/each}
</g>
