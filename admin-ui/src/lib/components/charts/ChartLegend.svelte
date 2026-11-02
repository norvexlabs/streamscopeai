<script lang="ts">
  // The key under a time-series card: one swatch per drawn series, shown only
  // when there is more than one to tell apart.
  import type { ChartSeries } from './TimeSeriesChart.svelte';

  let { series }: { series: ChartSeries[] } = $props();
</script>

{#if series.length > 1}
  <div class="flex flex-wrap items-center gap-4 mt-1.5 px-1">
    {#each series as s (s.key)}
      <span class="inline-flex items-center gap-1.5 text-xs text-(--text-secondary)">
        <span class="w-2.5 h-2.5 rounded-xs" style="background-color: {s.color}"></span>
        {s.label}
      </span>
    {/each}
  </div>
{/if}
