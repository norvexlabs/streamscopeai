<script lang="ts">
  import { getLayerCakeContext } from 'layercake';

  let {
    formatX = (d: any) => String(d),
    lines = [] as Array<{ key: string; label: string; color: string; format: (v: number) => string }>,
  }: {
    formatX?: (d: any) => string;
    lines: Array<{ key: string; label: string; color: string; format: (v: number) => string }>;
  } = $props();

  const k = getLayerCakeContext();

  let hoveredIndex = $state<number | null>(null);

  function handleMouseMove(e: MouseEvent) {
    const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
    const relX = e.clientX - rect.left;

    // Find nearest bucket
    const scale = k.xScale;
    const items = k.data;
    if (!items?.length) return;

    let closestIdx = 0;
    let closestDist = Infinity;
    for (let i = 0; i < items.length; i++) {
      const px = scale(items[i].timestamp);
      const dist = Math.abs(px - relX);
      if (dist < closestDist) {
        closestDist = dist;
        closestIdx = i;
      }
    }
    hoveredIndex = closestIdx;
  }

  function handleMouseLeave() {
    hoveredIndex = null;
  }

  const hoveredItem = $derived(hoveredIndex !== null ? k.data[hoveredIndex] : null);
  const crosshairX = $derived(hoveredItem ? k.xScale(hoveredItem.timestamp) : 0);
  const tooltipLeft = $derived.by(() => {
    if (!hoveredItem) return 0;
    // Flip tooltip to left side if near right edge — never past the left one:
    // in a narrow plot both sides are short of the panel's width.
    return crosshairX > k.width * 0.65 ? Math.max(0, crosshairX - 160) : crosshairX + 12;
  });
</script>

<!-- Invisible mouse capture area -->
<!-- svelte-ignore a11y_no_static_element_interactions -->
<div
  class="absolute inset-0"
  style="z-index: 10; cursor: crosshair;"
  onmousemove={handleMouseMove}
  onmouseleave={handleMouseLeave}
>
  {#if hoveredItem}
    <!-- Crosshair line (positioned within padding) -->
    <div
      class="absolute top-0 bottom-0 w-px bg-(--text-secondary)"
      style="left: {crosshairX}px; opacity: 0.4;"
    ></div>

    <!-- Tooltip panel -->
    <div
      class="absolute bg-(--bg-card) border border-(--border) rounded-lg shadow-lg px-3 py-2 pointer-events-none"
      style="left: {tooltipLeft}px; top: 8px; min-width: 140px; z-index: 20;"
    >
      <p class="text-[10px] text-(--text-secondary) font-mono mb-1.5">
        {formatX(hoveredItem.timestamp)}
      </p>
      {#each lines as l}
        <div class="flex items-center gap-2 py-0.5">
          <span class="w-2 h-2 rounded-full shrink-0" style="background: {l.color};"></span>
          <span class="text-[10px] text-(--text-secondary)">{l.label}</span>
          <!-- No reading for this bucket is not a zero. -->
          <span class="text-xs text-(--text-primary) font-mono ml-auto">{hoveredItem[l.key] == null ? '—' : l.format(hoveredItem[l.key])}</span>
        </div>
      {/each}
    </div>
  {/if}
</div>
