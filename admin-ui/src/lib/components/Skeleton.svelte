<script lang="ts">
  /**
   * Animated shimmer placeholder. Use while data is loading so the layout
   * holds its eventual shape instead of jumping when content arrives.
   *
   * `variant` picks a height preset; pass `height` to override.
   */
  let {
    variant = 'row',
    count = 3,
    height,
    rounded = 'rounded-sm',
  }: {
    variant?: 'row' | 'card' | 'chart' | 'text' | 'pill';
    count?: number;
    height?: string;
    rounded?: string;
  } = $props();

  function defaultHeight(v: typeof variant): string {
    switch (v) {
      case 'row':   return '2.5rem';
      case 'card':  return '6rem';
      case 'chart': return '12rem';
      case 'text':  return '0.875rem';
      case 'pill':  return '1.25rem';
    }
  }

  const h = $derived(height ?? defaultHeight(variant));
</script>

<div class="space-y-2" aria-hidden="true">
  {#each Array(count) as _, i (i)}
    <div class="skeleton-pulse {rounded}" style="height:{h}"></div>
  {/each}
</div>

<style>
  .skeleton-pulse {
    background: linear-gradient(
      90deg,
      var(--bg-card) 0%,
      var(--bg-elevated) 50%,
      var(--bg-card) 100%
    );
    background-size: 200% 100%;
    animation: shimmer 1.4s ease-in-out infinite;
  }
  @keyframes shimmer {
    0%   { background-position: 200% 0; }
    100% { background-position: -200% 0; }
  }
  @media (prefers-reduced-motion: reduce) {
    .skeleton-pulse {
      animation: none;
      background: var(--bg-elevated);
    }
  }
</style>
