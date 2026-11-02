<script lang="ts">
  // The small `Nd` / period chip that sits in the top-right of dashboard
  // tiles and panel headers. One render path so the chrome (size, color,
  // mono font) stays identical across MetricCard, AttentionCard, and every
  // dashboard panel's `headerExtra`.

  interface Props {
    /** Numeric day count (rendered as `${period}d`) or pre-formatted string. */
    period: number | string;
  }

  let { period }: Props = $props();

  const text = $derived(typeof period === 'number' ? `${period}d` : period);
</script>

<span class="text-[10px] text-(--text-secondary) font-mono">{text}</span>
