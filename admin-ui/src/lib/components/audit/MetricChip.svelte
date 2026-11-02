<script lang="ts">
  // Inline `label + value` chip used in the Extended Metrics flex-wrap strip
  // below the Identity & Context grid in every audit detail drawer. Same
  // visual as the inline cells inside the grid but tighter: `ml-1` gap and
  // no surrounding container — chips wrap inside the parent's flex strip.

  interface Props {
    label: string;
    value: string | number;
    title?: string;
    /** Override the default `font-mono text-(--text-primary)` value
     *  classes. Used by warning/error metrics that need a coloured value
     *  without a full StatusPill (e.g. "Zero Completion: Yes"). */
    valueClass?: string;
  }

  let {
    label,
    value,
    title,
    valueClass = 'font-mono text-(--text-primary)',
  }: Props = $props();
</script>

<span {title}>
  <span class="text-(--text-secondary)">{label}</span>
  <span class="ml-1 {valueClass}">{value}</span>
</span>
