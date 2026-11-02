<script lang="ts">
  // Dashboard headline tile: a labelled value (count / latency / cost) with
  // a category-identifying icon tile, optional subtitles, and an inline ↑/↓
  // trend chip that appears when `trendValue` moved in the latest refresh
  // (rules: `#lib/trend.js`). Trend state is browser-local per tab.
  //
  // Identity vs state:
  //   - `icon` + `iconTone` are category identity (fixed glyph, fixed tone).
  //   - `valueColor` is data-driven — drives the value digits and trend chip
  //     when it should pop (errors, reliability score). Defaults to plain
  //     `--text-primary` so most cards read calmly.
  //
  // Skeleton-vs-trend rule: <StatCard> shows the skeleton on the first load
  // only, so the trend chip survives periodic refreshes.
  import StatCard from '#lib/components/dashboard/StatCard.svelte';
  import TrendingValue from '#lib/components/dashboard/TrendingValue.svelte';
  import type { IconName, Tone } from '#lib/icons.js';

  let {
    label,
    period,
    value,
    subtitle,
    subtitle2,
    icon,
    iconTone,
    valueColor = 'var(--text-primary)',
    loading = false,
    href,
    trendValue,
  }: {
    label: string;
    period?: string;
    value: string | number;
    subtitle?: string;
    subtitle2?: string;
    icon: IconName;
    /** Override the icon's default category tone (`ICON_TONE[name]`). */
    iconTone?: Tone;
    /** Color for the value digits and trend chip — opt-in emphasis (errors,
     *  reliability score). Defaults to `--text-primary`. */
    valueColor?: string;
    loading?: boolean;
    href?: string;
    /** Opt-in numeric for trend tracking: the card renders a ↑/↓ chip when
     *  it moved in the latest refresh. `undefined` while the reading is
     *  missing — never a placeholder `0`. */
    trendValue?: number;
  } = $props();

</script>

<StatCard
  {label}
  {period}
  {icon}
  {iconTone}
  {subtitle}
  {subtitle2}
  {href}
  {loading}
>
  <TrendingValue {value} {trendValue} color={valueColor} />
</StatCard>
