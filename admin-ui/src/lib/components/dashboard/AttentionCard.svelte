<script lang="ts">
  // Clickable attention tile for the Dashboard Overview. The semantic icon
  // (via <IconTile>) is fixed category identity — it never changes with
  // state. State (count value, severity, direction) lives in the count
  // digit's color and an inline ↑/↓ trend chip rendered before the digits
  // when the count moved in the latest refresh. Trend tracking is shared
  // with <MetricCard> via the <TrendingValue> subcomponent.
  //
  // Severity drives the count color only:
  //   critical → --error  | warning → --warning  | info → --accent  | ok → --text-tertiary
  import StatCard from '#lib/components/dashboard/StatCard.svelte';
  import TrendingValue from '#lib/components/dashboard/TrendingValue.svelte';
  import type { IconName, Tone } from '#lib/icons.js';

  type Severity = 'critical' | 'warning' | 'info' | 'ok';

  let {
    label,
    period,
    count,
    severity,
    icon,
    iconTone,
    subtitle,
    href,
    loading = false,
  }: {
    label: string;
    period?: string;
    /** `undefined` until the count is known — shown as `--`, never as a
     *  placeholder `0` the trend chip would read as a real count. */
    count?: number;
    severity: Severity;
    icon: IconName;
    /** Override the icon's default category tone — use when the same glyph
     *  carries different meaning across pages (e.g. `clock` is `info` for
     *  latency but `warning` for expiring creds). */
    iconTone?: Tone;
    subtitle?: string;
    href: string;
    loading?: boolean;
  } = $props();

  const SEVERITY_COLOR: Record<Severity, string> = {
    critical: 'var(--error)',
    warning: 'var(--warning)',
    info: 'var(--accent)',
    ok: 'var(--text-tertiary)',
  };
  const color = $derived(SEVERITY_COLOR[severity]);
</script>

<StatCard {label} {period} {icon} {iconTone} {subtitle} {href} {loading}>
  <TrendingValue value={count ?? '--'} trendValue={count} {color} />
</StatCard>
