<script lang="ts">
  // Proxy-dashboard protocol card: a protocol's inbound vs outbound request
  // counts shown as two co-equal stats (translation moves a request between
  // the two), plus its error rate. Chrome: <StatCard>.
  import StatCard from '#lib/components/dashboard/StatCard.svelte';
  import { statValueClass, useStatCompact } from '#lib/components/dashboard/statCard.js';
  import type { IconName, Tone } from '#lib/icons.js';

  let {
    label,
    inbound,
    outbound,
    subtitle,
    icon,
    iconTone,
    loading = false,
    href,
  }: {
    label: string;
    inbound: string | number;
    outbound: string | number;
    subtitle?: string;
    icon: IconName;
    /** Override the icon's default category tone. Each protocol picks a tone
     *  to stay visually distinct across the four-card row. */
    iconTone?: Tone;
    loading?: boolean;
    href?: string;
  } = $props();

  const compact = useStatCompact();
</script>

<StatCard {label} {icon} {iconTone} {subtitle} {href} {loading}>
  <!-- Two co-equal stats: each stays whole on one line; on a narrow card the
       outbound figure moves under the inbound one rather than being cut off. -->
  <div class="flex flex-wrap gap-x-4 text-(--text-primary)">
    <p class={statValueClass(compact())} title={`${inbound} in`}>{inbound}<span class="text-xs font-medium text-(--text-tertiary) ml-1">in</span></p>
    <p class={statValueClass(compact())} title={`${outbound} out`}>{outbound}<span class="text-xs font-medium text-(--text-tertiary) ml-1">out</span></p>
  </div>
</StatCard>
