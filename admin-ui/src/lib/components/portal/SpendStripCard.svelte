<script lang="ts">
  /**
   * Portal Home — the caller's spend per UTC day over the last 7, today last,
   * as a stat card of bars (`spendBars`, `#lib/portalHome.js`). Each bar names
   * its day, spend and requests in words (title and accessible name), not
   * only by its height.
   */
  import type { PortalHome } from '#lib/api-types.js';
  import StatCard from '#lib/components/dashboard/StatCard.svelte';
  import { spendBars } from '#lib/portalHome.js';
  import { formatCost, formatUtcDay, formatUtcWeekday } from '#lib/formatters.js';
  import { m } from '#lib/paraglide/messages.js';

  let { days, loading = false }: { days: PortalHome['daily'] | undefined; loading?: boolean } = $props();

  const bars = $derived(spendBars(days ?? []));
  const describe = (b: (typeof bars)[number]) =>
    m.portal_home_strip_bar({
      day: formatUtcDay(b.day),
      spend: b.amount == null ? m.spend_mixed_short() : formatCost(b.amount, b.currency),
      count: b.requests,
    });
</script>

<StatCard label={m.portal_home_strip_title()} icon="bars3" {loading}>
  <div class="flex items-end gap-1.5 h-10" role="list" aria-label={m.portal_home_strip_title()} data-testid="spend-strip">
    {#each bars as b (b.day)}
      <div class="flex-1 h-full flex flex-col justify-end" role="listitem" aria-label={describe(b)} title={describe(b)}>
        <div
          class="w-full rounded-sm {b.today ? 'bg-(--accent)' : 'bg-(--chart-2)'}"
          style="height: {Math.max(2, Math.round(b.ratio * 100))}%"></div>
      </div>
    {/each}
  </div>
  <div class="flex gap-1.5 mt-1 text-[10px] text-(--text-tertiary)" aria-hidden="true">
    {#each bars as b (b.day)}
      <span class="flex-1 text-center truncate {b.today ? 'text-(--text-primary) font-medium' : ''}">{formatUtcWeekday(b.day)}</span>
    {/each}
  </div>
</StatCard>
