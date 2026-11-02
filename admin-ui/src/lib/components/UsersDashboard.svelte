<script lang="ts">
  import { formatCount, formatSpend, formatTimeAgo, formatDate, formatKeyLabel } from '#lib/formatters.js';
  import { amountBeside } from '#lib/spend.js';
  import { sessionsHref as sessionsListHref } from '#lib/deeplinks.js';
  import { consoleScope, dashboardScopeParams } from '#lib/scope.svelte.js';
  import MetricCard from '#lib/components/dashboard/MetricCard.svelte';
  import MetricGrid from '#lib/components/dashboard/MetricGrid.svelte';
  import BreakdownPanel from '#lib/components/dashboard/BreakdownPanel.svelte';
  import KeyListPanel from '#lib/components/dashboard/KeyListPanel.svelte';
  import PeriodBadge from '#lib/components/dashboard/PeriodBadge.svelte';
  import type { IconName, Tone } from '#lib/icons.js';
  import type { UsersKeysDashboardResponse } from '#lib/api-types.js';
  import { tagMarkColor } from '#lib/components/TagBadge.svelte';

  type Dashboard = UsersKeysDashboardResponse;
  type DashboardSummary = Dashboard['summary'];

  interface Props {
    data: Dashboard | null;
    loading: boolean;
    periodDays: number;
    onRevokeDormantKey: (keyId: string) => void;
  }

  let { data, loading, periodDays, onRevokeDormantKey }: Props = $props();

  const dashboard = $derived(data);

  const summary: DashboardSummary = $derived(dashboard?.summary ?? {
    total_users: 0, active_users: 0, disabled_users: 0,
    active_keys: 0, expired_keys: 0, revoked_keys: 0,
    total_requests: 0, spend: null,
  });

  const topUsersByCost = $derived(dashboard?.top_users_by_cost ?? []);
  // The first stated figure sets the denomination the bars are measured in
  // (a leader whose window straddles a currency change states none).
  const costLeader = $derived(topUsersByCost.find((u) => u.spend)?.spend);
  const topKeysByRequests = $derived(dashboard?.top_keys_by_requests ?? []);
  const dormantKeys = $derived(dashboard?.dormant_keys ?? []);
  const expiringSoon = $derived(dashboard?.expiring_soon ?? []);

  // Deep-links carry the dashboard's live scope (header workspace pin + period)
  // so the sessions list opens on exactly what this dashboard shows.
  const linkScope = $derived(dashboardScopeParams(consoleScope.period, consoleScope.workspace));

  function sessionsHref(email?: string | null): string | null {
    if (!email) return null;
    return sessionsListHref({ user_email: email, ...linkScope });
  }

  function expiryCountdown(expiresAt: string): { text: string; color: string } {
    const diff = new Date(expiresAt).getTime() - Date.now();
    const days = Math.ceil(diff / (1000 * 60 * 60 * 24));
    if (days <= 0) return { text: 'Expired', color: 'var(--error)' };
    if (days < 7) return { text: `${days}d left`, color: 'var(--error)' };
    if (days < 30) return { text: `${days}d left`, color: 'var(--warning)' };
    return { text: `${days}d left`, color: 'var(--text-secondary)' };
  }

  const metricCards: Array<{
    label: string;
    value: string;
    subtitle: string;
    icon: IconName;
    iconTone: Tone;
    trendValue: number;
  }> = $derived([
    {
      label: 'Total Users',
      value: formatCount(summary.total_users),
      subtitle: `${summary.active_users} active / ${summary.disabled_users} disabled`,
      icon: 'users',
      iconTone: 'info',
      trendValue: summary.total_users,
    },
    {
      label: 'Active Keys',
      value: formatCount(summary.active_keys),
      subtitle: 'Currently valid',
      icon: 'key',
      iconTone: 'success',
      trendValue: summary.active_keys,
    },
    {
      label: 'Expired Keys',
      value: formatCount(summary.expired_keys),
      subtitle: 'Past expiry date',
      icon: 'clock',
      iconTone: 'error',
      trendValue: summary.expired_keys,
    },
    {
      label: 'Revoked Keys',
      value: formatCount(summary.revoked_keys),
      subtitle: 'Manually disabled',
      icon: 'blocked',
      iconTone: 'warning',
      trendValue: summary.revoked_keys,
    },
  ]);

  // Build the rich `meta` chip line shown under each BreakdownRow's bar.
  // Each entry skips itself if its source field is missing — callers can
  // splat the conditional chips without filter().
  function keyMeta(item: Dashboard['top_keys_by_requests'][number]) {
    const out: Array<{ text: string }> = [];
    if (item.user_email) out.push({ text: item.user_email });
    if (item.workspace_name) out.push({ text: item.workspace_name });
    // A key whose window straddles a currency change says so, rather than
    // dropping its spend from the line.
    if (!item.spend || item.spend.amount > 0) out.push({ text: formatSpend(item.spend) });
    return out;
  }
</script>

<!-- Summary metric cards — same MetricCard component every dashboard uses, so
     the four-tile strip keeps the shared ↑/↓ trend chip, sticky-loaded
     skeleton, and category-coloured IconTile chrome. -->
<MetricGrid>
  {#each metricCards as card}
    <MetricCard {...card} {loading} />
  {/each}
</MetricGrid>

<!-- Ranked sections -->
<div class="grid grid-cols-1 md:grid-cols-2 gap-6 mt-6">
  <BreakdownPanel
    title="Top Users by Cost"
    {loading}
    emptyMessage="No usage in this window"
    items={topUsersByCost}
    getKey={(u) => u.user_id}
    getValue={(u) => amountBeside(u.spend, costLeader)}
    getRow={(item, max) => ({
      label: item.email ?? item.user_id,
      value: formatSpend(item.spend),
      sub: `${formatCount(item.request_count)} requests`,
      // A user whose window straddles a currency change has no one figure:
      // a full-width neutral bar marks its place (the server's order, by its
      // spend in today's currency) without measuring it against the others.
      percent: item.spend
        ? max > 0
          ? (amountBeside(item.spend, costLeader) / max) * 100
          : 0
        : 100,
      href: sessionsHref(item.email) ?? undefined,
      title: item.display_name ?? undefined,
      barColor: item.spend ? 'var(--chart-2)' : 'var(--text-tertiary)',
      animateBar: true,
    })}
  >
    {#snippet headerExtra()}
      <PeriodBadge period={periodDays} />
    {/snippet}
  </BreakdownPanel>

  <BreakdownPanel
    title="Top Keys by Requests"
    action="Manage"
    actionHref="/users"
    {loading}
    emptyMessage="No key usage in this window"
    items={topKeysByRequests}
    getKey={(k) => k.key_id}
    getValue={(k) => k.request_count ?? 0}
    getRow={(item, max) => ({
      label: formatKeyLabel(item.key_name, item.key_prefix),
      value: formatCount(item.request_count),
      percent: (item.request_count / max) * 100,
      href: sessionsHref(item.user_email) ?? undefined,
      title: `${item.key_prefix}…`,
      meta: keyMeta(item),
      barColor: tagMarkColor('teal'),
      animateBar: true,
    })}
  >
    {#snippet headerExtra()}
      <PeriodBadge period={periodDays} />
    {/snippet}
  </BreakdownPanel>

  <KeyListPanel
    title="Dormant Keys"
    {loading}
    emptyMessage="No dormant keys"
    {periodDays}
    items={dormantKeys}
    getKeyId={(i) => i.key_id}
    getName={(i) => formatKeyLabel(i.key_name, i.key_prefix)}
    getEmail={(i) => i.user_email}
    getProvider={(i) => i.workspace_name ? { name: i.workspace_name } : null}
    getHref={(i) => sessionsHref(i.user_email)}
  >
    {#snippet metaTail(item)}
      {#if item.last_used_at}
        <span>Last used {formatTimeAgo(item.last_used_at)}</span>
      {:else}
        <span class="text-(--warning)">Never used</span>
      {/if}
    {/snippet}
    {#snippet trailing(item)}
      <button
        onclick={(e) => { e.preventDefault(); e.stopPropagation(); onRevokeDormantKey(item.key_id); }}
        class="text-xs px-2 py-1 rounded-sm text-(--error) hover:bg-(--error-bg) transition-colors shrink-0"
      >Revoke</button>
    {/snippet}
  </KeyListPanel>

  <KeyListPanel
    title="Expiring Soon"
    {loading}
    emptyMessage="No keys expiring soon"
    {periodDays}
    items={expiringSoon}
    getKeyId={(i) => i.key_id}
    getName={(i) => formatKeyLabel(i.key_name, i.key_prefix)}
    getEmail={(i) => i.user_email}
    getProvider={(i) => i.workspace_name ? { name: i.workspace_name } : null}
    getHref={(i) => sessionsHref(i.user_email)}
  >
    {#snippet metaTail(item)}
      <span>Expires {formatDate(item.expires_at)}</span>
    {/snippet}
    {#snippet trailing(item)}
      {@const countdown = expiryCountdown(item.expires_at)}
      <span class="text-sm font-mono tabular-nums shrink-0" style="color: {countdown.color}">{countdown.text}</span>
    {/snippet}
  </KeyListPanel>
</div>
