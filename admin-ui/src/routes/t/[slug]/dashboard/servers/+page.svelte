<script lang="ts">
  // Dashboard → Servers: every LLM upstream server — except a pass-through one
  // that is turned off — whether it can serve now, and what it handled over the
  // period. Health and configuration come from
  // the server resource; traffic, latency, refusals and live load from
  // /analytics/servers, joined by id. A row opens the server's own dashboard.
  import { adminApi } from '#lib/api-client.js';
  import { extractError, fetchAllPages } from '#lib/api-helpers.js';
  import type { components } from '#lib/generated/api-types.js';
  import { consoleScope, currentWorkspaceQuery, currentPeriodQuery } from '#lib/scope.svelte.js';
  import { usePeriodicLoad } from '#lib/hooks.svelte.js';
  import { thref } from '#lib/tenant.js';
  import { formatCount, formatDuration, formatShare } from '#lib/formatters.js';
  import { trailingIncomplete } from '#lib/chartHelpers.js';
  import { SERVER_HEALTH, fleetOrder, isOffPassthrough, sentOf, serverHealthReason } from '#lib/endpoints.js';
  import DashboardScaffold from '#lib/components/dashboard/DashboardScaffold.svelte';
  import MetricCard from '#lib/components/dashboard/MetricCard.svelte';
  import MetricGrid from '#lib/components/dashboard/MetricGrid.svelte';
  import Panel from '#lib/components/dashboard/Panel.svelte';
  import StatusChip from '#lib/components/StatusChip.svelte';
  import Sparkline from '#lib/components/Sparkline.svelte';
  import ProviderIcon from '#lib/components/ProviderIcon.svelte';
  import LimitMeter from '#lib/components/limits/LimitMeter.svelte';
  import type { PageProps } from './$types';

  let { params }: PageProps = $props();

  type Server = components['schemas']['ServerResponse'];
  type Fleet = components['schemas']['ServerFleetResponse'];
  type FleetEntry = components['schemas']['ServerFleetEntry'];

  let slug = $derived(params.slug);
  let servers = $state<Server[]>([]);
  let fleet = $state<Fleet | null>(null);
  let loading = $state(true);
  let error = $state('');

  async function load() {
    loading = true;
    error = '';
    try {
      const [all, analytics] = await Promise.all([
        fetchAllPages<Server>((offset, limit) =>
          adminApi.GET('/api/v1/admin/servers', { params: { query: { offset, limit } } }),
        ),
        adminApi.GET('/api/v1/admin/analytics/servers', {
          params: { query: { ...currentPeriodQuery(), ...currentWorkspaceQuery() } },
        }),
      ]);
      // A pass-through server that is turned off does not exist for the
      // gateways, so it has nothing to show here.
      servers = all.filter((s) => !isOffPassthrough(s));
      if (analytics.error) error = extractError(analytics.error);
      else fleet = analytics.data ?? null;
    } catch (e: unknown) {
      error = e instanceof Error ? e.message : 'Failed to load servers';
    } finally {
      loading = false;
    }
  }

  usePeriodicLoad(load);

  const byId = $derived(new Map((fleet?.servers ?? []).map((e) => [e.server_id, e])));
  const rows = $derived(
    fleetOrder(
      servers.map((s) => {
        const entry: FleetEntry | undefined = byId.get(s.id);
        return { ...s, entry, requests: entry?.traffic.requests ?? 0 };
      }),
    ),
  );
  const partialLast = $derived(trailingIncomplete(fleet?.bucket_starts ?? [], fleet?.interval));

  const count = (h: Server['health']) => servers.filter((s) => s.health === h).length;
  const totals = $derived.by(() => {
    // The slots are stated only when every reporting server states its own: a
    // partial sum would read as a limit the fleet does not have.
    const t = { requests: 0, errors: 0, refusals: 0, passedOn: 0, queued: 0, inFlight: 0, capacity: 0 as number | null, held: 0, live: 0 };
    // Summed over the rows shown, so the cards and the table agree: a server
    // deleted since keeps traffic in the window but has no row.
    for (const e of rows.flatMap((r) => (r.entry ? [r.entry] : []))) {
      t.requests += e.traffic.requests;
      t.errors += e.traffic.errors;
      t.refusals += e.traffic.refusals;
      t.passedOn += e.traffic.passed_on;
      t.queued += e.traffic.queued;
      // A server read only for its engine metrics has no count to add.
      if (e.live?.gated) {
        t.live += 1;
        t.inFlight += e.live.in_flight;
        t.capacity = t.capacity != null && e.live.capacity != null ? t.capacity + e.live.capacity : null;
        t.held += e.live.held;
      }
    }
    return t;
  });

  const cards = $derived([
    {
      label: 'Servers',
      value: formatCount(servers.length),
      subtitle: `${count('down')} down · ${count('degraded')} degraded`,
      subtitle2: `${count('healthy')} healthy`,
      icon: 'edge' as const,
      valueColor: count('down') > 0 ? 'var(--error)' : count('degraded') > 0 ? 'var(--warning)' : undefined,
    },
    {
      label: 'Requests',
      period: `${consoleScope.periodDays}d`,
      value: formatCount(totals.requests),
      // Of what was sent: a refusal is not a failure.
      subtitle: `${formatShare(totals.errors, sentOf(totals))} failed`,
      icon: 'requests' as const,
      trendValue: totals.requests,
    },
    {
      label: 'Refused for capacity',
      period: `${consoleScope.periodDays}d`,
      value: formatCount(totals.refusals),
      subtitle: totals.passedOn > 0
        ? `${formatCount(totals.passedOn)} moved on to another target`
        : `${formatShare(totals.refusals, totals.requests)} of requests`,
      icon: 'blocked' as const,
      valueColor: totals.refusals > 0 ? 'var(--warning)' : undefined,
      trendValue: totals.refusals,
    },
    {
      label: 'Waited for capacity',
      period: `${consoleScope.periodDays}d`,
      value: formatCount(totals.queued),
      subtitle: `${formatShare(totals.queued, sentOf(totals))} of requests sent`,
      icon: 'clock' as const,
      trendValue: totals.queued,
    },
    {
      label: 'In flight now',
      value: totals.live > 0 ? formatCount(totals.inFlight) : '--',
      subtitle: totals.live > 0 ? `${formatCount(totals.held)} held at the gateway` : 'No gated server reporting',
      subtitle2: totals.live > 0 && totals.capacity != null ? `of ${formatCount(totals.capacity)} slots` : undefined,
      icon: 'bolt' as const,
    },
  ]);

</script>

<DashboardScaffold
  title="Servers"
  subtitle="Every LLM upstream server: whether it can serve now, its load, latency and scheduling"
>
  {#if error}
    <div class="bg-(--error-bg) border border-(--error-border) rounded-lg p-3 mb-4 text-sm text-(--error-text)">
      {error}
    </div>
  {/if}

  <MetricGrid class="mb-6">
    {#each cards as card (card.label)}
      <MetricCard {...card} loading={loading && fleet == null} />
    {/each}
  </MetricGrid>

  <Panel
    title="Servers"
    subtitle="Down and degraded first, then by traffic. Latency excludes the wait for capacity."
    flush
    {loading}
    empty={!loading && rows.length === 0}
    emptyMessage="No LLM upstream server is configured."
  >
    <div class="overflow-x-auto">
      <table class="w-full text-sm" data-server-fleet>
        <thead>
          <tr class="border-b border-(--border) text-xs text-(--text-secondary) uppercase tracking-wider">
            <th class="px-5 py-2.5 text-left font-medium">Server</th>
            <th class="px-3 py-2.5 text-left font-medium">Health</th>
            <th class="px-3 py-2.5 text-right font-medium">Requests</th>
            <th class="px-3 py-2.5 text-right font-medium">Failed</th>
            <th class="px-3 py-2.5 text-right font-medium">Refused</th>
            <th class="px-3 py-2.5 text-right font-medium">P95 latency</th>
            <th class="px-3 py-2.5 text-right font-medium">P95 TTFT</th>
            <th class="px-3 py-2.5 text-right font-medium">P95 wait</th>
            <th class="px-5 py-2.5 text-left font-medium w-48">Live</th>
          </tr>
        </thead>
        <tbody>
          {#each rows as s (s.id)}
            {@const t = s.entry?.traffic}
            <tr class="border-b border-(--border) last:border-0 hover:bg-(--bg-elevated)" data-server-row={s.id}>
              <td class="px-5 py-3">
                <a
                  href={thref(slug, `/dashboard/servers/${s.id}`)}
                  class="inline-flex items-center gap-2 font-medium text-(--text-primary) hover:text-(--accent)"
                >
                  <ProviderIcon name={s.provider} size="md" className="text-(--text-secondary) shrink-0" />
                  <span class="truncate">{s.name}</span>
                </a>
              </td>
              <td class="px-3 py-3">
                <StatusChip {...SERVER_HEALTH[s.health]} status={s.health} title={serverHealthReason(s) ?? undefined} />
              </td>
              <td class="px-3 py-3 text-right">
                <span class="inline-flex items-center gap-2 justify-end">
                  {#if s.entry}
                    <Sparkline values={s.entry.buckets} {partialLast} title={`${s.name} requests`} />
                  {/if}
                  <span class="font-mono tabular-nums">{formatCount(t?.requests ?? 0)}</span>
                </span>
              </td>
              <td class="px-3 py-3 text-right font-mono tabular-nums {t && t.errors > 0 ? 'text-(--error-text)' : 'text-(--text-secondary)'}"
                  title={t && t.failed_over > 0 ? `${t.failed_over} of them failed over to another replica or target` : undefined}>
                {t ? formatShare(t.errors, sentOf(t)) : '--'}
              </td>
              <td class="px-3 py-3 text-right font-mono tabular-nums {t && t.refusals > 0 ? 'text-(--warning-text)' : 'text-(--text-secondary)'}"
                  title={t && t.passed_on > 0 ? `${t.passed_on} of them moved on to another target` : undefined}>
                {formatCount(t?.refusals ?? 0)}
              </td>
              <td class="px-3 py-3 text-right font-mono tabular-nums">{t?.latency_p95_ms != null ? formatDuration(t.latency_p95_ms) : '--'}</td>
              <td class="px-3 py-3 text-right font-mono tabular-nums">{t?.ttft_p95_ms != null ? formatDuration(t.ttft_p95_ms) : '--'}</td>
              <td class="px-3 py-3 text-right font-mono tabular-nums">{t?.queue_wait_p95_ms != null ? formatDuration(t.queue_wait_p95_ms) : '--'}</td>
              <td class="px-5 py-3">
                {#if s.entry?.live?.gated}
                  <LimitMeter label="In flight" used={s.entry.live.in_flight} cap={s.entry.live.capacity} fmt={formatCount} />
                  {#if s.entry.live.held > 0 || s.entry.live.engines_silent > 0}
                    <p class="text-[10px] mt-0.5 text-(--warning-text)">
                      {#if s.entry.live.held > 0}{formatCount(s.entry.live.held)} held{/if}
                      {#if s.entry.live.held > 0 && s.entry.live.engines_silent > 0} · {/if}
                      {#if s.entry.live.engines_silent > 0}{s.entry.live.engines_silent} engine{s.entry.live.engines_silent === 1 ? '' : 's'} silent{/if}
                    </p>
                  {/if}
                {:else if s.gated}
                  <span class="text-xs text-(--text-secondary)" title="No connected gateway has reported this server's load">No reading</span>
                {:else}
                  <span class="text-xs text-(--text-tertiary)" title="Neither an in-flight bound nor a queue bound is set, so the gateway keeps no count here">Not gated</span>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  </Panel>
</DashboardScaffold>
