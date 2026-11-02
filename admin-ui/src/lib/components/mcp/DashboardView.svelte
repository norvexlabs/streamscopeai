<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import SegmentedControl from '#lib/components/forms/SegmentedControl.svelte';
  import { auditHref, toolCallsHref } from '#lib/deeplinks.js';
  import type { components } from '#lib/generated/api-types.js';
  import { formatCount, formatDuration } from '#lib/formatters.js';
  import { consoleScope, currentWorkspaceQuery, dashboardScopeParams, currentPeriodQuery } from '#lib/scope.svelte.js';
  import { latencyCard, reliabilityCard } from '#lib/cardPresets.js';
  import { usePeriodicLoad } from '#lib/hooks.svelte.js';
  import type { ReloadCause } from '#lib/refreshCycle.svelte.js';
  import TimeSeriesChart, { type ChartRow, type ChartSeries } from '#lib/components/charts/TimeSeriesChart.svelte';
  import Panel from '#lib/components/dashboard/Panel.svelte';
  import BreakdownPanel from '#lib/components/dashboard/BreakdownPanel.svelte';
  import MetricCard from '#lib/components/dashboard/MetricCard.svelte';
  import MetricGrid from '#lib/components/dashboard/MetricGrid.svelte';
  import Skeleton from '#lib/components/Skeleton.svelte';
  import type { IconName } from '#lib/icons.js';
  import { tagMarkColor } from '#lib/components/TagBadge.svelte';

  type UpstreamRow = components['schemas']['McpUpstreamServerRow'];
  type VirtualServerRow = components['schemas']['McpVirtualServerRow'];
  type Summary = components['schemas']['McpDashboardSummary'];
  type McpPanel = components['schemas']['McpDashboardPanel'];
  type TimeseriesResp = components['schemas']['McpTimeseriesResponse'];
  type ErrorsByMethod = components['schemas']['McpErrorsByMethodResponse'];

  let { virtualServers, upstreams }: { virtualServers: VirtualServerRow[]; upstreams: UpstreamRow[] } = $props();

  // Deep-links carry the dashboard's live scope (header workspace pin + period)
  // so the audit list opens on exactly what this dashboard shows.
  const linkScope = $derived(dashboardScopeParams(consoleScope.period, consoleScope.workspace));

  let summary = $state<Summary | null>(null);
  let timeseries = $state<TimeseriesResp | null>(null);
  let topTools = $state<McpPanel | null>(null);
  let topEndpoints = $state<McpPanel | null>(null);
  let topUpstreams = $state<McpPanel | null>(null);
  let topUsers = $state<McpPanel | null>(null);
  let topResources = $state<McpPanel | null>(null);
  let topPrompts = $state<McpPanel | null>(null);
  let methodDist = $state<McpPanel | null>(null);
  let topApps = $state<McpPanel | null>(null);
  let errorsByMethod = $state<ErrorsByMethod | null>(null);
  let loading = $state(true);
  let error = $state('');

  let toolsSortBy = $state<'count' | 'p95'>('count');
  // The Top Tools panel is written by the latest read only: `loadAll` and a
  // sort flip each take a generation, and an older answer is dropped.
  let toolsGen = 0;

  // A refresh whose read fails keeps the panel it re-read; the mount and a
  // scope change ask a new question, and a panel that failed shows nothing.
  async function loadAll(cause?: ReloadCause) {
    const keep = cause === 'refresh';
    const tools = ++toolsGen;
    loading = true;
    error = '';
    const baseQuery = {
      ...currentPeriodQuery(), ...currentWorkspaceQuery(),
      limit: 5,
    };
    const toolsQuery = { ...baseQuery, sort_by: toolsSortBy };
    try {
      const [s, ts, tt, te, tu, tus, tr, tp, md, ta, eb] = await Promise.all([
        adminApi.GET('/api/v1/admin/mcp/dashboard/summary', { params: { query: baseQuery } }),
        adminApi.GET('/api/v1/admin/mcp/dashboard/timeseries', { params: { query: baseQuery } }),
        adminApi.GET('/api/v1/admin/mcp/dashboard/by-tool', { params: { query: toolsQuery } }),
        adminApi.GET('/api/v1/admin/mcp/dashboard/by-endpoint', { params: { query: baseQuery } }),
        adminApi.GET('/api/v1/admin/mcp/dashboard/by-upstream', { params: { query: baseQuery } }),
        adminApi.GET('/api/v1/admin/mcp/dashboard/by-user', { params: { query: baseQuery } }),
        adminApi.GET('/api/v1/admin/mcp/dashboard/by-resource', { params: { query: baseQuery } }),
        adminApi.GET('/api/v1/admin/mcp/dashboard/by-prompt', { params: { query: baseQuery } }),
        adminApi.GET('/api/v1/admin/mcp/dashboard/by-method', { params: { query: baseQuery } }),
        adminApi.GET('/api/v1/admin/mcp/dashboard/by-app', { params: { query: baseQuery } }),
        adminApi.GET('/api/v1/admin/mcp/dashboard/errors-by-method', { params: { query: baseQuery } }),
      ]);
      summary = s.data ?? (keep ? summary : null);
      timeseries = ts.data ?? (keep ? timeseries : null);
      if (tools === toolsGen) topTools = tt.data ?? (keep ? topTools : null);
      topEndpoints = te.data ?? (keep ? topEndpoints : null);
      topUpstreams = tu.data ?? (keep ? topUpstreams : null);
      topUsers = tus.data ?? (keep ? topUsers : null);
      topResources = tr.data ?? (keep ? topResources : null);
      topPrompts = tp.data ?? (keep ? topPrompts : null);
      methodDist = md.data ?? (keep ? methodDist : null);
      topApps = ta.data ?? (keep ? topApps : null);
      errorsByMethod = eb.data ?? (keep ? errorsByMethod : null);
      // A refresh that kept a panel says so, until a refresh reads them all.
      if (keep) {
        error = [s, ts, tt, te, tu, tus, tr, tp, md, ta, eb].some((r) => r.error)
          ? 'Some panels could not be refreshed: they show their last figures.'
          : '';
      }
    } catch (e: unknown) {
      error = e instanceof Error ? e.message : 'failed to load dashboard';
    }
    loading = false;
  }

  usePeriodicLoad(() => loadAll(), loadAll);

  // ── Reload top tools when sort dimension flips ─────────────────────────
  function sortToolsBy(by: 'count' | 'p95') {
    if (by === toolsSortBy) return;
    toolsSortBy = by;
    // Also while the first load runs: this read's generation supersedes its
    // panel, which was asked in the other order.
    void reloadTools();
  }
  async function reloadTools() {
    const gen = ++toolsGen;
    const toolsQuery = {
      ...currentPeriodQuery(), ...currentWorkspaceQuery(),
      limit: 5,
      sort_by: toolsSortBy,
    };
    const { data } = await adminApi.GET('/api/v1/admin/mcp/dashboard/by-tool', {
      params: { query: toolsQuery },
    });
    // A re-order asks a new question: rows sorted the other way no longer
    // answer it, so a failed read shows none.
    if (gen === toolsGen) topTools = data ?? null;
  }

  // ── Display helpers ────────────────────────────────────────────────────
  function endpointName(uuid: string | null | undefined): string {
    if (!uuid) return '—';
    return virtualServers.find((v) => v.id === uuid)?.slug ?? uuid.slice(0, 8) + '…';
  }
  function upstreamName(uuid: string | null | undefined): string {
    if (!uuid) return '—';
    return upstreams.find((u) => u.id === uuid)?.name ?? uuid.slice(0, 8) + '…';
  }
  // Prev-period delta. MetricCard already renders an inline ↑/↓ chip when
  // `trendValue` moves between refresh ticks; this is the orthogonal
  // "vs previous period of the same length" line and goes into subtitle2.
  function deltaSubtitle(curr: number, prev: number): string | undefined {
    if (prev === 0) return undefined;
    const pct = ((curr - prev) / prev) * 100;
    return `${pct >= 0 ? '↑' : '↓'} ${Math.abs(pct).toFixed(0)}% vs prev`;
  }

  // ── Metric card definitions — icon + period + subtitle layout, shared
  //    with the LLM and Overview dashboards so the strip reads the same
  //    across protocols.
  const metricCards = $derived<Array<{
    label: string;
    period?: string;
    value: string;
    subtitle?: string;
    subtitle2?: string;
    icon: IconName;
    valueColor?: string;
    trendValue: number | undefined;
  }>>([
    {
      label: 'Calls',
      period: `${consoleScope.periodDays}d`,
      value: summary ? formatCount(summary.calls) : '–',
      subtitle: summary && summary.calls > 0
        ? `${formatCount(summary.unique_users)} ${summary.unique_users === 1 ? 'user' : 'users'} · ${formatCount(summary.sessions)} sessions`
        : undefined,
      subtitle2: summary ? deltaSubtitle(summary.calls, summary.previous.calls) : undefined,
      icon: 'requests',
      trendValue: summary?.calls,
    },
    {
      label: 'Sessions',
      period: `${consoleScope.periodDays}d`,
      value: summary ? formatCount(summary.sessions) : '–',
      subtitle: summary && summary.sessions > 0
        ? `${(summary.calls / summary.sessions).toFixed(1)} calls/session avg`
        : undefined,
      subtitle2: summary ? deltaSubtitle(summary.sessions, summary.previous.sessions) : undefined,
      icon: 'document',
      trendValue: summary?.sessions,
    },
    {
      label: 'Tool calls',
      period: `${consoleScope.periodDays}d`,
      value: summary ? formatCount(summary.tool_calls) : '–',
      subtitle: summary && summary.calls > 0
        ? `${((summary.tool_calls / summary.calls) * 100).toFixed(0)}% of calls`
        : undefined,
      subtitle2: summary ? deltaSubtitle(summary.tool_calls, summary.previous.tool_calls) : undefined,
      icon: 'wrench',
      trendValue: summary?.tool_calls,
    },
    // Latency before Reliability — see lib/cardPresets.ts for the
    // global ordering convention.
    latencyCard({
      p50_ms: summary?.p50_latency_ms,
      p95_ms: summary?.p95_latency_ms,
      p99_ms: summary?.p99_latency_ms,
      periodDays: consoleScope.periodDays,
    }),
    {
      ...reliabilityCard({
        totalRequests: summary?.calls ?? 0,
        errorCount: summary?.errors ?? 0,
        periodDays: consoleScope.periodDays,
      }),
      subtitle2: summary ? deltaSubtitle(summary.errors, summary.previous.errors) : undefined,
    },
    {
      label: 'Live tokens',
      period: 'now',
      value: summary ? formatCount(summary.live_tokens) : '–',
      subtitle: summary && summary.live_tokens > 0
        ? 'spec-OAuth JWTs in flight'
        : undefined,
      icon: 'lock',
      trendValue: summary?.live_tokens,
    },
  ]);

  // ── Chart data: total call volume + dual-latency split ────────────────
  const chartRows = $derived<ChartRow[]>(
    (timeseries?.buckets ?? []).map((b) => ({
      timestamp: new Date(b.timestamp),
      call_count: b.call_count,
      gw_p50: b.gateway_p50_ms,
      gw_p95: b.gateway_p95_ms,
      up_p50: b.upstream_p50_ms,
      up_p95: b.upstream_p95_ms,
    })),
  );
  const isHourly = $derived(timeseries?.interval === 'hour');

  const CALL_SERIES: ChartSeries[] = [
    { key: 'call_count', label: 'Calls', color: 'var(--accent)', fill: true },
  ];
  const LATENCY_SERIES: ChartSeries[] = [
    { key: 'gw_p50', label: 'Gateway P50', color: 'var(--success)', width: 1.5 },
    { key: 'gw_p95', label: 'Gateway P95', color: 'var(--warning)', width: 2 },
    { key: 'up_p50', label: 'Upstream P50', color: 'var(--success)', width: 1.5, dashArray: '4,3' },
    { key: 'up_p95', label: 'Upstream P95', color: 'var(--warning)', width: 2, dashArray: '4,3' },
  ];
</script>

{#if error}
  <div class="bg-(--error-bg) border border-(--error-border) rounded-lg p-3 text-sm text-(--error-text)">
    {error}
  </div>
{/if}

<!-- 6 metric cards via the shared MetricCard — same chrome, same trend chip,
     same sticky-loaded skeleton as every other dashboard. -->
<MetricGrid class="mb-6">
  {#each metricCards as card (card.label)}
    <MetricCard {...card} {loading} />
  {/each}
</MetricGrid>

<!-- 2 timeseries charts -->
<div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
  <TimeSeriesChart
    title="MCP Call Volume"
    {loading}
    empty={summary != null && summary.calls === 0}
    rows={chartRows}
    series={CALL_SERIES}
    formatY={formatCount}
    hourly={isHourly}
    nowRule
  />
  <TimeSeriesChart
    title="MCP Latency: gateway vs upstream"
    {loading}
    empty={summary != null && summary.calls === 0}
    rows={chartRows}
    series={LATENCY_SERIES}
    formatY={formatDuration}
    hourly={isHourly}
    nowRule
  />
</div>

<!-- 4 Top panels -->
<div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-6 mb-6">
  <BreakdownPanel
    title="Top Tools"
    action="View"
    actionHref={toolCallsHref({ kind: 'mcp', ...linkScope })}
    {loading}
    emptyMessage="No tool calls in this period"
    items={topTools?.items ?? []}
    getValue={(t) => t.call_count}
    getRow={(item, max) => ({
      label: item.key,
      value: toolsSortBy === 'p95' ? formatDuration(item.p95_latency_ms ?? 0) : formatCount(item.call_count),
      percent: (item.call_count / max) * 100,
      href: toolCallsHref({ kind: 'mcp', tool_id: item.key, ...linkScope }),
      title: `View tool calls for ${item.key}`,
      barColor: 'var(--chart-2)',
    })}
  >
    {#snippet headerExtra()}
      <SegmentedControl
        value={toolsSortBy}
        onchange={sortToolsBy}
        size="xs"
        framed={false}
        label="Sort tools by"
        options={[
          { value: 'count', label: 'Count' },
          { value: 'p95', label: 'P95' },
        ]} />
    {/snippet}
  </BreakdownPanel>

  <BreakdownPanel
    title="Top Endpoints"
    action="Configure"
    actionHref="/gateways/mcp?tab=endpoints"
    {loading}
    emptyMessage="No endpoint traffic"
    items={topEndpoints?.items ?? []}
    getValue={(e) => e.call_count}
    getRow={(item, max) => ({
      label: endpointName(item.key),
      value: formatCount(item.call_count),
      percent: (item.call_count / max) * 100,
      href: toolCallsHref({ kind: 'mcp', virtual_server_id: item.key, ...linkScope }),
      title: `View tool calls for endpoint ${endpointName(item.key)}`,
      mono: true,
      barColor: 'var(--success)',
    })}
  />

  <BreakdownPanel
    title="Top Upstreams"
    action="Configure"
    actionHref="/gateways/mcp?tab=upstream-servers"
    {loading}
    emptyMessage="No upstream traffic"
    items={topUpstreams?.items ?? []}
    getValue={(u) => u.call_count}
    getRow={(item, max) => ({
      label: upstreamName(item.key),
      value: formatCount(item.call_count),
      percent: (item.call_count / max) * 100,
      href: toolCallsHref({ kind: 'mcp', upstream_server_id: item.key, ...linkScope }),
      title: `View tool calls for upstream ${upstreamName(item.key)}`,
      barColor: 'var(--warning)',
    })}
  />

  <BreakdownPanel
    title="Top Users"
    action="Manage"
    actionHref="/users"
    {loading}
    emptyMessage="No user traffic"
    items={topUsers?.items ?? []}
    getValue={(u) => u.call_count}
    getRow={(item, max) => {
      const userHref = item.user_email
        ? toolCallsHref({ kind: 'mcp', user_email: item.user_email, ...linkScope })
        : item.user_id
          ? toolCallsHref({ kind: 'mcp', user_id: item.user_id, ...linkScope })
          : undefined;
      return {
        label: item.key,
        value: formatCount(item.call_count),
        percent: (item.call_count / max) * 100,
        href: userHref,
        title: userHref ? `View tool calls for ${item.key}` : item.key,
        mono: true,
        barColor: 'var(--chart-3)',
      };
    }}
  />
</div>

<!-- 3 secondary panels -->
<div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6 mb-6">
  <BreakdownPanel
    title="Top Resources"
    action="View"
    actionHref={toolCallsHref({ kind: 'mcp', ...linkScope })}
    {loading}
    emptyMessage="No resources/read calls"
    items={topResources?.items ?? []}
    getValue={(r) => r.call_count}
    getRow={(item, max) => ({
      label: item.key,
      value: formatCount(item.call_count),
      percent: (item.call_count / max) * 100,
      href: toolCallsHref({ kind: 'mcp', resource_uri: item.key, ...linkScope }),
      title: `View tool calls for ${item.key}`,
      mono: true,
      barColor: tagMarkColor('orange'),
    })}
  />

  <BreakdownPanel
    title="Top Prompts"
    action="View"
    actionHref={toolCallsHref({ kind: 'mcp', ...linkScope })}
    {loading}
    emptyMessage="No prompts/get calls"
    items={topPrompts?.items ?? []}
    getValue={(p) => p.call_count}
    getRow={(item, max) => ({
      label: item.key,
      value: formatCount(item.call_count),
      percent: (item.call_count / max) * 100,
      href: toolCallsHref({ kind: 'mcp', prompt_id: item.key, ...linkScope }),
      title: `View tool calls for prompt ${item.key}`,
      barColor: 'var(--chart-5)',
    })}
  />

  <BreakdownPanel
    title="Method Distribution"
    action="View"
    actionHref={auditHref({ kind: 'mcp', ...linkScope })}
    {loading}
    emptyMessage="No traffic"
    items={methodDist?.items ?? []}
    maxValue={methodDist?.total_calls ?? 0}
    getRow={(item, max) => {
      const pct = max > 0 ? (item.call_count / max) * 100 : 0;
      return {
        label: item.key,
        value: `${pct.toFixed(0)}% (${formatCount(item.call_count)})`,
        percent: pct,
        mono: true,
        barColor: 'var(--accent)',
      };
    }}
  />
</div>

<!-- 2 bottom panels -->
<div class="grid grid-cols-1 md:grid-cols-2 gap-6">
  <BreakdownPanel
    title="Top Apps (MCP)"
    {loading}
    emptyMessage="No apps recorded"
    items={topApps?.items ?? []}
    getValue={(a) => a.call_count}
    getRow={(item, max) => ({
      label: item.key,
      value: formatCount(item.call_count),
      percent: (item.call_count / max) * 100,
      href: toolCallsHref({ kind: 'mcp', app_id: item.key, ...linkScope }),
      title: `View tool calls for app ${item.key}`,
      barColor: 'var(--chart-3)',
    })}
  />

  <!-- Errors by Method (not bar-shaped — Panel shell only) -->
  <Panel
    title="Errors by Method"
    action="View"
    actionHref={auditHref({ kind: 'mcp', ...linkScope })}
    {loading}
    empty={!loading && (errorsByMethod?.items?.length ?? 0) === 0}
    emptyMessage="No errors recorded"
  >
    {#snippet skeleton()}
      <Skeleton variant="text" count={5} />
    {/snippet}
    <div class="space-y-3">
      {#each errorsByMethod?.items ?? [] as item (item.method)}
        <div class="flex items-center justify-between text-sm">
          <span class="text-(--text-primary) font-mono">{item.method}</span>
          <span class="text-xs text-(--text-secondary) font-mono">
            {formatCount(item.error_count)} error{item.error_count === 1 ? '' : 's'}
            {#if item.top_error_code}<span class="ml-2 text-(--error)">code {item.top_error_code}</span>{/if}
          </span>
        </div>
      {/each}
    </div>
  </Panel>
</div>
