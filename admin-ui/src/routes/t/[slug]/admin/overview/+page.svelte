<script lang="ts">
  import type { GlobalEdgeStats, EdgeStatsSeries, GlobalUsageSummary, EdgeNode, AuditLogRow } from '#lib/api-types.js';
  import type { components } from '#lib/generated/api-types.js';
  import { adminApi } from '#lib/api-client.js';
  import { goto } from '$app/navigation';
  import { consoleScope, currentWorkspaceQuery, dashboardScopeParams, currentPeriodQuery } from '#lib/scope.svelte.js';
  import { page } from '$app/state';
  import { thref } from '#lib/tenant.js';
  import { auditHref } from '#lib/deeplinks.js';
  import type { PageProps } from './$types';

  let { params }: PageProps = $props();

  let slug = $derived(params.slug);
  // Deep-links carry the dashboard's live scope (header workspace pin + period)
  // so the audit list opens on exactly what this overview shows.
  const linkScope = $derived(dashboardScopeParams(consoleScope.period, consoleScope.workspace));
  import { usePeriodicLoad } from '#lib/hooks.svelte.js';
  import { formatBytes, formatCount } from '#lib/formatters.js';

  type ApplianceDisk = components['schemas']['ApplianceDisk'];
  type ApplianceDiskPressure = components['schemas']['ApplianceDiskPressure'];
  import DashboardScaffold from '#lib/components/dashboard/DashboardScaffold.svelte';
  import MetricCard from '#lib/components/dashboard/MetricCard.svelte';
  import MetricGrid from '#lib/components/dashboard/MetricGrid.svelte';
  import Panel from '#lib/components/dashboard/Panel.svelte';
  import Callout from '#lib/components/Callout.svelte';
  import TimeSeriesChart, { type ChartRow, type ChartSeries } from '#lib/components/charts/TimeSeriesChart.svelte';
  import { seriesColor } from '#lib/chartHelpers.js';
  import AuditRowCard from '#lib/components/audit/AuditRowCard.svelte';

  // Latency percentile lines — severity colours, like the LLM latency card.
  const LATENCY_SERIES: ChartSeries[] = [
    { key: 'p50', label: 'p50', color: 'var(--success)' },
    { key: 'p95', label: 'p95', color: 'var(--warning)' },
    { key: 'p99', label: 'p99', color: 'var(--error)' },
  ];

  let edgeStats = $state<GlobalEdgeStats | null>(null);
  let edges = $state<EdgeNode[]>([]);
  // Whether the edge list came back — a failed fetch empties `edges`, which
  // is no reading for the trend chip.
  let edgesLoaded = $state(false);
  let tenants = $state<GlobalUsageSummary['tenants']>([]);
  let events = $state<AuditLogRow[]>([]);
  let platformDisk = $state<ApplianceDisk | null>(null);
  let platformPressure = $state<ApplianceDiskPressure | null>(null);
  let loading = $state(true);
  // Per-call errors — a failed fetch must read as an error, never as a
  // misleading empty state on an operator's monitoring dashboard.
  let statsError = $state('');
  let tenantsError = $state('');
  let auditError = $state('');

  const series = $derived<EdgeStatsSeries[]>(edgeStats?.edges ?? []);
  const isHourly = $derived(edgeStats?.interval === 'hour');
  const chartSeries = $derived<ChartSeries[]>(
    series.map((e, i) => ({ key: e.edge_name, label: e.edge_name, color: seriesColor(i) })),
  );

  // Edge connectivity (live status) — fetched separately from /admin/edge-nodes.
  const connectedEdges = $derived(edges.filter((e) => e.is_connected).length);
  const edgeColor = $derived(
    edges.length === 0
      ? 'var(--text-secondary)'
      : connectedEdges === edges.length
        ? 'var(--success)'
        : 'var(--warning)',
  );
  const pendingByEdge = $derived(
    edges
      .map((e) => ({ name: e.name, pending: e.metadata?.stats?.pending_audit_count ?? 0 }))
      .filter((e) => e.pending > 0)
      .sort((a, b) => b.pending - a.pending),
  );
  const pendingTotal = $derived(pendingByEdge.reduce((sum, e) => sum + e.pending, 0));

  // Response-cache occupancy per edge, from each edge's latest heartbeat. This
  // is process state — what the store is holding and what it gave up to hold it
  // — which no audit row can answer: a request's row records what happened to
  // that request, never what became of the entries around it.
  //
  // `metadata.stats` is the LAST heartbeat received for the edge, so on a
  // multi-replica edge it is one replica's view, not the fleet's — the same
  // caveat the memory reading carries.
  const cacheByEdge = $derived(
    edges
      // Every field is optional on the wire (a replica predating the feature
      // reports none), so defaults are applied before anything is compared —
      // an absent counter is zero, never a silently-skipped edge.
      .map((e) => {
        const c = e.metadata?.stats?.cache;
        const entries = c?.entries ?? 0;
        const bytes = c?.bytes ?? 0;
        const maxBytes = c?.max_bytes ?? 0;
        const vectors = c?.semantic_vectors ?? 0;
        const stores = c?.stores_total ?? 0;
        return {
          name: e.name,
          entries,
          bytes,
          stores,
          evictions: c?.evictions_total ?? 0,
          expired: c?.expired_total ?? 0,
          pct: maxBytes > 0 ? (bytes / maxBytes) * 100 : null,
          // A vector outliving its entry has no symptom other than memory, so
          // it needs some surfaced signal. This one is sound but one-way: more
          // vectors than entries PROVES a leak, while a leak smaller than the
          // count of exact-mode (vectorless) entries stays hidden inside it.
          leakedVectors: Math.max(0, vectors - entries),
        };
      })
      // An edge that has never stored anything has no cache to report on —
      // including it would read as "the cache is broken" rather than "unused".
      .filter((e) => e.entries > 0 || e.stores > 0),
  );

  // Window aggregates for the metric cards.
  const totalRequests = $derived(
    series.reduce((sum, e) => sum + e.buckets.reduce((s, b) => s + b.requests, 0), 0),
  );
  const totalErrors = $derived(
    series.reduce((sum, e) => sum + e.buckets.reduce((s, b) => s + b.errors, 0), 0),
  );
  // Mean p95 platform overhead across the window — the metric-card headline.
  const p95LatencyMs = $derived.by(() => {
    let sum = 0;
    let n = 0;
    for (const e of series) {
      for (const b of e.buckets) {
        sum += b.p95_overhead_ms;
        n++;
      }
    }
    return n > 0 ? sum / n : 0;
  });

  /** Platform latency rows — p50/p95/p99 averaged across edges per bucket.
   *  For the typical single-edge deployment the mean-of-one is exact. */
  const latencyRows = $derived.by(() => {
    const rows: ChartRow[] = [];
    if (series.length === 0) return rows;
    const len = series[0].buckets.length;
    for (let i = 0; i < len; i++) {
      let p50 = 0, p95 = 0, p99 = 0, n = 0;
      for (const e of series) {
        const b = e.buckets[i];
        // Skip edges with no traffic this bucket — a zero would dilute the
        // cross-edge mean (each edge already drops its own idle windows).
        if (!b || b.p95_overhead_ms <= 0) continue;
        p50 += b.p50_overhead_ms;
        p95 += b.p95_overhead_ms;
        p99 += b.p99_overhead_ms;
        n++;
      }
      rows.push({
        timestamp: new Date(series[0].buckets[i].bucket_start),
        p50: n > 0 ? p50 / n : 0,
        p95: n > 0 ? p95 / n : 0,
        p99: n > 0 ? p99 / n : 0,
      });
    }
    return rows;
  });

  /** Pivot the per-edge series into chart rows keyed by edge name. Every
   *  edge shares the same bucket axis (the backend fills it), so bucket `i`
   *  lines up across edges. */
  function chartData(metric: 'requests' | 'avg_cpu_percent' | 'avg_memory_mb'): ChartRow[] {
    if (series.length === 0) return [];
    const len = series[0].buckets.length;
    const rows: ChartRow[] = [];
    for (let i = 0; i < len; i++) {
      const row: ChartRow = {
        timestamp: new Date(series[0].buckets[i].bucket_start),
      };
      for (const e of series) {
        row[e.edge_name] = e.buckets[i]?.[metric] ?? 0;
      }
      rows.push(row);
    }
    return rows;
  }

  function formatMb(v: number): string {
    return v >= 1024 ? `${(v / 1024).toFixed(1)} GB` : `${Math.round(v)} MB`;
  }
  // Idle proxies run well below 1% CPU; rounding to a whole percent makes
  // every Y-axis tick read "0%" even when the line is clearly rising.
  function formatPct(v: number): string {
    if (v <= 0) return '0%';
    if (v < 0.1) return `${v.toFixed(2)}%`;
    if (v < 10) return `${v.toFixed(1)}%`;
    return `${Math.round(v)}%`;
  }
  // Proxy overhead is small (sub-ms to low-ms) — keep µs resolution so the
  // axis and metric card don't round everything to "0ms".
  function formatLatency(ms: number): string {
    if (ms <= 0) return '0';
    if (ms < 1) return `${Math.round(ms * 1000)}µs`;
    if (ms < 1000) return ms < 10 ? `${ms.toFixed(1)}ms` : `${Math.round(ms)}ms`;
    return `${(ms / 1000).toFixed(1)}s`;
  }

  async function load() {
    loading = true;
    statsError = tenantsError = auditError = '';
    // Edge telemetry counts ALL proxy load — the agent's own traffic stresses
    // the infrastructure too. The cross-tenant overview excludes agent self-
    // traffic server-side (it's a per-tenant axis, not selectable here); the
    // per-tenant platform-events feed applies the header workspace lens, which
    // excludes the Agent workspace by default.
    const [statsRes, edgeRes, tenantsRes, auditRes] = await Promise.all([
      adminApi.GET('/api/v1/admin/global/edge-stats', {
        params: { query: currentPeriodQuery() },
      }),
      adminApi.GET('/api/v1/admin/edge-nodes', { params: { query: { limit: 100 } } }),
      adminApi.GET('/api/v1/admin/global/analytics/overview', {
        params: { query: { ...currentPeriodQuery() } },
      }),
      adminApi.GET('/api/v1/admin/audit', {
        params: { query: { ...currentPeriodQuery(), ...currentWorkspaceQuery(), kind: 'all', limit: 10 } },
      }),
    ]);
    if (statsRes.error) statsError = 'Failed to load edge telemetry.';
    if (tenantsRes.error) tenantsError = 'Failed to load tenant load.';
    if (auditRes.error) auditError = 'Failed to load platform events.';
    edgeStats = statsRes.data ?? null;
    edges = edgeRes.data?.items ?? [];
    edgesLoaded = !edgeRes.error;
    tenants = tenantsRes.data?.tenants ?? [];
    events = auditRes.data?.items ?? [];
    // Appliance disk is pulled live from the host daemon — but ONLY on the VM
    // appliance. Elsewhere the route 404s; gating on the appliance flag keeps a
    // 404 off the page (it would surface as a browser console error) and the
    // Storage tile degrades to "Host service not running" exactly as before.
    if (page.data.user?.appliance) {
      const applianceRes = await adminApi.GET('/api/v1/admin/global/appliance/status');
      platformDisk = applianceRes.data?.disk ?? null;
      platformPressure = applianceRes.data?.disk_pressure ?? null;
    } else {
      platformDisk = null;
      platformPressure = null;
    }
    loading = false;
  }

  usePeriodicLoad(load);

  function openTenant(tenantSlug: string) {
    void goto(thref(slug, `/admin/tenants/${tenantSlug}`));
  }

  // Storage tile derivations. `platformDisk` is null off the VM appliance, or
  // when the host daemon cannot read the disk. The daemon's own reading comes
  // first, so the number agrees with the level that colours it; without one,
  // use is counted as df counts it: used of used + available, the blocks
  // reserved for root in neither.
  const storageUsedPct = $derived.by(() => {
    if (platformPressure && platformPressure.level !== 'unknown') return platformPressure.used_pct;
    if (!platformDisk) return undefined;
    const counted = platformDisk.used_bytes + platformDisk.available_bytes;
    return counted > 0 ? (platformDisk.used_bytes * 100) / counted : undefined;
  });
  const storageValue = $derived(storageUsedPct != null ? `${storageUsedPct.toFixed(0)}%` : '—');
  const storageSubtitle = $derived.by(() => {
    if (!platformDisk) return platformPressure ? 'Disk size unknown' : 'Host service not running';
    return `${formatBytes(platformDisk.used_bytes)} / ${formatBytes(platformDisk.total_bytes)}`;
  });
  const storageSubtitle2 = $derived.by(() => {
    switch (platformPressure?.level) {
      case 'soft': return 'Soft pressure';
      case 'hard': return 'Hard pressure';
      default: return undefined;
    }
  });
  const storageColor = $derived.by(() => {
    if (!platformDisk && !platformPressure) return 'var(--text-secondary)';
    switch (platformPressure?.level) {
      case 'hard': return 'var(--error)';
      case 'soft': return 'var(--warning)';
      default: return 'var(--text-primary)';
    }
  });

  // Memory pressure — used against the reported ceiling, from each edge's latest
  // heartbeat. On Kubernetes that's the per-pod cgroup working-set vs its
  // `memory.max`; on the single-host VM appliance the proxy reports whole-VM
  // used vs total RAM instead, so the tile reflects the appliance, not one
  // container's slice. Surfaces the worst edge: one that reports a limit (a real
  // `%`) outranks one that can't (off-cgroup / unconstrained), where only raw
  // usage is known.
  const memoryPressure = $derived.by(() => {
    const live = edges
      .map((e) => ({ name: e.name, s: e.metadata?.stats }))
      .filter((x) => !!x.s && (x.s.memory_rss_bytes ?? 0) > 0);
    if (live.length === 0) return null;
    const withLimit = live.filter((x) => (x.s?.memory_limit_bytes ?? 0) > 0);
    if (withLimit.length > 0) {
      const w = withLimit.reduce((a, b) =>
        (b.s!.memory_rss_bytes ?? 0) / b.s!.memory_limit_bytes! >
        (a.s!.memory_rss_bytes ?? 0) / a.s!.memory_limit_bytes!
          ? b : a);
      const used = w.s!.memory_rss_bytes ?? 0;
      const limit = w.s!.memory_limit_bytes!;
      return { name: w.name, used, limit, pct: (used / limit) * 100 };
    }
    const w = live.reduce((a, b) => (b.s!.memory_rss_bytes ?? 0) > (a.s!.memory_rss_bytes ?? 0) ? b : a);
    return { name: w.name, used: w.s!.memory_rss_bytes ?? 0, limit: null as number | null, pct: null as number | null };
  });
  const memoryValue = $derived(
    memoryPressure?.pct != null
      ? `${memoryPressure.pct.toFixed(0)}%`
      : memoryPressure
        ? formatBytes(memoryPressure.used)
        : '—',
  );
  const memorySubtitle = $derived.by(() => {
    if (!memoryPressure) return edges.length === 0 ? 'No edges connected' : 'No limit reported';
    if (memoryPressure.limit == null) return `${formatBytes(memoryPressure.used)} · no limit`;
    return `${formatBytes(memoryPressure.used)} / ${formatBytes(memoryPressure.limit)}`;
  });
  const memorySubtitle2 = $derived.by(() => {
    if (memoryPressure?.pct == null) return undefined;
    if (memoryPressure.pct >= 90) return 'Hard pressure';
    if (memoryPressure.pct >= 75) return 'Soft pressure';
    return undefined;
  });
  const memoryColor = $derived.by(() => {
    if (memoryPressure?.pct == null) return 'var(--text-primary)';
    if (memoryPressure.pct >= 90) return 'var(--error)';
    if (memoryPressure.pct >= 75) return 'var(--warning)';
    return 'var(--text-primary)';
  });

  // The memory ceiling across edges (MB) — the cgroup cap on K8s, total VM RAM
  // on the appliance — scales the Memory chart's y-axis so each edge's used line
  // reads as a fraction of its ceiling. Null when no bucket reported a limit
  // (then the chart auto-scales to data).
  const memLimitMb = $derived.by(() => {
    let max = 0;
    for (const e of series) for (const b of e.buckets) if (b.memory_limit_mb) max = Math.max(max, b.memory_limit_mb);
    return max > 0 ? max : null;
  });
</script>

{#snippet chart(
  title: string,
  metric: 'requests' | 'avg_cpu_percent' | 'avg_memory_mb',
  formatY: (v: number) => string,
  yFloor: number | null = null,
)}
  <TimeSeriesChart
    {title}
    {loading}
    rows={chartData(metric)}
    series={chartSeries}
    {formatY}
    hourly={isHourly}
    yFloor={yFloor ?? 0}
  />
{/snippet}

<DashboardScaffold
  title="Platform Overview"
  subtitle="Edge infrastructure — throughput, platform-induced latency, and resource usage"
>
  {#if statsError}
    <div class="mb-6"><Callout severity="error" title={statsError} /></div>
  {/if}

  <!-- Infrastructure metric cards -->
  <MetricGrid class="mb-6">
    <MetricCard
      label="Edge Nodes"
      value={`${connectedEdges}/${edges.length}`}
      subtitle="connected"
      icon="edge"
      valueColor={edgeColor}
      href={thref(slug, '/admin/edge')}
      trendValue={edgesLoaded ? connectedEdges : undefined}
      {loading}
    />
    <MetricCard
      label="Requests"
      value={formatCount(totalRequests)}
      subtitle="served this period"
      icon="requests"
      trendValue={edgeStats ? totalRequests : undefined}
      {loading}
    />
    <MetricCard
      label="Platform Latency"
      value={p95LatencyMs > 0 ? formatLatency(p95LatencyMs) : '—'}
      subtitle="p95 proxy overhead"
      icon="clock"
      trendValue={p95LatencyMs > 0 ? p95LatencyMs : undefined}
      {loading}
    />
    <MetricCard
      label="Errors"
      value={formatCount(totalErrors)}
      subtitle="this period"
      icon="errorCircle"
      valueColor={totalErrors > 0 ? 'var(--error)' : 'var(--text-primary)'}
      trendValue={edgeStats ? totalErrors : undefined}
      {loading}
    />
    <MetricCard
      label="Memory"
      value={memoryValue}
      subtitle={memorySubtitle}
      subtitle2={memorySubtitle2}
      icon="memory"
      valueColor={memoryColor}
      trendValue={memoryPressure?.pct ?? undefined}
      {loading}
    />
    <MetricCard
      label="Storage"
      value={storageValue}
      subtitle={storageSubtitle}
      subtitle2={storageSubtitle2}
      icon="storage"
      valueColor={storageColor}
      trendValue={storageUsedPct}
      {loading}
    />
  </MetricGrid>

  {#if pendingTotal > 0}
    <div class="mb-6">
      <Callout
        severity="warning"
        title={`${formatCount(pendingTotal)} audit record${pendingTotal === 1 ? '' : 's'} buffered on ${pendingByEdge.length} edge${pendingByEdge.length === 1 ? '' : 's'}`}
      >
        <p>
          Edges drain on heartbeat once admin-api is reachable; a non-zero
          backlog usually means a recent reconnect or backpressure.
        </p>
        <ul class="mt-2 flex flex-wrap gap-2">
          {#each pendingByEdge as edge (edge.name)}
            <li
              class="font-mono tabular-nums bg-(--warning-bg) border border-(--warning-border) rounded-md px-2 py-0.5"
            >
              {edge.name} · {formatCount(edge.pending)}
            </li>
          {/each}
        </ul>
      </Callout>
    </div>
  {/if}

  <!-- Per-edge legend — shared across every chart below -->
  {#if chartSeries.length > 0}
    <div class="flex flex-wrap items-center gap-x-4 gap-y-1.5 mb-3">
      {#each chartSeries as s (s.key)}
        <span class="inline-flex items-center gap-1.5 text-xs text-(--text-secondary)">
          <span class="w-2.5 h-2.5 rounded-xs" style="background-color: {s.color}"></span>
          {s.key}
        </span>
      {/each}
    </div>
  {/if}

  <!-- Operational time-series — side by side -->
  <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
    {@render chart('Requests', 'requests', formatCount)}
    <TimeSeriesChart
      title="Platform Latency"
      {loading}
      rows={latencyRows}
      series={LATENCY_SERIES}
      formatY={formatLatency}
      hourly={isHourly}
      legend
    />
    {@render chart('CPU', 'avg_cpu_percent', formatPct)}
    {@render chart('Memory', 'avg_memory_mb', formatMb, memLimitMb)}
  </div>

  <!-- Tenant load + platform events — side by side -->
  <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
    <Panel
      title="Top Tenants"
      subtitle="by request volume"
      flush
      {loading}
      error={tenantsError}
      empty={tenants.length === 0}
      emptyMessage="No tenant traffic in the selected period."
      action="Manage"
      actionHref={thref(slug, '/admin/tenants')}
    >
      <table class="w-full text-sm">
        <thead>
          <tr class="border-b border-(--border)">
            <th class="px-5 py-2.5 text-left text-xs font-medium text-(--text-secondary) uppercase tracking-wider"
              >Tenant</th
            >
            <th class="px-5 py-2.5 text-right text-xs font-medium text-(--text-secondary) uppercase tracking-wider"
              >Requests</th
            >
            <th class="px-5 py-2.5 text-right text-xs font-medium text-(--text-secondary) uppercase tracking-wider"
              >Errors</th
            >
            <th class="px-5 py-2.5 text-right text-xs font-medium text-(--text-secondary) uppercase tracking-wider"
              >Active Users</th
            >
          </tr>
        </thead>
        <tbody>
          {#each tenants.slice(0, 8) as t (t.tenant_id)}
            {@const errRate = t.total_requests > 0 ? (t.error_count / t.total_requests) * 100 : 0}
            <tr
              class="border-b border-(--border) last:border-0 hover:bg-(--bg-elevated) cursor-pointer transition-colors"
              role="button"
              tabindex="0"
              onclick={() => openTenant(t.slug)}
              onkeydown={(e) => {
                if ((e.key === 'Enter' || e.key === ' ') && e.target === e.currentTarget) {
                  e.preventDefault();
                  openTenant(t.slug);
                }
              }}
            >
              <td class="px-5 py-3">
                <span class="font-medium text-(--text-primary)">{t.tenant_name}</span>
                <span class="ml-2 text-xs font-mono text-(--text-secondary)">{t.slug}</span>
              </td>
              <td class="px-5 py-3 text-right font-mono text-(--text-primary)"
                >{formatCount(t.total_requests)}</td
              >
              <td
                class="px-5 py-3 text-right font-mono {errRate > 5
                  ? 'text-(--error)'
                  : 'text-(--text-secondary)'}"
              >
                {formatCount(t.error_count)}{#if errRate > 0}
                  <span class="text-xs">({errRate.toFixed(1)}%)</span>{/if}
              </td>
              <td class="px-5 py-3 text-right font-mono text-(--text-secondary)"
                >{t.active_users}</td
              >
            </tr>
          {/each}
        </tbody>
      </table>
    </Panel>

    <Panel
      title="Response Cache"
      subtitle="per edge, from its latest heartbeat"
      flush
      {loading}
      empty={cacheByEdge.length === 0}
      emptyMessage="No edge is reporting cached responses."
    >
      <table class="w-full text-sm">
        <thead>
          <tr class="border-b border-(--border)">
            <th class="px-5 py-2.5 text-left text-xs font-medium text-(--text-secondary) uppercase tracking-wider"
              >Edge</th
            >
            <th class="px-5 py-2.5 text-right text-xs font-medium text-(--text-secondary) uppercase tracking-wider"
              >Entries</th
            >
            <th class="px-5 py-2.5 text-right text-xs font-medium text-(--text-secondary) uppercase tracking-wider"
              >Used</th
            >
            <th class="px-5 py-2.5 text-right text-xs font-medium text-(--text-secondary) uppercase tracking-wider"
              >Evicted since start</th
            >
          </tr>
        </thead>
        <tbody>
          {#each cacheByEdge as e (e.name)}
            <tr class="border-b border-(--border) last:border-0">
              <td class="px-5 py-2.5 font-mono text-(--text-primary)">
                {e.name}
                {#if e.leakedVectors > 0}
                  <span
                    class="ml-2 text-xs font-mono"
                    style="color: var(--warning);"
                    title="Indexed prompt vectors outnumber cached entries — vectors are outliving the answers they point at."
                  >{formatCount(e.leakedVectors)} orphan vectors</span>
                {/if}
              </td>
              <td class="px-5 py-2.5 text-right font-mono tabular-nums text-(--text-secondary)">
                {formatCount(e.entries)}
              </td>
              <td class="px-5 py-2.5 text-right font-mono tabular-nums text-(--text-secondary)">
                {formatBytes(e.bytes)}{#if e.pct != null}<span
                    style="color: {e.pct >= 90 ? 'var(--error)' : e.pct >= 75 ? 'var(--warning)' : 'var(--text-tertiary)'}"
                  >
                    · {e.pct.toFixed(0)}%</span
                  >{/if}
              </td>
              <td
                class="px-5 py-2.5 text-right font-mono tabular-nums text-(--text-secondary)"
                title="Entries given up to make room, since this replica started. The live signal for a cache that is too small is the Used column — this is the lifetime total behind it."
              >
                {formatCount(e.evictions)}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </Panel>

    <Panel
      title="Recent Platform Events"
      flush
      {loading}
      error={auditError}
      empty={events.length === 0}
      emptyMessage="No pre-auth failures or platform events in the selected period."
      action="View all"
      actionHref={thref(slug, '/audit')}
    >
      {#each events as row (row.request_id)}
        <AuditRowCard
          {row}
          expanded={false}
          onToggle={() => goto(thref(slug, auditHref({ request_id: row.request_id })))}
          onFilterUser={(email) => goto(thref(slug, auditHref({ search: email, ...linkScope })))}
        />
      {/each}
    </Panel>
  </div>
</DashboardScaffold>
