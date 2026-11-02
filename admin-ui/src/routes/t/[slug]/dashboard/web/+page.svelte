<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import { auditHref } from '#lib/deeplinks.js';
  import type { components } from '#lib/generated/api-types.js';
  import { formatCount, formatDuration, formatBytes } from '#lib/formatters.js';
  import { consoleScope, currentWorkspaceQuery, dashboardScopeParams, currentPeriodQuery } from '#lib/scope.svelte.js';
  import { latencyCard, reliabilityCard } from '#lib/cardPresets.js';
  import { usePeriodicLoad } from '#lib/hooks.svelte.js';
  import { operationColor } from '#lib/colormaps/web.js';
  import { tagMarkColor } from '#lib/components/TagBadge.svelte';

  import DashboardScaffold from '#lib/components/dashboard/DashboardScaffold.svelte';
  import MetricCard from '#lib/components/dashboard/MetricCard.svelte';
  import MetricGrid from '#lib/components/dashboard/MetricGrid.svelte';
  import BreakdownPanel from '#lib/components/dashboard/BreakdownPanel.svelte';
  import EmptyState from '#lib/components/EmptyState.svelte';

  type Summary = components['schemas']['WebDashboardSummary'];
  type Panel_ = components['schemas']['WebDashboardPanel'];

  // Dashboards do not narrow themselves — each row is its own deep-link
  // into `/audit?kind=web&…` for follow-up. No filter bar; the only
  // controls that narrow this page are the global period and workspace
  // selectors (both shared across every dashboard).

  // ── Loaded state ────────────────────────────────────────────────────────
  let summary = $state<Summary | null>(null);
  let topHosts = $state<Panel_ | null>(null);
  let topQueries = $state<Panel_ | null>(null);
  let topUsers = $state<Panel_ | null>(null);
  let loading = $state(true);
  let error = $state('');

  // Deep-links carry the dashboard's live scope (header workspace pin + period)
  // so the audit list opens on exactly what this dashboard shows.
  const linkScope = $derived(dashboardScopeParams(consoleScope.period, consoleScope.workspace));

  function baseQuery() {
    return {
      ...currentPeriodQuery(), ...currentWorkspaceQuery(),
      limit: 10,
    };
  }

  async function loadAll() {
    loading = true;
    error = '';
    const q = baseQuery();
    try {
      const [s, hosts, queries, users] = await Promise.all([
        adminApi.GET('/api/v1/admin/web/dashboard/summary', { params: { query: q } }),
        adminApi.GET('/api/v1/admin/web/dashboard/by-host', { params: { query: q } }),
        adminApi.GET('/api/v1/admin/web/dashboard/by-query', { params: { query: q } }),
        adminApi.GET('/api/v1/admin/web/dashboard/by-user', { params: { query: q } }),
      ]);
      summary = s.data ?? null;
      topHosts = hosts.data ?? null;
      topQueries = queries.data ?? null;
      topUsers = users.data ?? null;
    } catch (e: unknown) {
      error = e instanceof Error ? e.message : 'failed to load web dashboard';
    } finally {
      loading = false;
    }
  }

  usePeriodicLoad(loadAll);

  // ── Card derivations ────────────────────────────────────────────────────
  const metricCards = $derived([
    {
      label: 'Requests',
      period: `${consoleScope.periodDays}d`,
      value: summary ? formatCount(summary.requests) : '--',
      subtitle: summary
        ? `${formatCount(summary.searches)} search · ${formatCount(summary.fetches)} fetch`
        : undefined,
      subtitle2: summary && summary.unique_users > 0
        ? `${formatCount(summary.unique_users)} ${summary.unique_users === 1 ? 'user' : 'users'}`
        : undefined,
      icon: 'requests' as const,
      trendValue: summary?.requests,
    },
    latencyCard({
      p50_ms: summary?.p50_latency_ms,
      p95_ms: summary?.p95_latency_ms,
      p99_ms: summary?.p99_latency_ms,
      periodDays: consoleScope.periodDays,
    }),
    reliabilityCard({
      totalRequests: summary?.requests ?? 0,
      errorCount: summary?.errors ?? 0,
      slowCount: summary?.slow_count ?? 0,
      slowLabel: 'slow (>10s)',
      periodDays: consoleScope.periodDays,
    }),
    {
      // The value slot holds the figure; what it counts lives in the label.
      label: 'Blocked',
      period: `${consoleScope.periodDays}d`,
      value: summary ? formatCount(summary.blocked) : '--',
      subtitle: summary
        ? `${formatCount(summary.ssrf_blocks)} SSRF · ${formatCount(summary.domain_filter_denies)} domain`
        : undefined,
      subtitle2: summary
        ? `${formatCount(summary.unique_hosts)} unique hosts`
        : undefined,
      icon: 'filtered' as const,
      valueColor: summary && summary.blocked > 0 ? 'var(--warning)' : 'var(--text-primary)',
      trendValue: summary?.blocked,
    },
  ]);

</script>

<DashboardScaffold
  title="Web"
  subtitle="Search + fetch activity across MCP, substitution, and admin tests"
>
  {#if error}
    <div class="bg-(--error-bg) border border-(--error-border) rounded-lg p-3 mb-4 text-sm text-(--error-text)">
      {error}
    </div>
  {/if}

  <!-- ── 4 KPI tiles — the "model card on top" strip ─────────────────────── -->
  <MetricGrid class="mb-6">
    {#each metricCards as card}
      <MetricCard {...card} loading={loading && summary == null} />
    {/each}
  </MetricGrid>

  <!-- ── Top hosts (fetch) · Top queries (search) ────────────────────────── -->
  <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
    <BreakdownPanel
      title="Top hosts"
      subtitle="Fetch destinations"
      loading={loading && topHosts == null}
      skeletonCount={6}
      items={topHosts?.items ?? []}
      getValue={(h) => h.requests}
      getRow={(h, max) => ({
        label: h.key || '(blank)',
        value: formatCount(h.requests),
        sub: h.bytes_out != null ? formatBytes(h.bytes_out) : undefined,
        percent: (h.requests / max) * 100,
        mono: true,
        title: h.p95_latency_ms != null ? `P95 ${formatDuration(h.p95_latency_ms)}` : undefined,
        barColor: tagMarkColor(operationColor('fetch')),
        href: h.key ? auditHref({ kind: 'web', operation: 'fetch', search: h.key, ...linkScope }) : undefined,
      })}
    >
      {#snippet emptySlot()}
        <EmptyState
          title="No fetches in this window"
          body="Nothing called the fetch tool during the selected period."
        />
      {/snippet}
    </BreakdownPanel>

    <BreakdownPanel
      title="Top queries"
      subtitle="Search inputs"
      loading={loading && topQueries == null}
      skeletonCount={6}
      items={topQueries?.items ?? []}
      getValue={(q) => q.requests}
      getRow={(q, max) => ({
        label: `"${q.key}"`,
        value: formatCount(q.requests),
        sub: q.avg_result_count != null ? `${q.avg_result_count.toFixed(0)} avg hits` : undefined,
        percent: (q.requests / max) * 100,
        title: q.p95_latency_ms != null ? `P95 ${formatDuration(q.p95_latency_ms)}` : undefined,
        barColor: tagMarkColor(operationColor('search')),
        href: q.key ? auditHref({ kind: 'web', operation: 'search', search: q.key, ...linkScope }) : undefined,
      })}
    >
      {#snippet emptySlot()}
        <EmptyState
          title="No searches in this window"
          body="Nothing called the search tool during the selected period."
        />
      {/snippet}
    </BreakdownPanel>
  </div>

  <!-- ── Top users ──────────────────────────────────────────────────────── -->
  <BreakdownPanel
    title="Top users"
    subtitle="By web request volume"
    loading={loading && topUsers == null}
    skeletonCount={6}
    items={topUsers?.items ?? []}
    getValue={(u) => u.requests}
    getRow={(u, max) => ({
      label: u.key,
      value: formatCount(u.requests),
      sub: u.p95_latency_ms != null ? `P95 ${formatDuration(u.p95_latency_ms)}` : undefined,
      percent: (u.requests / max) * 100,
      href: u.user_email
        ? auditHref({ kind: 'web', user_email: u.user_email, ...linkScope })
        : u.user_id
          ? auditHref({ kind: 'web', user_id: u.user_id, ...linkScope })
          : undefined,
      title: "View this user's web audit",
    })}
  >
    {#snippet emptySlot()}
      <EmptyState
        title="No user-attributed web activity"
        body="No web calls in this window carried a resolved user."
      />
    {/snippet}
  </BreakdownPanel>
</DashboardScaffold>
