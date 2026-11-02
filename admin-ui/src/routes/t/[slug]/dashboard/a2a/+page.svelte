<script lang="ts">
  // A2A dashboard — the agent-to-agent sibling of the LLM / MCP / Web pages, on
  // the same scaffold and the same shared panels. What differs is what is worth
  // asking: an agent call has no tool and no tokens, so the pivots are the AGENT
  // it addressed, the operation, and how the remote task ended.
  import { adminApi } from '#lib/api-client.js';
  import { auditHref } from '#lib/deeplinks.js';
  import type { components } from '#lib/generated/api-types.js';
  import { formatCount, formatDuration, formatTaskState } from '#lib/formatters.js';
  import { consoleScope, currentWorkspaceQuery, dashboardScopeParams, currentPeriodQuery } from '#lib/scope.svelte.js';
  import { latencyCard, reliabilityCard } from '#lib/cardPresets.js';
  import { usePeriodicLoad } from '#lib/hooks.svelte.js';
  import { auditKindColor } from '#lib/colormaps/audit_kinds.js';
  import { tagMarkColor } from '#lib/components/TagBadge.svelte';

  import DashboardScaffold from '#lib/components/dashboard/DashboardScaffold.svelte';
  import MetricCard from '#lib/components/dashboard/MetricCard.svelte';
  import MetricGrid from '#lib/components/dashboard/MetricGrid.svelte';
  import BreakdownPanel from '#lib/components/dashboard/BreakdownPanel.svelte';
  import EmptyState from '#lib/components/EmptyState.svelte';

  type Summary = components['schemas']['A2aDashboardSummary'];
  type Panel_ = components['schemas']['A2aDashboardPanel'];

  // Dashboards do not narrow themselves — each row deep-links into
  // `/audit?kind=a2a&…`. The only controls that narrow this page are the global
  // period and workspace selectors.
  let summary = $state<Summary | null>(null);
  let byAgent = $state<Panel_ | null>(null);
  let byMethod = $state<Panel_ | null>(null);
  let byTaskState = $state<Panel_ | null>(null);
  let byUser = $state<Panel_ | null>(null);
  let loading = $state(true);
  let error = $state('');

  const BAR = tagMarkColor(auditKindColor.a2a);

  // Deep-links carry the dashboard's live scope (header workspace pin + period)
  // so the audit list opens on exactly what this dashboard shows.
  const linkScope = $derived(dashboardScopeParams(consoleScope.period, consoleScope.workspace));

  function baseQuery() {
    return { ...currentPeriodQuery(), ...currentWorkspaceQuery(), limit: 10 };
  }

  async function loadAll() {
    loading = true;
    error = '';
    const q = baseQuery();
    try {
      const [s, agents, methods, states, users] = await Promise.all([
        adminApi.GET('/api/v1/admin/a2a/dashboard/summary', { params: { query: q } }),
        adminApi.GET('/api/v1/admin/a2a/dashboard/by-agent', { params: { query: q } }),
        adminApi.GET('/api/v1/admin/a2a/dashboard/by-method', { params: { query: q } }),
        adminApi.GET('/api/v1/admin/a2a/dashboard/by-task-state', { params: { query: q } }),
        adminApi.GET('/api/v1/admin/a2a/dashboard/by-user', { params: { query: q } }),
      ]);
      summary = s.data ?? null;
      byAgent = agents.data ?? null;
      byMethod = methods.data ?? null;
      byTaskState = states.data ?? null;
      byUser = users.data ?? null;
    } catch (e: unknown) {
      error = e instanceof Error ? e.message : 'failed to load A2A dashboard';
    } finally {
      loading = false;
    }
  }

  usePeriodicLoad(loadAll);

  const metricCards = $derived([
    {
      label: 'Agent calls',
      period: `${consoleScope.periodDays}d`,
      value: summary ? formatCount(summary.calls) : '--',
      subtitle: summary
        ? `${formatCount(summary.agents)} ${summary.agents === 1 ? 'agent' : 'agents'} · ${formatCount(summary.streamed)} streamed`
        : undefined,
      subtitle2: summary && summary.unique_users > 0
        ? `${formatCount(summary.unique_users)} ${summary.unique_users === 1 ? 'user' : 'users'}`
        : undefined,
      icon: 'requests' as const,
      trendValue: summary?.calls,
    },
    {
      label: 'Tasks · Conversations',
      period: `${consoleScope.periodDays}d`,
      value: summary ? formatCount(summary.tasks) : '--',
      subtitle: summary
        ? `${formatCount(summary.contexts)} ${summary.contexts === 1 ? 'conversation' : 'conversations'}`
        : undefined,
      subtitle2: 'Remote units of work',
      icon: 'bag' as const,
      trendValue: summary?.tasks,
    },
    latencyCard({
      p50_ms: summary?.p50_latency_ms,
      p95_ms: summary?.p95_latency_ms,
      p99_ms: summary?.p99_latency_ms,
      periodDays: consoleScope.periodDays,
    }),
    reliabilityCard({
      totalRequests: summary?.calls ?? 0,
      errorCount: summary?.errors ?? 0,
      slowCount: summary?.blocked ?? 0,
      slowLabel: 'blocked by policy',
      periodDays: consoleScope.periodDays,
    }),
    {
      // Screening results are the reason this surface exists — a peer agent's
      // reply lands in your own model's context. Keep them at eye level as a
      // top card (calm at zero, warning when present) and link straight to the
      // calls behind the count. Counts findings AND replies the gateway could
      // not screen in full — unscreened content reaches the model just the same,
      // so the card must not read as clean when coverage was incomplete.
      // MetricCard scopes the href to the active tenant plane, so pass the
      // tenant-relative auditHref as-is.
      label: 'Guardrail',
      period: `${consoleScope.periodDays}d`,
      value: summary ? formatCount(summary.guardrail_flagged) : '--',
      subtitle: summary
        ? summary.guardrail_flagged > 0
          ? `${summary.guardrail_flagged === 1 ? 'call needs' : 'calls need'} a look`
          : // Neutral at zero: a tenant whose guardrail is off has no rows to
            // count either, so this must not read as "screened, and clean".
            'Nothing to review'
        : undefined,
      icon: 'shield' as const,
      valueColor:
        summary && summary.guardrail_flagged > 0 ? 'var(--warning)' : 'var(--text-primary)',
      href: auditHref({ kind: 'a2a', has_guardrail: 'true', ...linkScope }),
      trendValue: summary?.guardrail_flagged,
    },
  ]);
</script>

<DashboardScaffold
  title="A2A"
  subtitle="Agent-to-agent calls: which agents, which operations, how their tasks ended"
>
  {#if error}
    <div class="bg-(--error-bg) border border-(--error-border) rounded-lg p-3 mb-4 text-sm text-(--error-text)">
      {error}
    </div>
  {/if}

  <MetricGrid class="mb-6">
    {#each metricCards as card}
      <MetricCard {...card} loading={loading && summary == null} />
    {/each}
  </MetricGrid>

  <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
    <BreakdownPanel
      title="Top agents"
      subtitle="By call volume"
      loading={loading && byAgent == null}
      skeletonCount={6}
      items={byAgent?.items ?? []}
      getValue={(a) => a.call_count}
      getRow={(a, max) => ({
        label: a.key || '(unregistered)',
        value: formatCount(a.call_count),
        sub: a.error_count > 0 ? `${formatCount(a.error_count)} errors` : undefined,
        percent: (a.call_count / max) * 100,
        mono: true,
        title: a.p95_latency_ms != null ? `P95 ${formatDuration(a.p95_latency_ms)}` : undefined,
        barColor: BAR,
        href: a.key ? auditHref({ kind: 'a2a', agent_slug: a.key, ...linkScope }) : undefined,
      })}
    >
      {#snippet emptySlot()}
        <EmptyState
          title="No agent calls in this window"
          body="Nothing reached a registered A2A agent during the selected period."
        />
      {/snippet}
    </BreakdownPanel>

    <BreakdownPanel
      title="Operations"
      subtitle="A2A methods"
      loading={loading && byMethod == null}
      skeletonCount={6}
      items={byMethod?.items ?? []}
      getValue={(m) => m.call_count}
      getRow={(m, max) => ({
        label: m.key,
        value: formatCount(m.call_count),
        sub: m.error_count > 0 ? `${formatCount(m.error_count)} errors` : undefined,
        percent: (m.call_count / max) * 100,
        mono: true,
        title: m.p95_latency_ms != null ? `P95 ${formatDuration(m.p95_latency_ms)}` : undefined,
        barColor: BAR,
        href: auditHref({ kind: 'a2a', methods: m.key, ...linkScope }),
      })}
    >
      {#snippet emptySlot()}
        <EmptyState
          title="No operations in this window"
          body="No A2A method was invoked during the selected period."
        />
      {/snippet}
    </BreakdownPanel>
  </div>

  <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
    <BreakdownPanel
      title="Task outcomes"
      subtitle="How remote work ended"
      loading={loading && byTaskState == null}
      skeletonCount={5}
      items={byTaskState?.items ?? []}
      getValue={(t) => t.call_count}
      getRow={(t, max) => ({
        label: formatTaskState(t.key),
        value: formatCount(t.call_count),
        percent: (t.call_count / max) * 100,
        barColor: BAR,
        href: auditHref({ kind: 'a2a', task_state: t.key, ...linkScope }),
      })}
    >
      {#snippet emptySlot()}
        <EmptyState
          title="No task outcomes yet"
          body="Calls in this window created no remote task, or none reported a state."
        />
      {/snippet}
    </BreakdownPanel>

    <BreakdownPanel
      title="Top users"
      subtitle="By agent-call volume"
      loading={loading && byUser == null}
      skeletonCount={5}
      items={byUser?.items ?? []}
      getValue={(u) => u.call_count}
      getRow={(u, max) => ({
        label: u.key,
        value: formatCount(u.call_count),
        sub: u.p95_latency_ms != null ? `P95 ${formatDuration(u.p95_latency_ms)}` : undefined,
        percent: (u.call_count / max) * 100,
        barColor: BAR,
        // The row shows a display name; the link filters on the id behind it.
        href: u.filter_id ? auditHref({ kind: 'a2a', user_id: u.filter_id, ...linkScope }) : undefined,
        title: "View this user's A2A audit",
      })}
    >
      {#snippet emptySlot()}
        <EmptyState
          title="No user-attributed agent calls"
          body="No A2A call in this window carried a resolved user."
        />
      {/snippet}
    </BreakdownPanel>
  </div>
</DashboardScaffold>
