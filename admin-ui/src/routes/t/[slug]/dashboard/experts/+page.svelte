<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import { sessionsHref } from '#lib/deeplinks.js';
  import type { ExpertDashboardResponse, SessionSummary, AppInfo, CrossSessionIssue } from '#lib/api-types.js';
  import { extractError, fetchAllPages } from '#lib/api-helpers.js';
  import { consoleScope, dashboardScopeParams, currentPeriodQuery } from '#lib/scope.svelte.js';
  import { usePeriodicLoad } from '#lib/hooks.svelte.js';
  import { formatCount, appName, formatTimeAgo } from '#lib/formatters.js';
  import DashboardScaffold from '#lib/components/dashboard/DashboardScaffold.svelte';
  import MetricCard from '#lib/components/dashboard/MetricCard.svelte';
  import MetricGrid from '#lib/components/dashboard/MetricGrid.svelte';
  import Panel from '#lib/components/dashboard/Panel.svelte';
  import SessionRow from '#lib/components/SessionRow.svelte';
  import SessionLinkList from '#lib/components/SessionLinkList.svelte';

  let dashboard = $state<ExpertDashboardResponse | null>(null);
  let flaggedSessions = $state<SessionSummary[]>([]);
  let crossIssues = $state<CrossSessionIssue[]>([]);
  // A failed fetch empties `crossIssues`, which is no reading for the trend chip.
  let crossIssuesLoaded = $state(false);
  let crossIssuesHasMore = $state(false);
  let appRegistry = $state<Map<string, AppInfo>>(new Map());
  let loading = $state(true);
  let dashboardError = $state('');

  // Expert data is tenant-wide (not workspace-scoped), so alert deep-links carry
  // only the period — passing `'all'` yields period-only scope — to match the
  // window the alert counts are computed over.
  const linkScope = $derived(dashboardScopeParams(consoleScope.period, 'all'));

  const metricCards = $derived(
    dashboard
      ? [
          {
            label: 'Major Alerts',
            value: formatCount(dashboard.total_alerts?.major ?? 0),
            subtitle: 'flagged sessions',
            icon: 'alert' as const,
            iconTone: 'error' as const,
            valueColor:
              (dashboard.total_alerts?.major ?? 0) > 0
                ? 'var(--error)'
                : 'var(--text-primary)',
            trendValue: dashboard.total_alerts?.major ?? 0,
            href: sessionsHref({ alert_level: 'major', ...linkScope }),
          },
          {
            label: 'Minor Alerts',
            value: formatCount(dashboard.total_alerts?.minor ?? 0),
            subtitle: 'flagged sessions',
            icon: 'info' as const,
            iconTone: 'warning' as const,
            valueColor:
              (dashboard.total_alerts?.minor ?? 0) > 0
                ? 'var(--warning)'
                : 'var(--text-primary)',
            trendValue: dashboard.total_alerts?.minor ?? 0,
            href: sessionsHref({ alert_level: 'minor', ...linkScope }),
          },
          {
            label: 'Analyzed',
            value: formatCount(dashboard.total_sessions_analyzed ?? 0),
            subtitle: `by ${dashboard.active_experts ?? 0} active expert${
              (dashboard.active_experts ?? 0) !== 1 ? 's' : ''
            }`,
            icon: 'clipboardCheck' as const,
            trendValue: dashboard.total_sessions_analyzed ?? 0,
          },
          {
            label: 'Suggestions',
            value: formatCount(dashboard.pending_suggestions ?? 0),
            subtitle: 'proposed transforms to review',
            icon: 'lightbulb' as const,
            trendValue: dashboard.pending_suggestions ?? 0,
          },
          {
            label: 'Cross-session issues',
            value: crossIssuesHasMore ? `${formatCount(crossIssues.length)}+` : formatCount(crossIssues.length),
            subtitle: 'spanning multiple sessions',
            icon: 'gitBranch' as const,
            iconTone: (crossIssues.length > 0 ? 'warning' : 'info') as 'warning' | 'info',
            valueColor: crossIssues.length > 0 ? 'var(--warning)' : 'var(--text-primary)',
            trendValue: crossIssuesLoaded ? crossIssues.length : undefined,
            href: '#cross-session-panel',
          },
        ]
      : [],
  );

  async function loadData() {
    loading = true;
    try {
      const period = currentPeriodQuery();
      const [dashboardRes, sessionsRes, issuesRes, appsList] = await Promise.all([
        adminApi.GET('/api/v1/admin/experts/dashboard', {
          params: { query: period },
        }),
        adminApi.GET('/api/v1/admin/sessions', {
          // The same window as the counts above: an absolute period is used
          // as is, a rolling one as its lookback from now.
          params: { query: { limit: 15, sort: 'alerts', ...(period.start
            ? { start: period.start, end: period.end }
            : { start: new Date(Date.now() - (period.days ?? 1) * 86400000).toISOString() }) } },
        }),
        adminApi.GET('/api/v1/admin/experts/cross-session-issues', {
          params: { query: { ...period, limit: 100 } },
        }),
        fetchAllPages<AppInfo>((offset, limit) =>
          adminApi.GET('/api/v1/admin/analytics/apps', { params: { query: { offset, limit } } }),
        ),
      ]);
      if (dashboardRes.data) dashboard = dashboardRes.data;
      dashboardError = dashboardRes.error ? extractError(dashboardRes.error) : '';
      flaggedSessions = (sessionsRes.data?.items ?? []).filter(
        (s) => s.alert_level === 'minor' || s.alert_level === 'major',
      );
      crossIssues = issuesRes.data?.items ?? [];
      crossIssuesLoaded = !issuesRes.error;
      crossIssuesHasMore = issuesRes.data?.has_more ?? false;
      appRegistry = new Map(appsList.map((a) => [a.id, a]));
    } finally {
      loading = false;
    }
  }

  usePeriodicLoad(loadData);
</script>

<DashboardScaffold title="Experts" subtitle="Agent alerts, sessions analyzed, pending suggestions">
  <MetricGrid class="mb-8">
    <!-- Placeholders until the first load only: a refresh keeps the real cards
         mounted, so they neither blink nor lose their trend baseline. -->
    {#if !dashboard && !dashboardError}
      {#each Array(5) as _, i (i)}
        <MetricCard loading label="" value="" icon="info" />
      {/each}
    {:else}
      {#each metricCards as card (card.label)}
        <MetricCard {...card} />
      {/each}
    {/if}
  </MetricGrid>
  {#if dashboardError}
    <p class="text-xs text-(--error) -mt-6 mb-6">{dashboardError}</p>
  {/if}

  <div id="cross-session-panel" class="scroll-mt-20 mb-6">
    <Panel
      flush
      title="Cross-session issues"
      subtitle="Findings that span several sessions"
      {loading}
      empty={!loading && crossIssues.length === 0}
    >
      {#snippet emptySlot()}
        <div class="px-6 py-12 text-center">
          <p class="text-sm text-(--text-secondary)">No cross-session issues in this period.</p>
          <p class="text-xs text-(--text-secondary) mt-1">
            Cluster experts raise these when a pattern spans multiple sessions.
          </p>
        </div>
      {/snippet}
      <div class="divide-y divide-(--border)">
        {#each crossIssues as issue (issue.id)}
          <div class="px-6 py-3.5 flex items-start gap-3">
            <span
              class="shrink-0 mt-0.5 px-1.5 py-0.5 text-[10px] font-semibold rounded uppercase
                {issue.level === 'major'
                  ? 'bg-(--error-bg) text-(--error)'
                  : issue.level === 'minor'
                    ? 'bg-(--warning-bg) text-(--warning)'
                    : 'bg-(--tag-neutral-bg) text-(--tag-neutral-text)'}"
            >{issue.axis ?? issue.level ?? 'issue'}</span>
            <div class="flex-1 min-w-0">
              <p class="text-sm text-(--text-primary)">{issue.note}</p>
              <div class="mt-1.5">
                <SessionLinkList sessionIds={issue.source_session_ids} label="Sessions:" />
              </div>
            </div>
            <span class="shrink-0 text-xs text-(--text-secondary)">{formatTimeAgo(issue.created_at)}</span>
          </div>
        {/each}
      </div>
    </Panel>
  </div>

  <Panel
    flush
    title="Flagged Sessions"
    action="View all"
    actionHref="/sessions"
    {loading}
    empty={!loading && flaggedSessions.length === 0}
  >
    {#snippet skeleton()}
      <div class="divide-y divide-(--border)">
        {#each Array(5) as _, i (i)}
          <div class="px-6 py-3.5 flex items-center gap-4">
            <div class="w-14 h-5 rounded-sm bg-(--bg-primary) animate-pulse"></div>
            <div class="flex-1">
              <div class="w-48 h-3.5 bg-(--bg-primary) rounded-sm animate-pulse mb-2"></div>
              <div class="w-32 h-3 bg-(--bg-primary) rounded-sm animate-pulse"></div>
            </div>
          </div>
        {/each}
      </div>
    {/snippet}
    {#snippet emptySlot()}
      <div class="px-6 py-12 text-center">
        <p class="text-sm text-(--text-secondary)">No flagged sessions in this period.</p>
        <p class="text-xs text-(--text-secondary) mt-1">
          Experts will flag sessions when configured rules trigger.
        </p>
      </div>
    {/snippet}
    <div class="divide-y divide-(--border)">
      {#each flaggedSessions as session (session.session_id)}
        <SessionRow {session} appName={(id) => appName(appRegistry, id)} />
      {/each}
    </div>
  </Panel>
</DashboardScaffold>
