<script lang="ts">
  import { toast } from '#lib/toast.svelte.js';
  import { extractError } from '#lib/api-helpers.js';
  import { adminApi } from '#lib/api-client.js';
  import { auditHref, sessionsHref } from '#lib/deeplinks.js';
  import { fetchAllPages } from '#lib/api-helpers.js';
  import type {
    AppInfo,
    TimeseriesBucket,
    ErrorAnalytics,
    BreakdownEntry,
    UsageSummary,
  } from '#lib/api-types.js';
  import type { components } from '#lib/generated/api-types.js';
  import {
    formatDuration,
    formatTokens,
    formatCost,
    formatSpend,
    formatSpendList,
    formatCount,
    appName,
    formatErrorCategory,
    errorCategoryColor,
  } from '#lib/formatters.js';
  import { spendUnitSummary } from '#lib/spend.js';
  import * as m from '#lib/paraglide/messages.js';
  import { consoleScope, currentWorkspaceQuery, dashboardScopeParams, currentPeriodQuery } from '#lib/scope.svelte.js';
  import { accountingCurrency } from '#lib/currency.svelte.js';
  import { latencyCard, reliabilityCard } from '#lib/cardPresets.js';
  import { usePeriodicLoad } from '#lib/hooks.svelte.js';
  import TimeSeriesChart, { type ChartRow, type ChartSeries } from '#lib/components/charts/TimeSeriesChart.svelte';
  import DashboardScaffold from '#lib/components/dashboard/DashboardScaffold.svelte';
  import MetricCard from '#lib/components/dashboard/MetricCard.svelte';
  import MetricGrid from '#lib/components/dashboard/MetricGrid.svelte';
  import BreakdownPanel from '#lib/components/dashboard/BreakdownPanel.svelte';
  import PeriodBadge from '#lib/components/dashboard/PeriodBadge.svelte';
  import type { RowMeta } from '#lib/components/dashboard/BreakdownRow.svelte';
  import { tagMarkColor } from '#lib/components/TagBadge.svelte';

  // Deep-links carry the dashboard's live scope (header workspace pin + period)
  // so the audit/sessions list opens on exactly what this dashboard shows.
  const linkScope = $derived(dashboardScopeParams(consoleScope.period, consoleScope.workspace));

  let stats = $state<UsageSummary>({
    total_requests: 0,
    total_sessions: 0,
    total_prompt_tokens: 0,
    total_completion_tokens: 0,
    total_cache_creation_tokens: 0,
    total_cache_read_tokens: 0,
    total_reasoning_tokens: 0,
    // The backend never sends an empty list, but this placeholder renders
    // before the first load resolves.
    spend: [],
    avg_latency_ms: 0,
    p50_latency_ms: 0,
    p95_latency_ms: 0,
    p99_latency_ms: 0,
    avg_ttft_ms: 0,
    p50_ttft_ms: 0,
    p95_ttft_ms: 0,
    error_count: 0,
    high_latency_count: 0,
    streaming_requests: 0,
    response_fastpath: 0,
    response_buffered: 0,
    response_tool_blocks: 0,
    total_embedding_requests: 0,
    total_audio_requests: 0,
    total_image_requests: 0,
    total_video_requests: 0,
  });
  let modelBreakdown = $state<BreakdownEntry[]>([]);
  let userBreakdown = $state<BreakdownEntry[]>([]);
  let appBreakdown = $state<BreakdownEntry[]>([]);
  let serverBreakdown = $state<BreakdownEntry[]>([]);
  let appRegistry = $state<Map<string, AppInfo>>(new Map());
  let timeseriesBuckets = $state<TimeseriesBucket[]>([]);
  let timeseriesInterval = $state('daily');
  let errorAnalytics = $state<ErrorAnalytics | null>(null);
  let cache = $state<components['schemas']['CacheAnalyticsResponse'] | null>(null);
  let loading = $state(true);

  // Gated on cached traffic in the SELECTED window, not on a preset existing:
  // every figure below is period- and workspace-scoped, so a panel shown for a
  // bound-but-idle preset could only ever render zeroes.
  const cacheActive = $derived((cache?.lookups ?? 0) > 0 || (cache?.bypassed ?? 0) > 0);

  // The window's spend, when it was all booked in one currency. Absent means
  // the window straddles a change of the accounting currency, and its
  // components are stated apart rather than added.
  const soleSpend = $derived(stats.spend.length === 1 ? stats.spend[0] : undefined);
  // Under the cost figure: the per-unit decomposition when there is one figure
  // to decompose, otherwise which denominations the window actually holds.
  const spendSubtitle = $derived(
    soleSpend
      ? (spendUnitSummary(soleSpend) ?? m.spend_reported_in({ currency: soleSpend.currency }))
      : stats.spend.length > 1
        ? `${m.spend_mixed_currency()}: ${stats.spend.map((s) => formatSpend(s)).join(' · ')}`
        : m.spend_reported_in({ currency: accountingCurrency() }),
  );

  // No "Activity" card here — total requests / sessions live on the Overview.
  // This page keeps the LLM-shaped metrics that the Overview deliberately drops.
  const metricCards = $derived([
    {
      label: 'Tokens',
      period: `${consoleScope.periodDays}d`,
      value: formatTokens(stats.total_prompt_tokens + stats.total_completion_tokens),
      subtitle: `${formatTokens(stats.total_prompt_tokens)} in / ${formatTokens(stats.total_completion_tokens)} out`,
      subtitle2:
        [
          stats.total_cache_read_tokens > 0
            ? `${formatTokens(stats.total_cache_read_tokens)} cache read`
            : '',
          stats.total_cache_creation_tokens > 0
            ? `${formatTokens(stats.total_cache_creation_tokens)} cache write`
            : '',
          stats.total_reasoning_tokens > 0
            ? `${formatTokens(stats.total_reasoning_tokens)} reasoning`
            : '',
        ]
          .filter(Boolean)
          .join(' · ') || undefined,
      icon: 'tokens' as const,
      trendValue: stats.total_prompt_tokens + stats.total_completion_tokens,
    },
    {
      label: 'Cost',
      period: `${consoleScope.periodDays}d`,
      value: formatSpendList(stats.spend),
      // Per pricing unit, not "input vs output": a second of audio is an input
      // unit for transcription and an output unit for speech, so that split no
      // longer names one thing.
      subtitle: spendSubtitle,
      subtitle2:
        stats.total_cache_read_tokens > 0 || stats.total_cache_creation_tokens > 0
          ? `${formatTokens(stats.total_cache_read_tokens + stats.total_cache_creation_tokens)} cached tokens`
          : undefined,
      icon: 'cost' as const,
      // Trend needs one comparable number, which a window spanning two
      // denominations does not have.
      trendValue: soleSpend?.amount,
    },
    latencyCard({
      p50_ms: stats.p50_latency_ms,
      p95_ms: stats.p95_latency_ms,
      p99_ms: stats.p99_latency_ms,
      subtitle2:
        stats.p50_ttft_ms > 0
          ? `TTFT P50 ${formatDuration(stats.p50_ttft_ms)} · P95 ${formatDuration(stats.p95_ttft_ms)}`
          : undefined,
      periodDays: consoleScope.periodDays,
    }),
    reliabilityCard({
      totalRequests: stats.total_requests,
      errorCount: stats.error_count,
      slowCount: stats.high_latency_count,
      slowLabel: 'slow TTFT (>10s)',
      periodDays: consoleScope.periodDays,
    }),
  ]);

  const chartRows = $derived<ChartRow[]>(
    timeseriesBuckets.map((b) => ({
      timestamp: new Date(b.timestamp),
      request_count: b.request_count,
      error_count: b.error_count,
      p50_latency_ms: b.p50_latency_ms,
      p95_latency_ms: b.p95_latency_ms,
      p99_latency_ms: b.p99_latency_ms,
    })),
  );
  const isHourly = $derived(timeseriesInterval === 'hourly');

  const REQUEST_SERIES: ChartSeries[] = [
    { key: 'request_count', label: 'Requests', color: 'var(--accent)', fill: true },
    { key: 'error_count', label: 'Errors', color: 'var(--error)', tooltipOnly: true },
  ];
  const LATENCY_SERIES: ChartSeries[] = [
    { key: 'p50_latency_ms', label: 'P50', color: 'var(--success)' },
    { key: 'p95_latency_ms', label: 'P95', color: 'var(--warning)' },
    { key: 'p99_latency_ms', label: 'P99', color: 'var(--error)' },
  ];

  /** Build the metrics-chip line shown under a breakdown bar. `cache` adds the
   *  cache-hit chip (users only); `err` adds the error-rate chip (users +
   *  clients). Servers and models pass neither. */
  function llmRowMeta(e: BreakdownEntry, opts: { cache?: boolean; err?: boolean } = {}): RowMeta[] {
    const chips: RowMeta[] = [
      { text: `${formatTokens(e.prompt_tokens + e.completion_tokens)} tok` },
      // A row this dashboard cannot state one figure for is a warning, not a
      // number — tinting it stops "mixed" from reading as a currency code.
      { text: formatSpend(e.spend), accent: e.spend ? undefined : 'var(--warning)' },
      { text: `P95 ${formatDuration(e.p95_latency_ms)}` },
    ];
    if (opts.cache && e.cache_read_tokens > 0 && e.prompt_tokens > 0) {
      chips.push({ text: `${Math.round((e.cache_read_tokens / e.prompt_tokens) * 100)}% cache hit` });
    }
    if (opts.err && e.error_count > 0) {
      chips.push({ text: `${((e.error_count / e.requests) * 100).toFixed(1)}% err`, accent: 'var(--error)' });
    }
    return chips;
  }

  const cacheMaxLookups = $derived(Math.max(0, ...(cache?.aliases ?? []).map((a) => a.lookups)));
  // A negative net is a real, actionable outcome — a semantic alias buying
  // embeddings on prompts nobody repeats — so it reads as an error, not as a
  // smaller win.
  // A window whose savings span two currencies states no figure, so no colour.
  const cacheNetColor = $derived(
    cache?.savings == null
      ? 'var(--text-secondary)'
      : cache.savings.net_saved < 0
        ? 'var(--error)'
        : 'var(--success)',
  );

  /** One of the cache's money figures in the currency it was stated in, or
   *  the mixed-currency marker when the window straddles a currency change. */
  function cacheMoney<T extends { currency: string }>(
    savings: T | null | undefined,
    pick: (s: T) => number,
  ): string {
    return savings ? formatCost(pick(savings), savings.currency) : formatSpend(null);
  }

  const cacheSubtitle = $derived.by(() => {
    if (!cache) return '';
    const parts = [
      `${formatCount(cache.hits)} of ${formatCount(cache.lookups)} served from cache`,
      `${(cache.hit_rate * 100).toFixed(0)}% hit rate`,
    ];
    // Only surfaced while an observe alias is running: it is the number that
    // answers "should I enforce this?", and noise on every other tenant.
    if (cache.observe_hits > 0) {
      parts.push(`${formatCount(cache.observe_hits)} observed · ${cacheMoney(cache.savings, (s) => s.would_avoid)} would be saved`);
    }
    if (cache.bypassed > 0) parts.push(`${formatCount(cache.bypassed)} bypassed by client`);
    return parts.join(' · ');
  });

  // A semantic alias that cannot embed silently falls back to exact matching,
  // which looks exactly like an alias nobody repeats prompts on. Only the
  // transient reasons belong in the alarm: `no_embedding_alias` means the
  // tenant simply hasn't configured one, which the Settings page already says.
  const cacheDegraded = $derived(
    (cache?.semantic_skips ?? [])
      .filter((s) => s.reason === 'embedding_timeout' || s.reason === 'embedding_failed')
      .reduce((n, s) => n + s.count, 0),
  );

  /** Human wording for the machine reasons the pipeline stamps on a badge.
   *  Unknown codes fall through verbatim rather than being dropped — a reason
   *  added later must still reach the operator. */
  const SKIP_LABELS: Record<string, string> = {
    // Responses that can never be cached, whatever the settings.
    tool_calls: 'tool calls',
    generated_media: 'generated media',
    error_status: 'upstream errors',
    incomplete_response: 'incomplete responses',
    empty_response: 'empty responses',
    zero_completion: 'no completion',
    // Responses the cache had no room for — these ARE actionable.
    entry_too_large: 'over the entry size limit',
    cache_full: 'cache full',
    client_bypass: 'client sent no-cache',
    // Semantic matching could not run.
    no_embedding_alias: 'no embedding alias set',
    embedding_alias_unresolved: 'embedding alias unresolved',
    embedding_failed: 'embedding call failed',
    embedding_timeout: 'embedding timed out',
  };
  const skipLabel = (reason: string) => SKIP_LABELS[reason] ?? reason;

  /** Chips under a cache alias's bar. Observe rows deliberately read
   *  differently: they saved nothing, so showing them a "net saved" would be a
   *  lie — their spend is tuning, reported as such. */
  function cacheRowMeta(a: components['schemas']['CacheAliasStat']): RowMeta[] {
    const m: RowMeta[] = [{ text: a.mode }, { text: `${formatCount(a.lookups)} lookups` }];
    const sv = a.savings;
    // A window straddling a currency change has no single figure for this
    // alias: say so, rather than leaving its money chips out.
    if (!sv) m.push({ text: formatSpend(null), accent: 'var(--text-secondary)' });
    if (a.mode === 'observe') {
      m.push({ text: `${formatCount(a.observe_hits)} would hit` });
      if (sv && sv.embedding_cost > 0) m.push({ text: `${formatCost(sv.embedding_cost, sv.currency)} tuning` });
    } else {
      m.push({ text: `${(a.hit_rate * 100).toFixed(0)}% hit` });
      if (sv) m.push({ text: `${formatCost(sv.gross_avoided, sv.currency)} avoided` });
      if (sv && sv.embedding_cost > 0) {
        m.push({ text: `${formatCost(sv.embedding_cost, sv.currency)} embeddings`, accent: 'var(--warning)' });
      }
    }
    // Why this alias isn't caching, next to the hit rate that raised the
    // question. The commonest reason only: the list is sorted, and a row of
    // chips enumerating every cause would bury the one that dominates.
    const [store] = a.store_skips;
    if (store) {
      m.push({ text: `${formatCount(store.count)} not stored: ${skipLabel(store.reason)}` });
    }
    const [sem] = a.semantic_skips;
    if (sem) {
      m.push({
        text: `${formatCount(sem.count)} exact-only: ${skipLabel(sem.reason)}`,
        accent: 'var(--warning)',
      });
    }
    return m;
  }

  async function loadData() {
    loading = true;
    try {
      const [
        usageRes,
        breakdownRes,
        userBreakdownRes,
        appBreakdownRes,
        serverBreakdownRes,
        appsList,
        tsRes,
        errRes,
        cacheRes,
      ] = await Promise.all([
          adminApi.GET('/api/v1/admin/analytics/overview', {
            params: { query: { ...currentPeriodQuery(), ...currentWorkspaceQuery() } },
          }),
          adminApi.GET('/api/v1/admin/analytics/breakdown', {
            params: { query: { ...currentPeriodQuery(), ...currentWorkspaceQuery() } },
          }),
          adminApi.GET('/api/v1/admin/analytics/breakdown', {
            params: { query: { ...currentPeriodQuery(), ...currentWorkspaceQuery(), by: 'user' } },
          }),
          adminApi.GET('/api/v1/admin/analytics/breakdown', {
            params: { query: { ...currentPeriodQuery(), ...currentWorkspaceQuery(), by: 'app' } },
          }),
          adminApi.GET('/api/v1/admin/analytics/breakdown', {
            params: { query: { ...currentPeriodQuery(), ...currentWorkspaceQuery(), by: 'server' } },
          }),
          fetchAllPages<AppInfo>((offset, limit) =>
            adminApi.GET('/api/v1/admin/analytics/apps', { params: { query: { offset, limit } } }),
          ),
          adminApi.GET('/api/v1/admin/analytics/timeseries', {
            params: { query: { ...currentPeriodQuery(), ...currentWorkspaceQuery() } },
          }),
          adminApi.GET('/api/v1/admin/analytics/errors', {
            params: { query: { ...currentPeriodQuery(), ...currentWorkspaceQuery() } },
          }),
          adminApi.GET('/api/v1/admin/analytics/cache', {
            params: { query: { ...currentPeriodQuery(), ...currentWorkspaceQuery() } },
          }),
        ]);
      if (usageRes.data) stats = { ...stats, ...usageRes.data };
      modelBreakdown = breakdownRes.data?.entries ?? [];
      userBreakdown = userBreakdownRes.data?.entries ?? [];
      appBreakdown = appBreakdownRes.data?.entries ?? [];
      serverBreakdown = serverBreakdownRes.data?.entries ?? [];
      appRegistry = new Map(appsList.map((a) => [a.id, a]));
      if (tsRes.data) {
        timeseriesBuckets = tsRes.data.buckets;
        timeseriesInterval = tsRes.data.interval;
      }
      if (errRes.data) errorAnalytics = errRes.data;
      if (cacheRes.data) cache = cacheRes.data;
    } catch (e) {
      toast.error(extractError(e));
    } finally {
      loading = false;
    }
  }

  usePeriodicLoad(loadData);
</script>

<DashboardScaffold title="LLM" subtitle="Token economics, model performance, top users by tokens">
  <!-- Metric cards: Tokens · Cost · Latency · Reliability (no Activity here — Overview owns it) -->
  <MetricGrid class="mb-8">
    {#each metricCards as card (card.label)}
      <MetricCard {loading} {...card} />
    {/each}
  </MetricGrid>

  <!-- Timeseries charts -->
  <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
    <TimeSeriesChart
      title="Request Volume"
      {loading}
      empty={chartRows.length === 0}
      rows={chartRows}
      series={REQUEST_SERIES}
      formatY={formatCount}
      hourly={isHourly}
      nowRule
    />
    <TimeSeriesChart
      title="Latency"
      {loading}
      empty={chartRows.length === 0}
      rows={chartRows}
      series={LATENCY_SERIES}
      formatY={formatDuration}
      hourly={isHourly}
      nowRule
    />
  </div>

  <!-- Response cache — shown only once an alias binds a cache preset. -->
  {#if cacheActive && cache}
    <div class="mb-6">
      <BreakdownPanel
        title="Response cache"
        subtitle={cacheSubtitle}
        action="Configure"
        actionHref="/settings?tab=cache"
        items={cache.aliases}
        maxValue={cacheMaxLookups}
        getKey={(a) => `${a.alias}:${a.mode}`}
        getRow={(a, max) => ({
          label: a.alias,
          value: cacheMoney(a.savings, (s) => (a.mode === 'observe' ? s.would_avoid : s.net_saved)),
          valueColor:
            a.mode === 'observe' || a.savings == null
              ? 'var(--text-secondary)'
              : a.savings.net_saved < 0
                ? 'var(--error)'
                : 'var(--success)',
          sub: a.mode === 'observe' ? 'would save' : 'net saved',
          percent: max > 0 ? (a.lookups / max) * 100 : 0,
          meta: cacheRowMeta(a),
          href: auditHref({ kind: 'llm', model: a.alias, ...linkScope }),
          title: `View audit log for ${a.alias}`,
          mono: true,
          animateBar: true,
          barColor: a.mode === 'observe' ? 'var(--text-tertiary)' : 'var(--success)',
        })}
      >
        {#snippet headerExtra()}
          {#if cacheDegraded > 0}
            <span
              class="text-xs font-mono px-1.5 py-0.5 rounded-full border"
              style="color: var(--warning); border-color: var(--warning);"
              title="Semantic matching fell back to exact for these requests. Raise the embedding timeout or check the embedding provider."
            >{formatCount(cacheDegraded)} semantic degraded</span>
          {/if}
          <span
            class="text-xs font-mono px-1.5 py-0.5 rounded-full border"
            style="color: {cacheNetColor}; border-color: {cacheNetColor};"
          >{cache ? cacheMoney(cache.savings, (s) => s.net_saved) : formatCost(0, accountingCurrency())} net</span>
          <PeriodBadge period={consoleScope.periodDays} />
        {/snippet}
      </BreakdownPanel>
    </div>
  {/if}

  <!-- Top Users / Clients / Servers / Models -->
  <div class="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-4 gap-6 mb-6">
    <BreakdownPanel
      title="Top Users"
      action="Manage"
      actionHref="/users"
      {loading}
      emptyMessage="No usage data yet"
      skeletonCount={4}
      items={userBreakdown}
      limit={5}
      getKey={(u) => u.user_id ?? u.user_email ?? u.key}
      getValue={(u) => u.requests}
      getRow={(user, max) => {
        const userHref = user.user_email
          ? sessionsHref({ user_email: user.user_email, ...linkScope })
          : user.user_id
            ? sessionsHref({ user_id: user.user_id, ...linkScope })
            : undefined;
        return {
          label: user.key,
          value: formatCount(user.requests),
          percent: (user.requests / max) * 100,
          meta: llmRowMeta(user, { cache: true, err: true }),
          href: userHref,
          title: userHref ? `View sessions for ${user.key}` : user.key,
          mono: true,
          animateBar: true,
          barColor: tagMarkColor('violet'),
        };
      }}
    >
      {#snippet headerExtra()}
        <PeriodBadge period={consoleScope.periodDays} />
      {/snippet}
    </BreakdownPanel>

    <BreakdownPanel
      title="Top Clients"
      action="Registry"
      actionHref="/clients?tab=detection"
      {loading}
      emptyMessage="No client data yet"
      skeletonCount={4}
      items={appBreakdown}
      limit={5}
      getKey={(a) => a.key}
      getValue={(a) => a.requests}
      getRow={(app, max) => ({
        label: appName(appRegistry, app.key) || app.key,
        value: formatCount(app.requests),
        percent: (app.requests / max) * 100,
        meta: llmRowMeta(app, { err: true }),
        href: sessionsHref({ app_id: app.key, ...linkScope }),
        title: `View sessions for ${appName(appRegistry, app.key) || app.key}`,
        mono: true,
        animateBar: true,
        barColor: tagMarkColor('teal'),
      })}
    >
      {#snippet headerExtra()}
        <PeriodBadge period={consoleScope.periodDays} />
      {/snippet}
    </BreakdownPanel>

    <BreakdownPanel
      title="Top Servers"
      action="All servers"
      actionHref="/dashboard/servers"
      {loading}
      emptyMessage="No usage data yet"
      skeletonCount={4}
      items={serverBreakdown}
      limit={5}
      getKey={(s) => s.server_id ?? s.key}
      getValue={(s) => s.requests}
      getRow={(server, max) => ({
        label: server.key,
        value: formatCount(server.requests),
        percent: (server.requests / max) * 100,
        meta: llmRowMeta(server),
        // The server's own dashboard, addressed by id like every server page.
        href: server.server_id
          ? `/dashboard/servers/${server.server_id}`
          : auditHref({ kind: 'llm', upstream_server: server.key, ...linkScope }),
        title: `Open the dashboard of ${server.key}`,
        mono: true,
        animateBar: true,
        barColor: tagMarkColor('orange'),
      })}
    >
      {#snippet headerExtra()}
        <PeriodBadge period={consoleScope.periodDays} />
      {/snippet}
    </BreakdownPanel>

    <BreakdownPanel
      title="Top Models"
      action="Providers"
      actionHref="/gateways/llm?tab=upstream"
      {loading}
      emptyMessage="No usage data yet"
      skeletonCount={4}
      items={modelBreakdown}
      limit={5}
      getKey={(m) => m.key}
      getValue={(m) => m.requests}
      getRow={(model, max) => ({
        label: model.key,
        value: formatCount(model.requests),
        percent: (model.requests / max) * 100,
        meta: llmRowMeta(model),
        href: auditHref({ kind: 'llm', model: model.key, ...linkScope }),
        title: `View audit log for model ${model.key}`,
        mono: true,
        animateBar: true,
        barColor: 'var(--accent)',
      })}
    >
      {#snippet headerExtra()}
        <PeriodBadge period={consoleScope.periodDays} />
      {/snippet}
    </BreakdownPanel>
  </div>

  <!-- Errors by category (LLM-shaped finish_reason / error_category) -->
  {#if errorAnalytics && errorAnalytics.total_errors > 0}
    <div class="mb-6">
      <BreakdownPanel
        title="Errors by category"
        action="All errors"
        actionHref={auditHref({ error_category: '_any', ...linkScope })}
        items={errorAnalytics.by_category}
        maxValue={errorAnalytics.total_errors}
        getKey={(c) => c.category}
        getRow={(cat, max) => {
          const pct = max > 0 ? (cat.count / max) * 100 : 0;
          const color = errorCategoryColor(cat.category);
          return {
            label: formatErrorCategory(cat.category),
            value: formatCount(cat.count),
            valueColor: color,
            sub: `${pct.toFixed(1)}%`,
            percent: pct,
            href: auditHref({ error_category: cat.category, ...linkScope }),
            mono: true,
            animateBar: true,
            barColor: color,
          };
        }}
      >
        {#snippet headerExtra()}
          <span
            class="text-xs font-mono px-1.5 py-0.5 rounded-full bg-(--error)/10 text-(--error) border border-(--error)"
          >{formatCount(errorAnalytics?.total_errors)}</span>
        {/snippet}
      </BreakdownPanel>
    </div>
  {/if}

</DashboardScaffold>
