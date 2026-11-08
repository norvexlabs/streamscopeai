<script lang="ts">
  import { useLoadView } from '#lib/loadView.svelte.js';
  import { toast } from '#lib/toast.svelte.js';
  import { extractError } from '#lib/api-helpers.js';
  import type { AppInfo, ToolInventoryTool, ToolInventorySummary } from '#lib/api-types.js';
  import type { components } from '#lib/generated/api-types.js';
  import { adminApi } from '#lib/api-client.js';
  import { thref } from '#lib/tenant.js';
  import { toolCallsHref as toolCallsListHref } from '#lib/deeplinks.js';
  import type { PageProps } from './$types';

  let { params }: PageProps = $props();

  let slug = $derived(params.slug);
  import { fetchAllPages } from '#lib/api-helpers.js';
  import { appName, formatCount, formatTimeAgo } from '#lib/formatters.js';
  import { consoleScope, currentWorkspaceQuery, dashboardScopeParams, currentPeriodQuery } from '#lib/scope.svelte.js';
  import { usePeriodicLoad } from '#lib/hooks.svelte.js';
  import DashboardScaffold from '#lib/components/dashboard/DashboardScaffold.svelte';
  import MetricCard from '#lib/components/dashboard/MetricCard.svelte';
  import MetricGrid from '#lib/components/dashboard/MetricGrid.svelte';
  import Panel from '#lib/components/dashboard/Panel.svelte';
  import Skeleton from '#lib/components/Skeleton.svelte';
  import EmptyState from '#lib/components/EmptyState.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import type { IconName, Tone } from '#lib/icons.js';

  type McpDashboardPanel = components['schemas']['McpDashboardPanel'];
  type ProfileCoverage = components['schemas']['ProfileCoverage'];
  type ToolEntry = ToolInventoryTool;
  type ToolSummary = ToolInventorySummary;

  let resourcePanel = $state<McpDashboardPanel>({ items: [], total_calls: 0 });
  let promptPanel = $state<McpDashboardPanel>({ items: [], total_calls: 0 });

  let tools = $state<ToolEntry[]>([]);
  let summary = $state<ToolSummary>({ total_tools: 0, total_calls: 0, blocked_count: 0, not_applied_count: 0, safe_count: 0, caution_count: 0, danger_count: 0, unknown_count: 0, redacted_count: 0 });
  // Whether `summary` holds a reading — a failed fetch zeroes it, which the
  // trend chip must not read as a drop.
  let summaryLoaded = $state(false);
  let coverage = $state<ProfileCoverage>({ profiled_calls: 0, total_calls: 0, top_unprofiled: [] });
  let appRegistry = $state<Map<string, AppInfo>>(new Map());
  let loading = $state(true);

  // Top-20 by call count — the dashboard is a summary view, /tool-calls owns
  // search-and-browse.
  const TOP_N = 20;
  let topTools = $derived(
    tools.slice().sort((a, b) => b.call_count - a.call_count).slice(0, TOP_N),
  );

  let coveragePct = $derived.by(() => {
    if (coverage.total_calls <= 0) return 0;
    return Math.round((coverage.profiled_calls / coverage.total_calls) * 100);
  });
  let unprofiledGapCalls = $derived.by(() =>
    coverage.top_unprofiled.reduce((acc, t) => acc + t.call_count, 0)
  );
  let unprofiledGapPct = $derived.by(() => {
    const gap = coverage.total_calls - coverage.profiled_calls;
    if (gap <= 0) return 0;
    return Math.round((unprofiledGapCalls / gap) * 100);
  });

  function appDescription(id: string): string {
    return appRegistry.get(id)?.description || id;
  }

  async function loadMcpPanels() {
    const baseQuery = {
      ...currentPeriodQuery(), ...currentWorkspaceQuery(),
      limit: 10,
    };
    const [r, p] = await Promise.all([
      adminApi.GET('/api/v1/admin/mcp/dashboard/by-resource', { params: { query: baseQuery } }),
      adminApi.GET('/api/v1/admin/mcp/dashboard/by-prompt', { params: { query: baseQuery } }),
    ]);
    resourcePanel = r.data ?? { items: [], total_calls: 0 };
    promptPanel = p.data ?? { items: [], total_calls: 0 };
  }

  async function loadTools() {
    loading = true;
    // Started beside the tools query and awaited with it, so an older reload's
    // panels can never land after a newer one's (the loader is single-flight).
    // Its own failures leave empty panels, never a rejected loader.
    const panels = loadMcpPanels().catch(() => {});
    try {
      const { data, error: err } = await adminApi.GET('/api/v1/admin/analytics/tools', {
        params: { query: {
          ...currentPeriodQuery(), ...currentWorkspaceQuery(),
        } },
      });
      if (err) {
        toast.error(extractError(err));
        summaryLoaded = false;
        tools = [];
        summary = { total_tools: 0, total_calls: 0, blocked_count: 0, not_applied_count: 0, safe_count: 0, caution_count: 0, danger_count: 0, unknown_count: 0, redacted_count: 0 };
        coverage = { profiled_calls: 0, total_calls: 0, top_unprofiled: [] };
      } else if (data) {
        summaryLoaded = true;
        tools = data.tools || [];
        summary = data.summary || { total_tools: 0, total_calls: 0, blocked_count: 0, not_applied_count: 0, safe_count: 0, caution_count: 0, danger_count: 0, unknown_count: 0, redacted_count: 0 };
        coverage = data.coverage || { profiled_calls: 0, total_calls: 0, top_unprofiled: [] };
      }
    } catch (e) {
      toast.error(extractError(e));
      summaryLoaded = false;
      tools = [];
      summary = { total_tools: 0, total_calls: 0, blocked_count: 0, not_applied_count: 0, safe_count: 0, caution_count: 0, danger_count: 0, unknown_count: 0, redacted_count: 0 };
      coverage = { profiled_calls: 0, total_calls: 0, top_unprofiled: [] };
    } finally {
      await panels;
      loading = false;
    }
  }

  // The apps registry (names for client ids) is near-static: loaded once on
  // mount, not on every refresh. `loadTools` is awaited — the refresh cycle
  // settles when the loader returns, and the cards' readings must have
  // landed by then.
  // Skeleton on the first load and after a scope change only (`#lib/loadView.js`):
  // a refresh keeps what is shown, the empty state included.
  const topView = useLoadView(() => loading);

  usePeriodicLoad(async () => {
    try {
      const appsList = await fetchAllPages<AppInfo>((offset, limit) =>
        adminApi.GET('/api/v1/admin/analytics/apps', { params: { query: { offset, limit } } }));
      appRegistry = new Map(appsList.map(a => [a.id, a]));
    } catch (e) {
      toast.error(extractError(e));
    }
    await loadTools();
  }, loadTools);

  function riskColor(risk: string): string {
    switch (risk) {
      case 'danger': return 'var(--error)';
      case 'caution':
      case 'would block': return 'var(--warning)';
      case 'unknown': return 'var(--text-secondary)';
      default: return 'var(--success)';
    }
  }

  // Summary tiles. Risk-class colors live on the value digits (data → state);
  // the icon glyph stays category-fixed (tone is identity, not severity).
  // `trendValue` drives the inline ↑/↓ chip when counts move between refresh
  // ticks, matching every other dashboard. A zero count falls back to the
  // primary text color so empty categories read calmly instead of glowing
  // red/amber on an empty period.
  function riskValueColor(count: number, color: string): string {
    return count > 0 ? color : 'var(--text-primary)';
  }
  const summaryCards = $derived<Array<{
    label: string;
    value: string;
    icon: IconName;
    iconTone?: Tone;
    valueColor?: string;
    trendValue: number | undefined;
  }>>([
    { label: 'Unique Tools', value: formatCount(summary.total_tools), icon: 'wrench', trendValue: summaryLoaded ? summary.total_tools : undefined },
    { label: 'Total Calls', value: formatCount(summary.total_calls), icon: 'requests', trendValue: summaryLoaded ? summary.total_calls : undefined },
    { label: 'Safe', value: formatCount(summary.safe_count), icon: 'check', iconTone: 'success', valueColor: riskValueColor(summary.safe_count, 'var(--success)'), trendValue: summaryLoaded ? summary.safe_count : undefined },
    { label: 'Caution', value: formatCount(summary.caution_count), icon: 'alert', iconTone: 'warning', valueColor: riskValueColor(summary.caution_count, 'var(--warning)'), trendValue: summaryLoaded ? summary.caution_count : undefined },
    { label: 'Danger', value: formatCount(summary.danger_count), icon: 'errorCircle', iconTone: 'error', valueColor: riskValueColor(summary.danger_count, 'var(--error)'), trendValue: summaryLoaded ? summary.danger_count : undefined },
    { label: 'Blocked', value: formatCount(summary.blocked_count), icon: 'blocked', iconTone: 'error', valueColor: riskValueColor(summary.blocked_count, 'var(--error)'), trendValue: summaryLoaded ? summary.blocked_count : undefined },
    { label: 'Would block', value: formatCount(summary.not_applied_count), icon: 'blocked', iconTone: 'warning', valueColor: riskValueColor(summary.not_applied_count, 'var(--warning)'), trendValue: summaryLoaded ? summary.not_applied_count : undefined },
    { label: 'Unknown', value: formatCount(summary.unknown_count), icon: 'info', iconTone: 'neutral', trendValue: summaryLoaded ? summary.unknown_count : undefined },
    { label: 'Redacted', value: formatCount(summary.redacted_count), icon: 'lock', iconTone: 'info', trendValue: summaryLoaded ? summary.redacted_count : undefined },
  ]);

  function riskBg(risk: string): string {
    switch (risk) {
      case 'danger': return 'var(--error-bg)';
      case 'caution':
      case 'would block': return 'var(--warning-bg)';
      case 'unknown': return 'var(--bg-elevated)';
      default: return 'var(--success-bg)';
    }
  }

  // Per-card chip rows: one chip per risk level with a non-zero count.
  // Order is fixed worst-first for the eye to catch danger / blocked first.
  type Chip = { level: 'safe' | 'caution' | 'danger' | 'unknown' | 'blocked' | 'would block'; count: number };
  function chipsFor(tool: ToolEntry): Chip[] {
    const rows: Chip[] = [
      { level: 'danger', count: tool.danger_count },
      { level: 'blocked', count: tool.blocked_count },
      { level: 'would block', count: tool.not_applied_count },
      { level: 'caution', count: tool.caution_count },
      { level: 'unknown', count: tool.unknown_count },
      { level: 'safe', count: tool.safe_count },
    ];
    return rows.filter((c) => c.count > 0);
  }

  // Deep-links carry the dashboard's live scope (header workspace pin + period)
  // so the tool-calls feed opens on exactly what this dashboard shows.
  const linkScope = $derived(dashboardScopeParams(consoleScope.period, consoleScope.workspace));

  // Deep-link to the LLM tool-calls feed pre-filtered to this tool (and
  // optionally a single risk level when the chip itself is clicked).
  function toolCallsHref(toolName: string, risk?: string): string {
    return thref(slug, toolCallsListHref({ kind: 'llm', tool_name: toolName, risk, ...linkScope }));
  }

  // Card click handler — keyboard handler mirrors `<a>` Enter/Space semantics
  // for the surrounding `<div role="link">` (Svelte can't nest `<a>` inside
  // `<a>` for the chip drill-downs, so the outer card is a clickable div).
  function activateCardOn(href: string) {
    return (e: KeyboardEvent) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        window.location.assign(href);
      }
    };
  }
</script>

<DashboardScaffold title="Tools">
  <MetricGrid class="mb-6">
    {#each summaryCards as card (card.label)}
      <MetricCard {...card} {loading} />
    {/each}
  </MetricGrid>

  <div class="bg-(--bg-card) rounded-xl p-4 border border-(--border) mb-6">
    <div class="flex items-center justify-between mb-2">
      <h3 class="text-sm font-semibold text-(--text-primary)">Profile Coverage</h3>
      <span class="text-xs font-mono text-(--text-secondary)">{coveragePct}%</span>
    </div>
    <div class="h-2 bg-(--bg-primary) rounded-full overflow-hidden border border-(--border)">
      <div class="h-full bg-(--accent) transition-all" style="width: {coveragePct}%"></div>
    </div>
    <p class="text-xs text-(--text-secondary) mt-2">
      {coverage.profiled_calls.toLocaleString()} of {coverage.total_calls.toLocaleString()} calls resolved to a canonical tool_id
    </p>
    {#if coverage.top_unprofiled.length > 0}
      <div class="flex items-center justify-between mt-1 text-xs">
        <span class="text-(--text-secondary)">
          → {coverage.top_unprofiled.length} unprofiled wire name{coverage.top_unprofiled.length !== 1 ? 's' : ''} drive {unprofiledGapPct}% of the gap
        </span>
        <a
          href={thref(slug, '/policy?tab=field-profiles')}
          class="text-(--accent) hover:underline"
        >Open Field Profiles ›</a>
      </div>
    {/if}
  </div>

  <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
    {#each [
      { panel: resourcePanel, title: 'By Resource', subtitle: 'Top resources by `resources/read`', filterKey: 'resource_uri' as const },
      { panel: promptPanel, title: 'By Prompt', subtitle: 'Top prompts by `prompts/get`', filterKey: 'prompt_id' as const },
    ] as { panel, title, subtitle, filterKey } (title)}
      <Panel
        flush
        {title}
        {subtitle}
        loading={loading && panel.items.length === 0}
        empty={!loading && panel.items.length === 0}
        emptyMessage="No data for this period"
      >
        {#snippet headerExtra()}
          <span class="text-xs font-mono text-(--text-secondary)">
            {panel.total_calls.toLocaleString()} call{panel.total_calls === 1 ? '' : 's'}
          </span>
        {/snippet}
        {#snippet skeleton()}
          <div class="p-4"><Skeleton variant="row" count={5} /></div>
        {/snippet}
        <table class="w-full text-xs">
          <thead>
            <tr class="border-b border-(--border) text-(--text-secondary)">
              <th class="text-left font-normal py-2 px-4">Key</th>
              <th class="text-right font-normal py-2 px-4">Calls</th>
              <th class="text-right font-normal py-2 px-4">Errors</th>
              <th class="text-right font-normal py-2 px-4">Last</th>
            </tr>
          </thead>
          <tbody>
            {#each panel.items as row (row.key)}
              {@const href = thref(slug, toolCallsListHref({ kind: 'mcp', [filterKey]: row.key, ...linkScope }))}
              <tr
                class="border-b border-(--border) last:border-b-0 hover:bg-(--bg-elevated) cursor-pointer transition-colors"
                onclick={() => window.location.assign(href)}
              >
                <td class="py-2 px-4 font-mono text-(--text-primary) truncate max-w-[18rem]" title={row.key}>
                  <a href={href} class="hover:text-(--accent)" onclick={(e) => e.stopPropagation()}>{row.key}</a>
                </td>
                <td class="py-2 px-4 text-right font-mono text-(--text-primary)">{row.call_count.toLocaleString()}</td>
                <td class="py-2 px-4 text-right font-mono {row.error_count > 0 ? 'text-(--error)' : 'text-(--text-secondary)'}">{row.error_count}</td>
                <td class="py-2 px-4 text-right text-(--text-secondary)">{formatTimeAgo(row.last_used)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </Panel>
    {/each}
  </div>

  <div class="flex items-center justify-between mb-3">
    <h3 class="text-sm font-semibold text-(--text-primary)">Top {TOP_N} tools by frequency</h3>
    <a
      href={thref(slug, toolCallsListHref({ kind: 'llm', ...linkScope }))}
      class="text-xs font-medium text-(--accent) hover:text-(--accent-hover) transition-colors"
    >Browse invocation feed →</a>
  </div>

  {#if topView.skeleton}
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
      <Skeleton variant="card" count={8} />
    </div>
  {:else if topTools.length === 0}
    <EmptyState
      title="No tool calls in this period"
      body="Activity from any LLM client that calls a tool will appear here."
    >
      {#snippet icon()}<Icon name="wrench" size="lg" tone="neutral" />{/snippet}
    </EmptyState>
  {:else}
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
      {#each topTools as tool (tool.tool_name)}
        {@const chips = chipsFor(tool)}
        {@const cardHref = toolCallsHref(tool.tool_name)}
        <!-- Outer container is a `<div role="link">` (not `<a>`) so the
             inner per-risk chips can be their own `<a>` tags without
             nesting. Keyboard activation routes through `activateCardOn`
             which mirrors `<a>` Enter/Space semantics. Clicking a chip
             still bubbles to the card click handler — `stopPropagation` on
             each chip's onclick keeps the navigation single-target. -->
        <div
          role="link"
          tabindex="0"
          aria-label="View tool calls for {tool.tool_name}"
          onclick={() => window.location.assign(cardHref)}
          onkeydown={activateCardOn(cardHref)}
          class="block bg-(--bg-card) rounded-lg p-3 border border-(--border) border-l-4 hover:bg-(--bg-elevated) hover:border-(--accent) transition-colors cursor-pointer"
          style="border-left-color: {riskColor(tool.risk_level)}"
        >
          <div class="flex items-start justify-between gap-2 mb-2">
            <span
              class="font-mono text-sm text-(--text-primary) truncate"
              title={tool.tool_name}
            >{tool.tool_name}</span>
          </div>

          {#if chips.length > 0}
            <div class="flex flex-wrap gap-1 mb-2">
              {#each chips as chip (chip.level)}
                <a
                  href={toolCallsHref(tool.tool_name, chip.level === 'would block' ? undefined : chip.level)}
                  onclick={(e) => e.stopPropagation()}
                  class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded-sm text-[10px] font-semibold uppercase hover:ring-1 hover:ring-(--accent) transition-shadow"
                  style="color: {riskColor(chip.level)}; background: {riskBg(chip.level)}"
                  title="View {chip.level} calls for {tool.tool_name}"
                >
                  <span>{chip.level}</span>
                  <span class="font-mono normal-case">{chip.count.toLocaleString()}</span>
                </a>
              {/each}
            </div>
          {/if}

          <div class="grid grid-cols-2 gap-1.5 text-xs">
            <div>
              <div class="font-mono text-sm text-(--text-primary)">{tool.call_count.toLocaleString()}</div>
              <div class="text-[10px] text-(--text-secondary) uppercase tracking-wider">calls</div>
            </div>
            <div>
              <div class="font-mono text-sm text-(--text-secondary)">{tool.user_count}</div>
              <div class="text-[10px] text-(--text-secondary) uppercase tracking-wider">users</div>
            </div>
          </div>

          {#if tool.app_ids.length > 0}
            <div class="flex flex-wrap gap-1 mt-2">
              {#each tool.app_ids.slice(0, 3) as appId (appId)}
                <span
                  class="inline-flex items-center px-1.5 py-0.5 rounded-sm text-[10px] font-medium bg-(--bg-primary) text-(--text-secondary) border border-(--border)"
                  title={appDescription(appId)}
                >{appName(appRegistry, appId)}</span>
              {/each}
              {#if tool.app_ids.length > 3}
                <span class="text-[10px] text-(--text-secondary) px-1">+{tool.app_ids.length - 3}</span>
              {/if}
            </div>
          {/if}
        </div>
      {/each}
    </div>

    {#if tools.length > TOP_N}
      <p class="text-xs text-(--text-secondary) mt-3 text-center">
        Showing top {TOP_N} of {tools.length} tools by call frequency
      </p>
    {/if}
  {/if}
</DashboardScaffold>
