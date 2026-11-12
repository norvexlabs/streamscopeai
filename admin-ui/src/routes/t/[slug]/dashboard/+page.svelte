<script lang="ts">
	import { adminApi } from '#lib/api-client.js';
	import { extractError } from '#lib/api-helpers.js';
	import { thref } from '#lib/tenant.js';
	import { auditHref, sessionsHref } from '#lib/deeplinks.js';
	import type { PageProps } from './$types';

	let { params }: PageProps = $props();

	let slug = $derived(params.slug);
	import type { components } from '#lib/generated/api-types.js';
	import { consoleScope, currentPeriodQuery, currentWorkspaceQuery, dashboardScopeParams, dashboardWorkspaceParam } from '#lib/scope.svelte.js';
	import { usePeriodicLoad } from '#lib/hooks.svelte.js';
	import { formatCount, formatCost, formatSpend } from '#lib/formatters.js';
	import { accountingCurrency } from '#lib/currency.svelte.js';
	import DashboardScaffold from '#lib/components/dashboard/DashboardScaffold.svelte';
	import Panel from '#lib/components/dashboard/Panel.svelte';
	import AttentionCard from '#lib/components/dashboard/AttentionCard.svelte';
	import MetricGrid from '#lib/components/dashboard/MetricGrid.svelte';
	import Sparkline from '#lib/components/Sparkline.svelte';
	import { bucketState, bucketStateLabel, niceMaxWithMidpoint, trailingIncomplete } from '#lib/chartHelpers.js';
	import { upstreamAttention } from '#lib/endpoints.js';

	// Deep-links carry the dashboard's live scope (header workspace pin + period)
	// so the audit/sessions list opens on exactly what this dashboard shows.
	// Single-request focus links (`request_id`) are exempt — they target one row.
	const linkScope = $derived(dashboardScopeParams(consoleScope.period, consoleScope.workspace));
	// Workspace-only scope for surfaces NOT filtered by the header period — the
	// attention tiles (fixed short backend window) and the persistent notification
	// feed. Carrying the period there could open a window that excludes the very
	// rows the count is about, stranding the link on an empty list.
	const linkWorkspace = $derived(dashboardWorkspaceParam(consoleScope.workspace));

	type CrossTimeseriesResponse = components['schemas']['CrossTimeseriesResponse'];
	type CrossTimeseriesBucket = components['schemas']['CrossTimeseriesBucket'];
	type NotificationItem = components['schemas']['NotificationItem'];
	type BreakdownEntry = components['schemas']['BreakdownEntry'];
	type McpInvocationCount = components['schemas']['McpInvocationCount'];
	type McpUpstreamRow = components['schemas']['McpUpstreamServerRow'];
	type A2aBreakdownItem = components['schemas']['A2aBreakdownItem'];
	type UpstreamSparkline = components['schemas']['UpstreamSparkline'];
	type AttentionResponse = components['schemas']['AttentionResponse'];

	let attention = $state<AttentionResponse | null>(null);
	let attentionError = $state('');
	let timeseries = $state<CrossTimeseriesResponse | null>(null);
	let notifications = $state<NotificationItem[]>([]);
	let topLlmUpstreams = $state<BreakdownEntry[]>([]);
	let topMcpUpstreams = $state<McpInvocationCount[]>([]);
	let topA2aAgents = $state<A2aBreakdownItem[]>([]);
	let mcpUpstreamLookup = $state<Record<string, McpUpstreamRow>>({});
	let llmSparklines = $state<Record<string, number[]>>({});
	let mcpSparklines = $state<Record<string, number[]>>({});
	let a2aSparklines = $state<Record<string, number[]>>({});
	let llmBucketStarts = $state<string[]>([]);
	let mcpBucketStarts = $state<string[]>([]);
	let a2aBucketStarts = $state<string[]>([]);
	let llmInterval = $state<string>('day');
	let mcpInterval = $state<string>('day');
	let a2aInterval = $state<string>('day');
	let timeseriesError = $state('');
	let notificationsError = $state('');
	let topUpstreamsError = $state('');
	let cache = $state<components['schemas']['CacheAnalyticsResponse'] | null>(null);
	let loading = $state(true);

	// Gated on cached traffic in the SELECTED window, not on a preset existing:
	// the figure is period- and workspace-scoped, so a chip shown for a
	// bound-but-idle preset could only ever read zero.
	const cacheActive = $derived((cache?.lookups ?? 0) > 0 || (cache?.bypassed ?? 0) > 0);
	// A negative net is real and actionable (a semantic alias buying embeddings
	// on prompts nobody repeats), so it reads as an error rather than a small win.
	// Neutral when the window straddles a currency change: no single net figure.
	const cacheNetColor = $derived(
		cache?.savings == null
			? 'var(--text-secondary)'
			: cache.savings.net_saved < 0
				? 'var(--error)'
				: 'var(--success)',
	);

	async function loadAll() {
		loading = true;
		attentionError = timeseriesError = notificationsError = topUpstreamsError = '';
		// Global workspace scope rides on every panel alongside the period. The
		// default scope excludes the Agent workspace, so the agent's own traffic
		// no longer inflates the attention counts.
		const params = { ...currentPeriodQuery(), ...currentWorkspaceQuery() };
		const [att, ts, er, llm, mcp, mcpServers, a2a, llmSpark, mcpSpark, a2aSpark, cacheRes] = await Promise.all([
			adminApi.GET('/api/v1/admin/analytics/cross/attention', {
				params: { query: { ...currentWorkspaceQuery() } },
			}),
			adminApi.GET('/api/v1/admin/analytics/cross/timeseries', { params: { query: params } }),
			adminApi.GET('/api/v1/admin/notifications', {
				params: { query: { ...currentWorkspaceQuery(), limit: 8 } },
			}),
			adminApi.GET('/api/v1/admin/analytics/breakdown', {
				params: { query: { ...params, by: 'server' } },
			}),
			adminApi.GET('/api/v1/admin/mcp/dashboard/by-upstream', {
				params: { query: { ...params, limit: 4 } },
			}),
			adminApi.GET('/api/v1/admin/mcp/upstream-servers', {
				params: { query: { limit: 200 } },
			}),
			adminApi.GET('/api/v1/admin/a2a/dashboard/by-agent', {
				params: { query: { ...params, limit: 4 } },
			}),
			adminApi.GET('/api/v1/admin/analytics/cross/upstream-timeseries', {
				params: { query: { ...params, kind: 'llm', limit: 4 } },
			}),
			adminApi.GET('/api/v1/admin/analytics/cross/upstream-timeseries', {
				params: { query: { ...params, kind: 'mcp', limit: 4 } },
			}),
			adminApi.GET('/api/v1/admin/analytics/cross/upstream-timeseries', {
				params: { query: { ...params, kind: 'a2a', limit: 4 } },
			}),
			adminApi.GET('/api/v1/admin/analytics/cache', { params: { query: params } }),
		]);
		if (att.error) attentionError = extractError(att.error);
		else attention = att.data ?? null;
		if (ts.error) timeseriesError = extractError(ts.error);
		else timeseries = ts.data ?? null;
		if (er.error) notificationsError = extractError(er.error);
		else notifications = er.data?.items ?? [];

		const llmRows = llm.error ? [] : (llm.data?.entries ?? []);
		topLlmUpstreams = llmRows
			.slice()
			.sort((a, b) => b.requests - a.requests)
			.slice(0, 4);
		const mcpPanel = mcp.error ? null : mcp.data;
		topMcpUpstreams = mcpPanel?.items?.slice(0, 4) ?? [];
		topA2aAgents = a2a.error ? [] : (a2a.data?.items?.slice(0, 4) ?? []);
		const lookup: Record<string, McpUpstreamRow> = {};
		for (const row of mcpServers.data?.items ?? []) lookup[row.id] = row;
		mcpUpstreamLookup = lookup;
		const llmSparkRows: UpstreamSparkline[] = llmSpark.error ? [] : (llmSpark.data?.upstreams ?? []);
		llmSparklines = Object.fromEntries(llmSparkRows.map((r) => [r.key, r.buckets]));
		llmBucketStarts = llmSpark.error ? [] : (llmSpark.data?.bucket_starts ?? []);
		llmInterval = llmSpark.error ? 'day' : (llmSpark.data?.interval ?? 'day');
		const mcpSparkRows: UpstreamSparkline[] = mcpSpark.error ? [] : (mcpSpark.data?.upstreams ?? []);
		mcpSparklines = Object.fromEntries(mcpSparkRows.map((r) => [r.key, r.buckets]));
		mcpBucketStarts = mcpSpark.error ? [] : (mcpSpark.data?.bucket_starts ?? []);
		mcpInterval = mcpSpark.error ? 'day' : (mcpSpark.data?.interval ?? 'day');
		const a2aSparkRows: UpstreamSparkline[] = a2aSpark.error ? [] : (a2aSpark.data?.upstreams ?? []);
		a2aSparklines = Object.fromEntries(a2aSparkRows.map((r) => [r.key, r.buckets]));
		a2aBucketStarts = a2aSpark.error ? [] : (a2aSpark.data?.bucket_starts ?? []);
		a2aInterval = a2aSpark.error ? 'day' : (a2aSpark.data?.interval ?? 'day');
		cache = cacheRes.error ? null : (cacheRes.data ?? null);
		if (llm.error || mcp.error || a2a.error) {
			topUpstreamsError = extractError(llm.error ?? mcp.error ?? a2a.error);
		}
		loading = false;
	}

	usePeriodicLoad(loadAll);

	// Attention queue tile derivations — one per category. The card severity
	// caps at the worst-case (expired creds → critical; expiring soon → warning;
	// else info). Subtitle wording stays terse so the four tiles read at a
	// glance.
	const alertsSeverity = $derived<'critical' | 'warning' | 'info' | 'ok'>(
		!attention || attention.alerts.total === 0
			? 'ok'
			: attention.alerts.major > 0
				? 'critical'
				: 'warning',
	);
	const alertsSubtitle = $derived(
		attention && attention.alerts.total > 0
			? `${attention.alerts.major} major · ${attention.alerts.minor} minor`
			: undefined,
	);

	const blockedSeverity = $derived<'critical' | 'warning' | 'info' | 'ok'>(
		!attention || attention.blocked.total === 0 ? 'ok' : 'warning',
	);
	const blockedSubtitle = $derived(
		attention && attention.blocked.top_rule_id
			? `top rule: ${attention.blocked.top_rule_id}`
			: undefined,
	);

	// Guardrail: a finding — or content the scan could not cover in full — is a
	// warning; a stripped (enforce) block is critical. Subtitle surfaces the
	// stripped count when non-zero.
	const guardrailSeverity = $derived<'critical' | 'warning' | 'info' | 'ok'>(
		!attention || attention.guardrail.total === 0
			? 'ok'
			: attention.guardrail.blocked > 0
				? 'critical'
				: 'warning',
	);
	const guardrailSubtitle = $derived(
		attention && attention.guardrail.blocked > 0
			? `${attention.guardrail.blocked} stripped`
			: undefined,
	);

	const expiringSeverity = $derived<'critical' | 'warning' | 'info' | 'ok'>(
		!attention || attention.expiring.total === 0
			? 'ok'
			: attention.expiring.expired > 0 || attention.expiring.lt_24h > 0
				? 'critical'
				: 'warning',
	);
	const expiringSubtitle = $derived.by(() => {
		if (!attention || attention.expiring.total === 0) return undefined;
		const parts: string[] = [];
		if (attention.expiring.expired > 0) parts.push(`${attention.expiring.expired} expired`);
		if (attention.expiring.lt_24h > 0) parts.push(`${attention.expiring.lt_24h} <24h`);
		const rest = attention.expiring.lt_7d - attention.expiring.expired - attention.expiring.lt_24h;
		if (rest > 0) parts.push(`${rest} <${attention.expiry_window_days}d`);
		return parts.join(' · ');
	});

	const errorsSeverity = $derived<'critical' | 'warning' | 'info' | 'ok'>(
		!attention || attention.errors.total === 0 ? 'ok' : 'warning',
	);
	const errorsSubtitle = $derived(
		attention && attention.errors.top_error_category
			? `top: ${attention.errors.top_error_category}`
			: undefined,
	);

	const attentionPeriod = $derived(attention ? `${attention.window_days}d` : '');

	// Upstream health — the servers' state NOW (and refusals in the window).
	// The rule lives in `upstreamAttention`, beside the server health it reads.
	const upstreams = $derived(attention ? upstreamAttention(attention.upstreams) : null);

	// Budget tile — scopes at/over (critical) or approaching (warning) their cap
	// this period. Count is the breach total; the worst offender drives the link.
	const budgetSeverity = $derived<'critical' | 'warning' | 'info' | 'ok'>(
		!attention
			? 'ok'
			: attention.budget.breached > 0
				? 'critical'
				: attention.budget.approaching > 0
					? 'warning'
					: 'ok',
	);
	const budgetSubtitle = $derived.by(() => {
		if (!attention) return undefined;
		const parts: string[] = [];
		if (attention.budget.breached > 0) parts.push(`${attention.budget.breached} over`);
		if (attention.budget.approaching > 0) parts.push(`${attention.budget.approaching} near`);
		if (attention.budget.worst_ratio != null && parts.length > 0)
			parts.push(`worst ${Math.round(attention.budget.worst_ratio * 100)}%`);
		return parts.length > 0 ? parts.join(' · ') : undefined;
	});
	// A member's limit lives on its workspace's Limits tab.
	const budgetHref = $derived(
		attention?.budget.worst_scope_kind === 'user' && attention.budget.worst_workspace_id
			? thref(slug, `/workspaces/${attention.budget.worst_workspace_id}?tab=limits`)
			: attention?.budget.worst_scope_kind === 'workspace' && attention.budget.worst_scope_id
				? thref(slug, `/workspaces/${attention.budget.worst_scope_id}`)
				: attention?.budget.worst_scope_kind === 'key'
					? thref(slug, '/users')
					: thref(slug, '/workspaces'),
	);

	// Alerts tile click-through: filter to the dominant severity so the
	// destination list is non-empty. Major wins ties (more actionable).
	const alertsHref = $derived(
		attention && attention.alerts.major > 0
			? thref(slug, sessionsHref({ alert_level: 'major', ...linkWorkspace }))
			: thref(slug, sessionsHref({ alert_level: 'minor', ...linkWorkspace })),
	);

	// Stacked bar geometry for the timeseries chart.
	const buckets = $derived(timeseries?.buckets ?? []);
	const stackTotal = (b: CrossTimeseriesBucket) =>
		(b.llm_count ?? 0) + (b.mcp_count ?? 0) + (b.a2a_count ?? 0);
	// The stack's axis: twice one nice whole step above the tallest bar, so its
	// top and midpoint labels are both round counts (3 → 4, 12 → 20).
	const maxStack = $derived(niceMaxWithMidpoint(Math.max(0, ...buckets.map(stackTotal)), true));
	const partialLastLlm = $derived(trailingIncomplete(llmBucketStarts, llmInterval));
	const partialLastMcp = $derived(trailingIncomplete(mcpBucketStarts, mcpInterval));
	const partialLastA2a = $derived(trailingIncomplete(a2aBucketStarts, a2aInterval));

	// Hover state for the bar-chart popover tooltip — matches the LayerCake
	// Tooltip UX used by /dashboard/llm and /dashboard/mcp.
	let hoveredBarIdx = $state<number | null>(null);
	let barChartEl = $state<HTMLDivElement | undefined>();
	let hoverX = $state(0);
	const hoveredBar = $derived(hoveredBarIdx !== null ? buckets[hoveredBarIdx] : null);
	const popoverLeft = $derived.by(() => {
		if (!barChartEl) return hoverX + 12;
		const w = barChartEl.clientWidth;
		return hoverX > w * 0.65 ? hoverX - 200 : hoverX + 12;
	});

	function formatTime(iso: string): string {
		const d = new Date(iso);
		if (timeseries?.interval === 'hour') {
			const date = d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
			const time = d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', hour12: false });
			return `${date} · ${time}`;
		}
		return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
	}

	function formatRelTime(iso: string): string {
		const d = new Date(iso);
		const diffMs = Date.now() - d.getTime();
		const mins = Math.floor(diffMs / 60000);
		if (mins < 1) return 'just now';
		if (mins < 60) return `${mins}m ago`;
		const hrs = Math.floor(mins / 60);
		if (hrs < 24) return `${hrs}h ago`;
		return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
	}

	// Severity → token-based dot colour (0 info, 1 warning, 2 critical).
	function severityDot(sev: number): string {
		if (sev >= 2) return 'bg-(--error)';
		if (sev === 1) return 'bg-(--warning)';
		return 'bg-(--accent)';
	}
	function severityLabel(sev: number): string {
		return sev >= 2 ? 'Critical' : sev === 1 ? 'Warning' : 'Info';
	}

	// Deep-link a notification to where the operator acts on it.
	function notificationHrefFor(n: NotificationItem): string {
		switch (n.target_kind) {
			case 'session':
				return n.target_id ? thref(slug, `/sessions/${n.target_id}`) : thref(slug, '/sessions');
			// Keys and users are both managed on the /users inventory page (no
			// per-user / per-key detail route); workspaces have a detail page.
			case 'api_key':
			case 'user':
				return thref(slug, '/users');
			case 'workspace':
				return n.target_id ? thref(slug, `/workspaces/${n.target_id}`) : thref(slug, '/workspaces');
			// Upstream-health alarm: the upstream servers are managed on the LLM
			// gateways page (no per-server detail route — target_id is informational).
			case 'upstream_server':
				return thref(slug, '/gateways/llm');
			// An MCP server every call fails on: its settings are on the MCP
			// page's upstream tab, where its card names what is missing.
			case 'mcp_upstream_server':
				return thref(slug, '/gateways/mcp?tab=upstream-servers');
			// Guardrail-detection alarm: focus the exact flagged request when known
			// (a `request_id` deep-link bypasses the /audit period window so the row is
			// always shown); otherwise fall back to the interleaved filtered list (no
			// `kind`, so both web observe-scan and LLM inbound fold-back rows show).
			case 'guardrail':
				return thref(
					slug,
					n.target_id
						? auditHref({ request_id: n.target_id })
						: auditHref({ has_guardrail: 'true', ...linkWorkspace })
				);
			// Systematic expert-analysis failures are acted on from the Experts page
			// (judge model / routing configuration).
			case 'agent_experts':
				return thref(slug, '/experts');
			// Org-total budget ceiling: the scope IS the tenant, so there is no
			// per-row detail to open — the cap is edited on the settings page's
			// Budget tab, which the `?tab=` deep-link selects directly.
			case 'tenant':
				return thref(slug, '/settings?tab=budget');
			default:
				return thref(slug, '/dashboard');
		}
	}
</script>

<DashboardScaffold title="Overview" subtitle="Cross-protocol health · LLM + MCP + A2A">
	<!-- Attention queue: 7 tiles linking the operator to where they can act.
	     Counts come from /analytics/cross/attention and are not period-scoped
	     (they have their own activity / expiry windows). Each tile shows a
	     ↑/↓ chip inline with the number when the count moved in the latest
	     refresh. -->
	<MetricGrid class="mb-8">
		<AttentionCard
			{loading}
			label="Upstream health"
			period={attentionPeriod}
			count={upstreams?.count}
			severity={upstreams?.severity ?? 'ok'}
			subtitle={upstreams?.subtitle}
			icon="edge"
			href={thref(slug, upstreams?.href ?? '/dashboard/servers')}
		/>
		<AttentionCard
			{loading}
			label="Alerts"
			period={attentionPeriod}
			count={attention?.alerts.total}
			severity={alertsSeverity}
			subtitle={alertsSubtitle}
			icon="alert"
			href={alertsHref}
		/>
		<AttentionCard
			{loading}
			label="Blocked tools"
			period={attentionPeriod}
			count={attention?.blocked.total}
			severity={blockedSeverity}
			subtitle={blockedSubtitle}
			icon="blocked"
			href={thref(slug, auditHref({ kind: 'llm', has_blocked: 'true', ...linkWorkspace }))}
		/>
		<AttentionCard
			{loading}
			label="Guardrail"
			period={attentionPeriod}
			count={attention?.guardrail.total}
			severity={guardrailSeverity}
			subtitle={guardrailSubtitle}
			icon="shield"
			href={thref(slug, auditHref({ has_guardrail: 'true', ...linkWorkspace }))}
		/>
		<AttentionCard
			{loading}
			label="Expiring creds"
			period={attention ? `<${attention.expiry_window_days}d` : ''}
			count={attention?.expiring.total}
			severity={expiringSeverity}
			subtitle={expiringSubtitle}
			icon="clock"
			iconTone="warning"
			href={thref(slug, '/keys')}
		/>
		<AttentionCard
			{loading}
			label="Errors"
			period={attentionPeriod}
			count={attention?.errors.total}
			severity={errorsSeverity}
			subtitle={errorsSubtitle}
			icon="errorCircle"
			href={thref(slug, auditHref({ error_category: '_any', ...linkWorkspace }))}
		/>
		<AttentionCard
			{loading}
			label="Budget breaches"
			count={attention?.budget.breached}
			severity={budgetSeverity}
			subtitle={budgetSubtitle}
			icon="cost"
			href={budgetHref}
		/>
	</MetricGrid>
	{#if attentionError}
		<p class="text-xs text-(--error) mb-4">{attentionError}</p>
	{/if}

	<!-- Stacked LLM × MCP timeseries -->
	<div class="mb-6">
		<Panel
			title="Request volume"
			subtitle="LLM × MCP × A2A, stacked"
			loading={loading && buckets.length === 0}
			error={timeseriesError}
			empty={!loading && buckets.length === 0}
		>
			{#snippet headerExtra()}
				<!-- Cache savings ride here rather than the attention grid above:
				     those tiles are things to act on, and money saved is not one. -->
				{#if cacheActive}
					<a
						href={thref(slug, '/dashboard/llm')}
						class="text-xs font-mono px-1.5 py-0.5 rounded-full border hover:opacity-80"
						style="color: {cacheNetColor}; border-color: {cacheNetColor};"
						title="Response cache savings — open the LLM dashboard for the per-alias breakdown"
					>{cache?.savings
						? formatCost(cache.savings.net_saved, cache.savings.currency)
						: cache
							? formatSpend(null)
							: formatCost(0, accountingCurrency())} cache</a>
				{/if}
			{/snippet}
			<!-- svelte-ignore a11y_no_static_element_interactions -->
			<div class="flex items-stretch h-48 mb-2">
				<!-- Y-axis scale: a nice-number max, midpoint, and zero. Makes the
				     bar heights legible and explains why the scale jumps when the
				     active scope (e.g. workspace) changes the request volume. -->
				<div
					class="relative w-10 shrink-0 text-[10px] font-mono text-(--text-tertiary)"
					aria-hidden="true"
				>
					<span class="absolute right-1.5 top-0 -translate-y-1/2">{formatCount(maxStack)}</span>
					<span class="absolute right-1.5 top-1/2 -translate-y-1/2">{formatCount(maxStack / 2)}</span>
					<span class="absolute right-1.5 bottom-0 translate-y-1/2">0</span>
				</div>
				<div
					bind:this={barChartEl}
					class="flex items-stretch gap-1 flex-1 relative"
					onmouseleave={() => (hoveredBarIdx = null)}
				>
					<!-- Gridlines aligned to the Y-axis ticks (max / mid). -->
					<div class="absolute inset-x-0 top-0 border-t border-(--border) opacity-50 pointer-events-none"></div>
					<div class="absolute inset-x-0 top-1/2 border-t border-(--border) opacity-30 pointer-events-none"></div>
					{#each buckets as b, i (b.bucket_start)}
					{@const total = stackTotal(b)}
					{@const ratio = total / maxStack}
					{@const llmRatio = total > 0 ? (b.llm_count ?? 0) / total : 0}
					{@const mcpRatio = total > 0 ? (b.mcp_count ?? 0) / total : 0}
					{@const a2aRatio = total > 0 ? (b.a2a_count ?? 0) / total : 0}
					{@const state = bucketState(b.bucket_start, timeseries?.interval)}
					{@const incomplete = state !== 'settled'}
					<!-- svelte-ignore a11y_no_static_element_interactions -->
					<div
						class="flex-1 min-w-1.5 flex flex-col-reverse rounded-xs overflow-hidden bg-(--bg-secondary) relative cursor-crosshair"
						onmousemove={(e) => {
							hoveredBarIdx = i;
							const rect = barChartEl?.getBoundingClientRect();
							if (rect) hoverX = e.clientX - rect.left;
						}}
					>
						<div class="absolute inset-x-0 bottom-0 h-0.5 bg-(--bg-elevated)"></div>
						{#if total > 0}
							<div class="bg-(--chart-2)" style="height: {ratio * llmRatio * 100}%;"></div>
							<div class="bg-(--chart-3)" style="height: {ratio * mcpRatio * 100}%;"></div>
							<div class="bg-(--chart-5)" style="height: {ratio * a2aRatio * 100}%;"></div>
						{/if}
						{#if incomplete}
							<div
								class="absolute inset-0 pointer-events-none"
								style="background: repeating-linear-gradient(45deg, transparent 0 4px, var(--bg-elevated) 4px 5px);"
							></div>
						{/if}
						{#if hoveredBarIdx === i}
							<div class="absolute inset-0 bg-(--bg-elevated) opacity-40 pointer-events-none"></div>
						{/if}
					</div>
				{/each}
				{#if hoveredBar}
					{@const hovTotal = stackTotal(hoveredBar)}
					{@const hovState = bucketState(hoveredBar.bucket_start, timeseries?.interval)}
					<div
						class="absolute bg-(--bg-card) border border-(--border) rounded-lg shadow-lg px-3 py-2 pointer-events-none"
						style="left: {popoverLeft}px; top: 8px; min-width: 180px; z-index: 20;"
					>
						<p class="text-[10px] text-(--text-secondary) font-mono mb-1.5">
							{formatTime(hoveredBar.bucket_start)}{bucketStateLabel(hovState)}
						</p>
						<div class="flex items-center gap-2 py-0.5">
							<span class="w-2 h-2 rounded-full shrink-0 bg-(--chart-2)"></span>
							<span class="text-[10px] text-(--text-secondary)">LLM</span>
							<span class="text-xs text-(--text-primary) font-mono ml-auto">{formatCount(hoveredBar.llm_count ?? 0)}</span>
						</div>
						<div class="flex items-center gap-2 py-0.5">
							<span class="w-2 h-2 rounded-full shrink-0 bg-(--chart-3)"></span>
							<span class="text-[10px] text-(--text-secondary)">MCP</span>
							<span class="text-xs text-(--text-primary) font-mono ml-auto">{formatCount(hoveredBar.mcp_count ?? 0)}</span>
						</div>
						<div class="flex items-center gap-2 py-0.5">
							<span class="w-2 h-2 rounded-full shrink-0 bg-(--chart-5)"></span>
							<span class="text-[10px] text-(--text-secondary)">A2A</span>
							<span class="text-xs text-(--text-primary) font-mono ml-auto">{formatCount(hoveredBar.a2a_count ?? 0)}</span>
						</div>
						<div class="flex items-center gap-2 py-0.5 mt-1 pt-1 border-t border-(--border)">
							<span class="text-[10px] text-(--text-secondary) ml-4">Total</span>
							<span class="text-xs text-(--text-primary) font-mono ml-auto">{formatCount(hovTotal)}</span>
						</div>
					</div>
				{/if}
				</div>
			</div>
			{#if buckets.length > 0}
				<div class="flex items-center justify-between text-[10px] font-mono text-(--text-tertiary) mb-2 ml-10">
					<span>{formatTime(buckets[0].bucket_start)}</span>
					<span>{formatTime(buckets[buckets.length - 1].bucket_start)}</span>
				</div>
			{/if}
			<div class="flex items-center gap-4 text-xs text-(--text-secondary)">
				<span class="inline-flex items-center gap-1.5">
					<span class="w-2 h-2 rounded-xs bg-(--chart-2)"></span>LLM
				</span>
				<span class="inline-flex items-center gap-1.5">
					<span class="w-2 h-2 rounded-xs bg-(--chart-3)"></span>MCP
				</span>
				<span class="inline-flex items-center gap-1.5">
					<span class="w-2 h-2 rounded-xs bg-(--chart-5)"></span>A2A
				</span>
				<span class="ml-auto font-mono text-[10px]">
					{timeseries?.interval ?? '—'} buckets · {buckets.length}
				</span>
			</div>
		</Panel>
	</div>

	<!-- Top upstreams: rank-by-volume snapshot for the period, one panel per
	     protocol (an LLM server, an MCP server, an A2A agent — each protocol's
	     notion of "who we called out to"). Distinct from /dashboard/llm,
	     /dashboard/mcp and /dashboard/a2a which present full tables ranked by
	     error / latency / cost. -->
	<div class="grid grid-cols-1 lg:grid-cols-3 gap-5 mb-6">
		<Panel
			title="Top LLM upstreams"
			subtitle="By request volume"
			action="View all"
			actionHref={thref(slug, '/dashboard/servers')}
			loading={loading && topLlmUpstreams.length === 0}
			error={topUpstreamsError}
			empty={!loading && topLlmUpstreams.length === 0}
			emptyMessage="No LLM traffic in the selected period."
		>
			<ul class="space-y-2.5 -mx-1">
				{#each topLlmUpstreams as u (u.key)}
					<li class="flex items-center gap-3 px-1">
						<span class="w-1.5 h-1.5 rounded-full bg-(--chart-2) shrink-0"></span>
						<!-- The server's own dashboard, addressed by id like every server page. -->
						<a
							href={u.server_id
								? thref(slug, `/dashboard/servers/${u.server_id}`)
								: thref(slug, auditHref({ kind: 'llm', upstream_server: u.key, ...linkScope }))}
							class="flex-1 min-w-0 text-sm text-(--text-primary) hover:text-(--accent) transition-colors truncate"
						>
							{u.key}
						</a>
						<Sparkline
							values={llmSparklines[u.key] ?? []}
							partialLast={partialLastLlm}
							color="var(--chart-2)"
							title={`${u.key} request volume`}
						/>
						<span class="text-xs text-(--text-secondary) tabular-nums">
							{formatCount(u.requests)} req
						</span>
						<span class="text-xs text-(--text-secondary) tabular-nums w-16 text-right">
							{formatSpend(u.spend)}
						</span>
					</li>
				{/each}
			</ul>
		</Panel>

		<Panel
			title="Top MCP upstreams"
			subtitle="By call volume"
			action="View all"
			actionHref={thref(slug, '/dashboard/mcp')}
			loading={loading && topMcpUpstreams.length === 0}
			error={topUpstreamsError}
			empty={!loading && topMcpUpstreams.length === 0}
			emptyMessage="No MCP traffic in the selected period."
		>
			<ul class="space-y-2.5 -mx-1">
				{#each topMcpUpstreams as u (u.key)}
					{@const server = mcpUpstreamLookup[u.key]}
					<li class="flex items-center gap-3 px-1">
						<span class="w-1.5 h-1.5 rounded-full bg-(--chart-3) shrink-0"></span>
						<!-- The audit log of every call to this upstream — what the panel
						     counts. Not the tool-call log: it lists tools/call only, so an
						     upstream busy with list/resource/prompt calls would show empty. -->
						<a
							href={thref(slug, auditHref({ kind: 'mcp', upstream_server_id: u.key, ...linkScope }))}
							class="flex-1 min-w-0 text-sm text-(--text-primary) hover:text-(--accent) transition-colors truncate"
						>
							{server?.name ?? u.key.slice(0, 8)}
						</a>
						<Sparkline
							values={mcpSparklines[u.key] ?? []}
							partialLast={partialLastMcp}
							color="var(--chart-3)"
							title={`${server?.name ?? u.key} call volume`}
						/>
						<span class="text-xs text-(--text-secondary) tabular-nums">
							{formatCount(u.call_count)} calls
						</span>
						<span class="text-xs text-(--text-secondary) w-16 text-right truncate">
							{server?.auth_mode ?? '—'}
						</span>
					</li>
				{/each}
			</ul>
		</Panel>

		<Panel
			title="Top A2A agents"
			subtitle="By call volume"
			action="View all"
			actionHref={thref(slug, '/dashboard/a2a')}
			loading={loading && topA2aAgents.length === 0}
			error={topUpstreamsError}
			empty={!loading && topA2aAgents.length === 0}
			emptyMessage="No agent-to-agent traffic in the selected period."
		>
			<ul class="space-y-2.5 -mx-1">
				{#each topA2aAgents as a (a.key)}
					<li class="flex items-center gap-3 px-1">
						<span class="w-1.5 h-1.5 rounded-full bg-(--chart-5) shrink-0"></span>
						<a
							href={thref(slug, auditHref({ kind: 'a2a', agent_slug: a.key, ...linkScope }))}
							class="flex-1 min-w-0 text-sm text-(--text-primary) hover:text-(--accent) transition-colors truncate"
						>
							{a.key}
						</a>
						<Sparkline
							values={a2aSparklines[a.key] ?? []}
							partialLast={partialLastA2a}
							color="var(--chart-5)"
							title={`${a.key} call volume`}
						/>
						<span class="text-xs text-(--text-secondary) tabular-nums">
							{formatCount(a.call_count)} calls
						</span>
						<span class="text-xs w-16 text-right tabular-nums {a.error_count > 0 ? 'text-(--error)' : 'text-(--text-secondary)'}">
							{a.error_count > 0 ? `${formatCount(a.error_count)} err` : '—'}
						</span>
					</li>
				{/each}
			</ul>
		</Panel>
	</div>

	<!-- Notifications feed — budget crossings, major session alerts, expiring
	     keys. Workspace-scoped (like the attention tiles), newest first. -->
	<Panel
		title="Notifications"
		subtitle="Attention feed · latest"
		loading={loading && notifications.length === 0}
		error={notificationsError}
		empty={!loading && notifications.length === 0}
		emptyMessage="No notifications — budgets, alerts, and expiring keys are all clear."
	>
		<ul class="divide-y divide-(--border) -mx-5 -my-5">
			{#each notifications as n (n.id)}
				<li>
					<a
						href={notificationHrefFor(n)}
						class="flex items-center gap-3 px-5 py-2.5 hover:bg-(--bg-elevated) transition-colors"
					>
						<span
							class="w-2 h-2 rounded-full shrink-0 {severityDot(n.severity)}"
							title={severityLabel(n.severity)}
						></span>
						<span class="text-xs text-(--text-secondary) tabular-nums w-16 shrink-0">
							{formatRelTime(n.created_at)}
						</span>
						<span class="flex-1 min-w-0">
							<span class="block text-sm text-(--text-primary) truncate">{n.title}</span>
							<span class="block text-xs text-(--text-secondary) truncate">{n.summary}</span>
						</span>
					</a>
				</li>
			{/each}
		</ul>
	</Panel>

</DashboardScaffold>
