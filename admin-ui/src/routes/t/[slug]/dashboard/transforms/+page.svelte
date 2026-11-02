<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import { extractSettings } from '#lib/api-helpers.js';
  import { thref } from '#lib/tenant.js';
  import type { PageProps } from './$types';

  let { params }: PageProps = $props();

  let slug = $derived(params.slug);
  import type { TransformStatsResponse } from '#lib/api-types.js';
  import { consoleScope, currentWorkspaceQuery, currentPeriodQuery } from '#lib/scope.svelte.js';
  import { usePeriodicLoad } from '#lib/hooks.svelte.js';
  import { formatCount, formatTimeAgo } from '#lib/formatters.js';
  import DashboardScaffold from '#lib/components/dashboard/DashboardScaffold.svelte';
  import MetricCard from '#lib/components/dashboard/MetricCard.svelte';
  import MetricGrid from '#lib/components/dashboard/MetricGrid.svelte';
  import Panel from '#lib/components/dashboard/Panel.svelte';
  import { onMount } from 'svelte';

  let stats = $state<TransformStatsResponse | null>(null);
  let loading = $state(true);
  let failMode = $state<'open' | 'closed' | null>(null);

  async function loadStats() {
    loading = true;
    const { data } = await adminApi.GET('/api/v1/admin/analytics/transforms', {
      params: { query: { ...currentPeriodQuery(), ...currentWorkspaceQuery() } },
    });
    if (data) stats = data;
    loading = false;
  }

  async function loadFailMode() {
    const { data } = await adminApi.GET('/api/v1/admin/settings');
    if (data) {
      failMode = extractSettings(data).rhai_fail_mode === 'closed' ? 'closed' : 'open';
    }
  }

  usePeriodicLoad(loadStats);
  onMount(loadFailMode);

  const totalErrors = $derived(stats?.transforms.reduce((s, t) => s + t.error_count, 0) ?? 0);
</script>

<DashboardScaffold title="Transforms" subtitle="Programs applied to requests and responses, hit rates, errors">
  {#snippet filters()}
    {#if failMode}
      <a
        href={thref(slug, '/settings?tab=scripts')}
        title="Configure script fail mode"
        class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs border transition-colors {failMode === 'closed'
          ? 'border-(--warning-border) bg-(--warning-bg) text-(--warning-text) hover:bg-(--bg-elevated)'
          : 'border-(--border) text-(--text-secondary) hover:bg-(--bg-elevated)'}"
      >
        <span class="w-1.5 h-1.5 rounded-full {failMode === 'closed' ? 'bg-(--warning)' : 'bg-(--success)'}"></span>
        Fail mode: {failMode}
      </a>
    {/if}
  {/snippet}
  <MetricGrid class="mb-8">
    <MetricCard
      {loading}
      label="Total requests"
      period={`${consoleScope.periodDays}d`}
      value={formatCount(stats?.total_requests ?? 0)}
      icon="requests"
      trendValue={stats?.total_requests}
    />
    <MetricCard
      {loading}
      label="With transforms"
      period={`${consoleScope.periodDays}d`}
      value={formatCount(stats?.requests_with_transforms ?? 0)}
      subtitle={stats && stats.total_requests > 0
        ? `${Math.round((stats.requests_with_transforms / stats.total_requests) * 100)}% of requests`
        : undefined}
      icon="bolt"
      trendValue={stats?.requests_with_transforms}
    />
    <MetricCard
      {loading}
      label="Active transforms"
      value={stats?.transforms.length ?? 0}
      icon="settings"
      trendValue={stats?.transforms.length}
    />
    <MetricCard
      {loading}
      label="Errors"
      period={`${consoleScope.periodDays}d`}
      value={formatCount(totalErrors)}
      icon="errorCircle"
      valueColor={totalErrors > 0 ? 'var(--error)' : 'var(--text-primary)'}
      trendValue={stats ? totalErrors : undefined}
    />
  </MetricGrid>

  {#if stats && stats.transforms.length > 0}
    <Panel flush title="Per-program breakdown">
      <div class="overflow-x-auto">
        <table class="w-full text-sm">
          <thead>
            <tr class="border-b border-(--border) text-left text-(--text-secondary)">
              <th class="pb-3 px-6 pt-3 font-medium">Transform</th>
              <th class="pb-3 px-6 pt-3 font-medium text-right">Applied</th>
              <th class="pb-3 px-6 pt-3 font-medium text-right">Modified</th>
              <th class="pb-3 px-6 pt-3 font-medium text-right">Passed</th>
              <th class="pb-3 px-6 pt-3 font-medium text-right">Errors</th>
              <th class="pb-3 px-6 pt-3 font-medium text-right">Last Seen</th>
            </tr>
          </thead>
          <tbody>
            {#each stats.transforms as t (t.name)}
              {@const href = t.id ? thref(slug, `/transforms/${t.id}`) : null}
              <tr
                class="border-b border-(--border) {href ? 'hover:bg-(--bg-elevated) cursor-pointer' : ''} transition-colors"
                onclick={() => { if (href) window.location.assign(href); }}
                title={href ? `Open program ${t.name}` : `Program "${t.name}" no longer exists`}
              >
                <td class="py-3 px-6 font-medium text-(--text-primary)">
                  {#if href}
                    <a href={href} class="hover:text-(--accent)" onclick={(e) => e.stopPropagation()}>{t.name}</a>
                  {:else}
                    <span class="text-(--text-secondary)" title="No live program with this name">{t.name}</span>
                  {/if}
                </td>
                <td class="py-3 px-6 text-right text-(--text-secondary) font-mono">{t.total.toLocaleString()}</td>
                <td class="py-3 px-6 text-right font-mono">
                  <span class="text-(--tag-blue-text)">{t.modify_count.toLocaleString()}</span>
                  {#if t.total > 0}
                    <span class="text-xs text-(--text-secondary) ml-1">({Math.round((t.modify_count / t.total) * 100)}%)</span>
                  {/if}
                </td>
                <td class="py-3 px-6 text-right text-(--text-secondary) font-mono">{t.pass_count.toLocaleString()}</td>
                <td class="py-3 px-6 text-right font-mono">
                  {#if t.error_count > 0}
                    <span class="text-(--error)">{t.error_count.toLocaleString()}</span>
                  {:else}
                    <span class="text-(--text-secondary)">0</span>
                  {/if}
                </td>
                <td class="py-3 px-6 text-right text-xs text-(--text-secondary)">{t.last_seen ? formatTimeAgo(t.last_seen) : '—'}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </Panel>
  {:else if stats && stats.transforms.length === 0}
    <p class="text-center py-12 text-(--text-secondary)">No transform activity in the last {consoleScope.periodDays} days.</p>
  {/if}
</DashboardScaffold>
