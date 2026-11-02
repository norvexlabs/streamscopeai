<script lang="ts">
  import type { ProxyDashboardData } from '#lib/api-types.js';
  import { auditHref } from '#lib/deeplinks.js';
  import { adminApi } from '#lib/api-client.js';
  import { formatCount } from '#lib/formatters.js';
  import { consoleScope, currentWorkspaceQuery, dashboardScopeParams, currentPeriodQuery } from '#lib/scope.svelte.js';
  import { usePeriodicLoad } from '#lib/hooks.svelte.js';
  import DashboardScaffold from '#lib/components/dashboard/DashboardScaffold.svelte';
  import ProtocolCard from '#lib/components/dashboard/ProtocolCard.svelte';
  import MetricGrid from '#lib/components/dashboard/MetricGrid.svelte';
  import BreakdownPanel from '#lib/components/dashboard/BreakdownPanel.svelte';
  import type { IconName, Tone } from '#lib/icons.js';

  let data = $state<ProxyDashboardData | null>(null);
  let loading = $state(true);

  // Deep-links carry the dashboard's live scope (header workspace pin + period)
  // so the audit list opens on exactly what this dashboard shows.
  const linkScope = $derived(dashboardScopeParams(consoleScope.period, consoleScope.workspace));

  function protocolLabel(api_version: string): string {
    switch (api_version) {
      case 'chat_completions':
        return 'Chat Completions';
      case 'responses':
        return 'Responses';
      case 'anthropic_messages':
        return 'Anthropic Messages';
      case 'google_gemini':
        return 'Google Gemini';
      default:
        return api_version;
    }
  }
  // Each protocol gets a distinct glyph + tone so the four-card row reads as
  // four categories at a glance. Tone is category identity (fixed per protocol),
  // not state — the error rate lives in the subtitle.
  function protocolIcon(api_version: string): IconName {
    switch (api_version) {
      case 'chat_completions': return 'chat';
      case 'responses':        return 'document';
      case 'anthropic_messages': return 'bolt';
      case 'google_gemini':    return 'sparkles';
      default:                 return 'arrowRight';
    }
  }
  // Tones double as category identity here — each protocol picks a distinct
  // tone so the 4-card row reads at a glance. We deliberately use only
  // non-status tones (success/info/warning + neutral) and skip `error`,
  // which would misread as "Gemini is broken" rather than "Gemini is its
  // own category".
  function protocolTone(api_version: string): Tone {
    switch (api_version) {
      case 'chat_completions':   return 'success';
      case 'responses':          return 'info';
      case 'anthropic_messages': return 'warning';
      case 'google_gemini':      return 'neutral';
      default:                   return 'neutral';
    }
  }

  async function loadDashboard() {
    loading = true;
    const res = await adminApi.GET('/api/v1/admin/analytics/proxy', {
      params: { query: { ...currentPeriodQuery(), ...currentWorkspaceQuery() } },
    });
    data = res.data ?? null;
    loading = false;
  }

  usePeriodicLoad(loadDashboard);
</script>

<DashboardScaffold title="Proxy" subtitle="Per-protocol throughput and translation pairs">
  <!-- Per-protocol metric cards -->
  <MetricGrid class="mb-8">
    <!-- Placeholders on the first load only: a refresh keeps the real cards,
         so the grid never re-lays out around a different count. -->
    {#if loading && !data}
      {#each Array(4) as _, i (i)}
        <ProtocolCard loading label="" inbound="" outbound="" icon="chat" />
      {/each}
    {:else if data}
      {#each data.protocol_stats as proto (proto.api_version)}
        {@const errRate = proto.inbound_count > 0 ? (proto.error_count / proto.inbound_count) * 100 : 0}
        <ProtocolCard
          label={protocolLabel(proto.api_version)}
          inbound={formatCount(proto.inbound_count)}
          outbound={formatCount(proto.outbound_count)}
          subtitle={`${errRate.toFixed(1)}% errors`}
          icon={protocolIcon(proto.api_version)}
          iconTone={protocolTone(proto.api_version)}
          href={auditHref({ kind: 'llm', api_version: proto.api_version, ...linkScope })}
        />
      {/each}
    {/if}
  </MetricGrid>

  {#if data}
    {@const translation = data.translation_stats}
    <div class="mb-6">
      <BreakdownPanel
        title="Protocol Translation"
        emptyMessage="No cross-protocol translations"
        items={translation.pairs}
        maxValue={translation.total_translated}
        getRow={(pair, max) => ({
          label: `${protocolLabel(pair.from_protocol)} → ${protocolLabel(pair.to_protocol)}`,
          value: formatCount(pair.count),
          percent: max > 0 ? (pair.count / max) * 100 : 0,
          barColor: 'var(--accent)',
        })}
      >
        {#snippet headerExtra()}
          <span class="text-xs text-(--text-secondary) font-mono">
            {formatCount(translation.total_translated)} translated
          </span>
        {/snippet}
      </BreakdownPanel>
    </div>
  {/if}

</DashboardScaffold>
