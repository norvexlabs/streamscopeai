<script lang="ts">
  import type { components } from '#lib/generated/api-types.js';
  import { formatBytes, formatDateTime, formatDuration } from '#lib/formatters.js';
  import Badge from '#lib/components/Badge.svelte';
  import { dedupeBadgesByCode } from '#lib/badges.js';
  import CopyButton from '#lib/components/CopyButton.svelte';
  import DetailField from '#lib/components/audit/DetailField.svelte';
  import MetricChip from '#lib/components/audit/MetricChip.svelte';
  import StatusPill from '#lib/components/audit/StatusPill.svelte';
  import WebCallEvent from '#lib/components/events/WebCallEvent.svelte';
  import { page } from '$app/state';
  import { scopeHref } from '#lib/tenant.js';
  import { auditHref } from '#lib/deeplinks.js';
  import { m } from '#lib/paraglide/messages.js';
  import { portalWorkspace } from '#lib/selfScoped.js';

  type WebAuditLogEntry = components['schemas']['WebAuditLogEntry'];

  interface Props {
    row: WebAuditLogEntry;
    /** Filter the audit list by user email — wired by the parent. */
    onfilteruser?: (email: string) => void;
  }

  let { row, onfilteruser }: Props = $props();
  // The portal workspace being viewed rides the link to the orchestrating row.
  const viewedWorkspace = portalWorkspace();
</script>

<div class="space-y-4">
  <!-- ─── Identity & Context ──────────────────────────────────────── -->
  <div class="grid grid-cols-1 md:grid-cols-3 gap-x-6 gap-y-2 text-xs">
    <DetailField label={m.audit_detail_request()} flex>
      <code class="font-mono text-[11px] text-(--text-primary) truncate" title={row.request_id}>
        {row.request_id.slice(-8)}
      </code>
      <CopyButton text={row.request_id} />
    </DetailField>
    <DetailField label={m.browse_detail_time()} value={formatDateTime(row.timestamp)} />
    <DetailField label={m.browse_filter_surface()} value={row.surface === 'substitution' ? 'substitution' : '/mcp/web'} />
    {#if row.user_email}
      <DetailField label={m.browse_detail_user()}>
        {#if onfilteruser}
          <button
            class="ml-2 text-(--accent) hover:text-(--accent-hover) truncate"
            onclick={() => onfilteruser(row.user_email!)}
          >
            {row.user_email}
          </button>
        {:else}
          <span class="ml-2 text-(--text-primary) truncate">{row.user_email}</span>
        {/if}
      </DetailField>
    {/if}
    {#if row.app_id}
      <DetailField label={m.audit_detail_app()} value={row.app_id} />
    {/if}
    {#if row.upstream_server_name}
      <DetailField label={m.browse_detail_upstream()} value={row.upstream_server_name} />
    {/if}
    {#if row.parent_request_id}
      <DetailField label={m.browse_detail_orchestrator()} colSpan={2} flex>
        <!-- A full load: from the audit page itself the link is a fresh deep
             link (the page reads its filters and focus once, on load). -->
        <a
          class="text-(--accent) hover:text-(--accent-hover) font-mono text-[11px]"
          data-sveltekit-reload
          href={scopeHref(page.params.slug ?? '', page.url.pathname, auditHref({ kind: 'llm', request_id: row.parent_request_id, workspace_id: viewedWorkspace() }))}
          title={m.browse_detail_orchestrator_title()}
        >
          {row.parent_request_id.slice(-8)}
        </a>
        <CopyButton text={row.parent_request_id} />
      </DetailField>
    {/if}
  </div>

  <!-- ─── Extended Metrics ─────────────────────────────────────────── -->
  <div class="flex flex-wrap items-center gap-3 text-[11px] pt-2 border-t border-(--border)">
    {#if row.latency_total_ms != null}
      <MetricChip label={m.browse_metric_total()} value={formatDuration(row.latency_total_ms)} />
    {/if}
    {#if row.upstream_latency_ms != null}
      <MetricChip label={m.browse_detail_upstream()} value={formatDuration(row.upstream_latency_ms)} />
    {/if}
    {#if row.bytes_in != null}
      <MetricChip label={m.browse_metric_body_in()} value={formatBytes(row.bytes_in)} />
    {/if}
    {#if row.upstream_status != null}
      <MetricChip label={m.browse_metric_upstream_http()} value={row.upstream_status} />
    {/if}
    {#if row.status_code != null && row.status_code >= 400}
      <StatusPill tone="error">HTTP {row.status_code}</StatusPill>
    {/if}
    {#if row.error_category}
      <StatusPill tone="error" bordered={false} title={row.error_detail ?? ''}>
        {row.error_category}
      </StatusPill>
    {/if}
  </div>

  <!-- ─── Badges ───────────────────────────────────────────────────── -->
  {#if row.badges && row.badges.length > 0}
    <div class="flex flex-wrap gap-1.5 pt-2 border-t border-(--border)">
      {#each dedupeBadgesByCode(row.badges) as badge (badge.code)}
        <Badge {badge} />
      {/each}
    </div>
  {/if}

  <!-- ─── Transform Summary ─────────────────────────────────────────── -->
  {#if row.transform_diff && row.filter_chain}
    {@const chainArr = Array.isArray(row.filter_chain) ? row.filter_chain : []}
    {#if chainArr.length > 0}
      <div class="flex flex-wrap items-center gap-2 text-[11px]">
        <span class="text-[10px] font-semibold uppercase tracking-wider text-(--text-secondary)">
          {m.browse_detail_url_filter_chain()}
        </span>
        {#each chainArr as id}
          <span class="px-2 py-0.5 rounded-sm bg-(--bg-secondary) text-(--text-primary) font-mono">
            {id}
          </span>
        {/each}
      </div>
    {/if}
  {/if}

  <!-- ─── Call detail (canonical event component) ──────────────────── -->
  <div class="pt-3 border-t border-(--border)">
    <p class="text-[10px] font-semibold uppercase tracking-wider text-(--text-secondary) mb-2">
      {m.browse_detail_call()}
    </p>
    <WebCallEvent {row} defaultExpanded={true} />
  </div>
</div>
