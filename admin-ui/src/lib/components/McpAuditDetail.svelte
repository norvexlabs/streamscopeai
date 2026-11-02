<script lang="ts">
  import type { components } from '#lib/generated/api-types.js';
  import { formatDuration, formatBytes, formatDateTime } from '#lib/formatters.js';
  import { page } from '$app/state';
  import { thref } from '#lib/tenant.js';
  import { toolCallsHref } from '#lib/deeplinks.js';

  let slug = $derived(page.params.slug ?? '');
  import Badge from '#lib/components/Badge.svelte';
  import { dedupeBadgesByCode } from '#lib/badges.js';
  import CopyButton from '#lib/components/CopyButton.svelte';
  import DetailField from '#lib/components/audit/DetailField.svelte';
  import MetricChip from '#lib/components/audit/MetricChip.svelte';
  import StatusPill from '#lib/components/audit/StatusPill.svelte';
  import McpCallEvent from '#lib/components/events/McpCallEvent.svelte';
  import { isSelfScoped } from '#lib/selfScoped.js';
  import { m } from '#lib/paraglide/messages.js';

  type McpAuditLogEntry = components['schemas']['McpAuditLogEntry'];
  type McpTransformDiff = components['schemas']['McpTransformDiff'];

  interface Props {
    row: McpAuditLogEntry;
    /** Filter the audit list by user email — wired by the parent. */
    onfilteruser?: (email: string) => void;
    /**
     * Suppress the "Open in Tool Calls feed" pivot link. Set when this drawer
     * is rendered inside the `/tool-calls` feed itself, where the link would
     * point back to the page you're already on (a dead self-link). The pivot
     * stays available from the `/audit` view.
     */
    hideFeedLink?: boolean;
  }

  let { row, onfilteruser, hideFeedLink = false }: Props = $props();
  // On the portal the gateway configuration and the tool-calls feed do not
  // exist: their links render as plain text, or not at all.
  const selfScoped = isSelfScoped();

  // Typed view of the diff so the template doesn't grovel through optional
  // chain unions. `policy_classification` etc. surface as named branches.
  let diff = $derived<McpTransformDiff | null>(row.transform_diff ?? null);

  // The McpCallEvent component already knows how to render `tools/call` /
  // `prompts/get` / `resources/read` payloads via ToolCallEvent /
  // ToolResultEvent — feed it the same shape the session view uses.
  let callEvent = $derived({
    type: 'mcp_call' as const,
    request_id: row.request_id,
    timestamp: row.timestamp,
    method: row.method,
    tool_id: row.tool_id ?? null,
    prompt_id: row.prompt_id ?? null,
    resource_uri: row.resource_uri ?? null,
    virtual_server_slug: row.virtual_server_slug ?? null,
    upstream_server_name: row.upstream_server_name ?? null,
    status_code: row.status_code ?? null,
    error_code: row.error_code ?? null,
    error_message: row.error_message ?? null,
    latency_ms: row.latency_total_ms ?? null,
    transform_diff: row.transform_diff ?? null,
    params: row.params,
    result: row.result,
  });

  function riskClasses(risk: string): string {
    switch (risk) {
      case 'critical':
      case 'high':
        return 'bg-(--error-bg) border-(--error)/30 text-(--error)';
      case 'medium':
        return 'bg-(--warning-bg) border-(--warning-border) text-(--warning)';
      case 'low':
        return 'bg-(--success-bg) border-(--success-border) text-(--tag-teal-text)';
      default:
        return 'bg-(--bg-elevated) border-(--border) text-(--text-secondary)';
    }
  }

  function actionClasses(action: string): string {
    switch (action) {
      case 'block':
        return 'bg-(--error-bg) border-(--error)/30 text-(--error)';
      case 'replace':
        return 'bg-(--warning-bg) border-(--warning-border) text-(--warning)';
      case 'classify':
        return 'bg-(--tag-indigo-bg) text-(--tag-indigo-text) border-current/30';
      default:
        return 'bg-(--bg-elevated) border-(--border) text-(--text-secondary)';
    }
  }

  function listChangedLabel(kind: string): string {
    return `${kind}/list_changed`;
  }
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
    {#if row.protocol_version}
      <DetailField label={m.browse_detail_protocol()} value={row.protocol_version} />
    {/if}
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
    {#if row.virtual_server_slug}
      <DetailField label={m.browse_detail_virtual_server()}>
        {#if selfScoped}
          <span class="ml-2 text-(--text-primary) font-mono">{row.virtual_server_slug}</span>
        {:else}
          <a
            class="ml-2 text-(--accent) hover:text-(--accent-hover) font-mono"
            href={thref(slug, '/gateways/mcp?tab=endpoints')}
          >
            {row.virtual_server_slug}
          </a>
        {/if}
      </DetailField>
    {/if}
    {#if row.upstream_server_name}
      <DetailField label={m.browse_detail_upstream()} value={row.upstream_server_name} />
    {/if}
    {#if row.mcp_session_id}
      <DetailField label={m.browse_detail_mcp_session()} colSpan={2} flex>
        <code class="font-mono text-[11px] text-(--text-primary) truncate" title={row.mcp_session_id}>
          {row.mcp_session_id}
        </code>
        <CopyButton text={row.mcp_session_id} />
      </DetailField>
    {/if}
    {#if !hideFeedLink && !selfScoped && (row.method === 'tools/call' || row.method === 'resources/read' || row.method === 'prompts/get')}
      <div class="md:col-span-3 pt-1">
        <a
          href={thref(slug, toolCallsHref({ kind: 'mcp', request_id: row.request_id }))}
          class="text-[11px] text-(--accent) hover:underline"
        >
          {m.browse_detail_open_tool_calls()}
        </a>
      </div>
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
    {#if row.request_bytes != null}
      <MetricChip label={m.browse_metric_req()} value={formatBytes(row.request_bytes)} />
    {/if}
    {#if row.response_bytes != null}
      <MetricChip label={m.browse_metric_resp()} value={formatBytes(row.response_bytes)} />
    {/if}
    {#if row.error_code != null}
      <StatusPill tone="error">rpc {row.error_code}</StatusPill>
    {/if}
    {#if row.status_code != null && row.status_code >= 400}
      <StatusPill tone="error">HTTP {row.status_code}</StatusPill>
    {/if}
    {#if row.error_message}
      <StatusPill tone="error" bordered={false} title={row.error_message}>
        <span class="max-w-md truncate">{row.error_message}</span>
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

  <!-- ─── Transform Summary (typed McpTransformDiff) ──────────────── -->
  {#if diff}
    {#if diff.policy_classification}
      <div class="rounded-lg border border-(--border) bg-(--bg-primary)/60 p-3 space-y-2">
        <div class="flex items-center gap-2 flex-wrap">
          <span class="text-[10px] font-semibold uppercase tracking-wider text-(--text-secondary)">{m.browse_detail_policy()}</span>
          <span class="px-2 py-0.5 rounded-sm text-[10px] font-medium border {riskClasses(diff.policy_classification.risk)}">
            {diff.policy_classification.risk}
          </span>
          <span class="px-2 py-0.5 rounded-sm text-[10px] font-medium border {actionClasses(diff.policy_classification.action)}">
            {diff.policy_classification.action}
          </span>
          {#if diff.policy_classification.tool_id}
            <code class="px-1.5 py-0.5 rounded-sm text-[10px] font-mono bg-(--bg-secondary) text-(--text-primary)">
              {diff.policy_classification.tool_id}
            </code>
          {/if}
          {#if diff.policy_classification.rule_id}
            <code class="px-1.5 py-0.5 rounded-sm text-[10px] font-mono bg-(--bg-secondary) text-(--text-secondary)" title="rule id">
              {diff.policy_classification.rule_id}
            </code>
          {/if}
          {#if diff.policy_classification.profile_id}
            <code class="px-1.5 py-0.5 rounded-sm text-[10px] font-mono bg-(--bg-secondary) text-(--text-secondary)" title="profile id">
              profile: {diff.policy_classification.profile_id}
            </code>
          {/if}
        </div>
        {#if diff.policy_classification.title}
          <div class="text-sm text-(--text-primary)">{diff.policy_classification.title}</div>
        {/if}
        {#if diff.policy_classification.description}
          <div class="text-xs text-(--text-secondary)">{diff.policy_classification.description}</div>
        {/if}
      </div>
    {/if}

    {#if diff.mcp_stream}
      <div class="flex flex-wrap items-center gap-3 text-[11px]">
        <span class="text-[10px] font-semibold uppercase tracking-wider text-(--text-secondary)">{m.browse_detail_stream()}</span>
        <span class="px-2 py-0.5 rounded-sm bg-(--bg-secondary) text-(--text-primary) font-mono" title="server-initiated sampling/createMessage requests">
          sampling: {diff.mcp_stream.sampling_requests}
        </span>
        <span class="px-2 py-0.5 rounded-sm bg-(--bg-secondary) text-(--text-primary) font-mono" title="server-initiated elicitation/create requests">
          elicitation: {diff.mcp_stream.elicitation_requests}
        </span>
        <span class="px-2 py-0.5 rounded-sm bg-(--bg-secondary) text-(--text-primary) font-mono" title="notifications/logging events">
          log: {diff.mcp_stream.log_notifications}
        </span>
        <span class="px-2 py-0.5 rounded-sm bg-(--bg-secondary) text-(--text-primary) font-mono" title="notifications/list_changed events">
          list_changed: {diff.mcp_stream.list_changed_notifications}
        </span>
        <span class="px-2 py-0.5 rounded-sm bg-(--bg-secondary) text-(--text-primary) font-mono" title="notifications/elicitation/complete events">
          elicit_complete: {diff.mcp_stream.elicitation_complete_notifications}
        </span>
        <span class="px-2 py-0.5 rounded-sm bg-(--bg-secondary) text-(--text-primary) font-mono" title="total bytes streamed from upstream">
          bytes: {formatBytes(diff.mcp_stream.stream_bytes)}
        </span>
      </div>
    {/if}

    {#if diff.mcp_server_initiated}
      <div class="flex items-center gap-2 text-[11px]">
        <span class="text-[10px] font-semibold uppercase tracking-wider text-(--text-secondary)">{m.browse_detail_server_initiated()}</span>
        <span class="px-2 py-0.5 rounded-sm bg-(--bg-secondary) text-(--text-primary) font-mono">
          {diff.mcp_server_initiated.method}
        </span>
        <code class="px-1.5 py-0.5 rounded-sm text-[10px] font-mono bg-(--bg-secondary) text-(--text-secondary)" title="JSON-RPC id">
          id: {JSON.stringify(diff.mcp_server_initiated.rpc_id)}
        </code>
      </div>
    {/if}

    {#if diff.mcp_list_changed}
      <div class="flex items-center gap-2 text-[11px]">
        <span class="text-[10px] font-semibold uppercase tracking-wider text-(--text-secondary)">{m.browse_detail_list_changed()}</span>
        <span class="px-2 py-0.5 rounded-sm bg-(--bg-secondary) text-(--text-primary) font-mono">
          {listChangedLabel(diff.mcp_list_changed.kind)}
        </span>
      </div>
    {/if}

    {#if diff.mcp_elicitation_complete}
      <div class="flex items-center gap-2 text-[11px]">
        <span class="text-[10px] font-semibold uppercase tracking-wider text-(--text-secondary)">{m.browse_detail_elicitation_complete()}</span>
        {#if diff.mcp_elicitation_complete.elicitation_id}
          <code class="px-1.5 py-0.5 rounded-sm text-[10px] font-mono bg-(--bg-secondary) text-(--text-primary)">
            {diff.mcp_elicitation_complete.elicitation_id}
          </code>
        {:else}
          <span class="text-(--text-secondary) italic">{m.browse_detail_no_id()}</span>
        {/if}
      </div>
    {/if}

    {#if diff.transport === 'sse'}
      <div class="flex items-center gap-2 text-[11px]">
        <span class="text-[10px] font-semibold uppercase tracking-wider text-(--text-secondary)">{m.browse_detail_transport()}</span>
        <span class="px-2 py-0.5 rounded-sm bg-(--bg-elevated) text-(--text-secondary) border border-(--border) font-mono">
          legacy SSE GET
        </span>
      </div>
    {/if}
  {/if}

  <!-- ─── JSON-RPC payload viewer ──────────────────────────────────── -->
  <div class="pt-3 border-t border-(--border)">
    <p class="text-[10px] font-semibold uppercase tracking-wider text-(--text-secondary) mb-2">
      {m.browse_detail_jsonrpc_payload()}
    </p>
    <McpCallEvent event={callEvent} />
  </div>
</div>
