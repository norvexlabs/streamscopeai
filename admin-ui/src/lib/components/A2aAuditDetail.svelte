<script lang="ts">
  import { isSelfScoped, portalWorkspace, sessionHref, workspaceQuery } from '#lib/selfScoped.js';
  import { pageHidden } from '#lib/portalPages.svelte.js';
  // Expanded drawer for an A2A audit row. The call's structured content — the
  // message the caller sent, the agent's reply, its artifacts — renders through
  // the SAME `A2aCallEvent` the session timeline uses, fed by the canonical
  // trace projection (`GET /traces/{id}` → the `a2a_call` event). The drawer
  // itself owns only the operator's audit metadata: identity, metrics, badges,
  // the policy ledger, and the raw JSON-RPC payloads behind a toggle.

  import type { components } from '#lib/generated/api-types.js';
  import { adminApi } from '#lib/api-client.js';
  import { portalApi } from '#lib/portal-client.js';
  import { formatDuration, formatBytes, formatDateTime, formatTaskState } from '#lib/formatters.js';
  import { page } from '$app/state';
  import { thref } from '#lib/tenant.js';
  import Badge from '#lib/components/Badge.svelte';
  import { dedupeBadgesByCode } from '#lib/badges.js';
  import CopyButton from '#lib/components/CopyButton.svelte';
  import DetailField from '#lib/components/audit/DetailField.svelte';
  import MetricChip from '#lib/components/audit/MetricChip.svelte';
  import StatusPill from '#lib/components/audit/StatusPill.svelte';
  import RawJsonBlock from '#lib/components/RawJsonBlock.svelte';
  import GuardrailBanner from '#lib/components/events/GuardrailBanner.svelte';
  import A2aCallEvent from '#lib/components/events/A2aCallEvent.svelte';
  import { m } from '#lib/paraglide/messages.js';

  type A2aAuditLogEntry = components['schemas']['A2aAuditLogEntry'];
  type ConversationEvent = components['schemas']['ConversationEvent'];
  type A2aCallEventShape = Extract<ConversationEvent, { type: 'a2a_call' }>;

  interface Props {
    row: A2aAuditLogEntry;
    /** Filter the audit list by user email — wired by the parent. */
    onfilteruser?: (email: string) => void;
  }

  let { row, onfilteruser }: Props = $props();
  let slug = $derived(page.params.slug ?? '');
  // On the portal: the trace is read through the portal (the caller's own,
  // or a sharing workspace's), and the gateway and policy pages do not exist.
  const selfScoped = isSelfScoped();

  let policyFindings = $derived(row.transform_diff?.policy_findings ?? []);
  let guardrails = $derived(row.transform_diff?.guardrail_steps ?? []);

  // The projected call. A2A rows have no conversation_turns entry, so the trace
  // endpoint answers them via the A2A branch: one `a2a_call` event carrying the
  // canonical blocks. Fetched on mount — the drawer only renders when the row is
  // already expanded, and the payload is small.
  let callEvent = $state<A2aCallEventShape | null>(null);
  let traceError = $state(false);
  let showRaw = $state(false);

  $effect(() => {
    let cancelled = false;
    callEvent = null;
    traceError = false;
    void (async () => {
      const { data, error } = selfScoped
        ? await portalApi.GET('/api/v1/portal/audit/{request_id}', {
            params: { path: { request_id: row.request_id }, query: workspaceQuery(viewedWorkspace()) },
          })
        : await adminApi.GET('/api/v1/admin/traces/{request_id}', {
            params: { path: { request_id: row.request_id }, query: { format: 'parsed_raw' } },
          });
      if (cancelled) return;
      const ev = data?.events?.find(
        (e): e is A2aCallEventShape => e.type === 'a2a_call',
      );
      if (error || !ev) {
        traceError = true;
      } else {
        // The drawer's own header owns the policy ledger and guardrail banners,
        // so the shared event renders content only — no duplicate banners.
        callEvent = { ...ev, guardrails: [], blocked: null };
      }
    })();
    return () => { cancelled = true; };
  });

  let hasRaw = $derived(!!(row.params || row.result || row.stream_events));
  // The portal workspace being viewed rides every session link.
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
    {#if row.protocol_version}
      <DetailField label={m.browse_detail_a2a_version()} value={row.protocol_version} />
    {/if}
    {#if row.user_email}
      <DetailField label={m.browse_detail_caller()}>
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
    {#if row.agent_slug}
      <DetailField label={m.browse_filter_agent()}>
        {#if selfScoped}
          <span class="ml-2 text-(--text-primary) font-mono">{row.agent_slug}</span>
        {:else}
          <a
            class="ml-2 text-(--accent) hover:text-(--accent-hover) font-mono"
            href={thref(slug, '/gateways/a2a')}
          >
            {row.agent_slug}
          </a>
        {/if}
      </DetailField>
    {/if}
    <DetailField label={m.browse_detail_method()} value={row.method} />
    {#if row.task_state}
      <DetailField label={m.browse_filter_task_state()} value={formatTaskState(row.task_state)} />
    {/if}
    {#if row.a2a_context_id}
      <DetailField label={m.browse_detail_context()} colSpan={2} flex>
        <code class="font-mono text-[11px] text-(--text-primary) truncate" title={row.a2a_context_id}>
          {row.a2a_context_id}
        </code>
        <CopyButton text={row.a2a_context_id} />
      </DetailField>
    {/if}
    {#if row.a2a_task_id}
      <DetailField label={m.browse_detail_task()} colSpan={2} flex>
        <code class="font-mono text-[11px] text-(--text-primary) truncate" title={row.a2a_task_id}>
          {row.a2a_task_id}
        </code>
        <CopyButton text={row.a2a_task_id} />
      </DetailField>
    {/if}
  </div>

  <!-- ─── Metrics ──────────────────────────────────────────────────── -->
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
    {#if row.error_category}
      <StatusPill tone="error">{row.error_category}</StatusPill>
    {/if}
    {#if row.error_message || row.error_detail}
      {@const detail = row.error_message || row.error_detail || ''}
      <StatusPill tone="error" bordered={false} title={detail}>
        <span class="max-w-md truncate">{detail}</span>
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

  <!-- ─── What the gateway did ─────────────────────────────────────── -->
  {#if policyFindings.length > 0}
    <div class="pt-2 border-t border-(--border) text-xs space-y-1">
      {#each policyFindings as p, i (i)}
        <div class="flex items-center gap-2">
          <StatusPill tone={p.action === 'block' ? 'error' : 'warning'}>{p.action}</StatusPill>
          <span class="text-[10px] uppercase tracking-wider text-(--text-tertiary)">{p.phase}</span>
          {#if p.rule_id && selfScoped}
            <span class="font-mono text-[11px] text-(--text-primary)">{p.rule_id}</span>
          {:else if p.rule_id}
            <a
              class="font-mono text-[11px] text-(--accent) hover:text-(--accent-hover)"
              href={thref(slug, `/policy?rule_id=${encodeURIComponent(p.rule_id)}`)}
              title={m.event_view_rule({ id: p.rule_id })}
            >{p.rule_id}</a>
          {/if}
          <span class="text-(--text-secondary)">{p.title ?? p.description ?? ''}</span>
        </div>
      {/each}
    </div>
  {/if}
  {#each guardrails as g, i (i)}
    <div class="border-t border-(--border)">
      <GuardrailBanner guardrail={g} />
    </div>
  {/each}

  <!-- ─── The call, rendered as a conversation ─────────────────────── -->
  <div class="space-y-2 pt-3 border-t border-(--border)">
    <div class="flex items-center justify-between">
      <p class="text-[10px] font-semibold uppercase tracking-wider text-(--text-secondary)">{m.event_a2a_message()} · {m.event_a2a_reply()}</p>
      {#if hasRaw}
        <button
          onclick={() => (showRaw = !showRaw)}
          class="px-2 py-0.5 rounded-sm text-[10px] font-medium transition-colors {showRaw ? 'bg-(--accent) text-(--accent-fg)' : 'bg-(--bg-secondary) text-(--text-secondary) hover:text-(--text-primary)'}"
        >JSON</button>
      {/if}
    </div>

    {#if showRaw}
      <!-- The payloads verbatim, as they crossed the wire. -->
      <div class="space-y-2">
        {#if row.params}
          <RawJsonBlock label="params" value={row.params} />
        {/if}
        {#if row.result}
          <RawJsonBlock label="result" value={row.result} />
        {/if}
        {#if row.stream_events}
          <RawJsonBlock label="stream events" value={row.stream_events} />
        {/if}
      </div>
    {:else if callEvent}
      <A2aCallEvent event={callEvent} defaultExpanded />
    {:else if traceError}
      <p class="text-xs text-(--text-secondary) py-3 text-center">{m.audit_detail_no_content()}</p>
    {:else}
      <div class="flex items-center gap-2 text-xs text-(--text-secondary) py-3 justify-center">
        <div class="w-3 h-3 border border-(--accent) border-t-transparent rounded-full animate-spin"></div>
        {m.audit_detail_loading_trace()}
      </div>
    {/if}
  </div>

  {#if row.session_id && !pageHidden('sessions', page.data)}
    <div class="pt-2 border-t border-(--border)">
      <a
        href={sessionHref(slug, page.url.pathname, row.session_id, viewedWorkspace())}
        class="inline-flex items-center gap-1.5 px-3 py-1.5 border border-(--accent) rounded-lg text-xs font-medium text-(--accent) hover:bg-(--accent)/10 transition-colors"
      >
        {m.audit_detail_view_session()}
      </a>
    </div>
  {/if}
</div>
