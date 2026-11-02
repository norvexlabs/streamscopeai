<script lang="ts">
  // Expanded LLM audit row body. Owns trace + media-blob lifecycle for a
  // single LLM row — the parent only feeds in the row + app registry and
  // receives an `ondiff` callback when the operator clicks "Show diff",
  // since the diff side-sheet is a viewport-scoped overlay anchored to the
  // page.
  import type { components } from '#lib/generated/api-types.js';
  import { adminApi } from '#lib/api-client.js';
  import { portalApi } from '#lib/portal-client.js';
  import { isSelfScoped, portalWorkspace, sessionHref, workspaceQuery } from '#lib/selfScoped.js';
  import { formatTokens, formatBytes, formatPrice, formatCount, formatDuration, appName } from '#lib/formatters.js';
  import { rateUnitLabel } from '#lib/rates.js';
  import { type InjectionBlock } from '#lib/diff-utils.js';
  import CopyButton from '#lib/components/CopyButton.svelte';
  import Badge from '#lib/components/Badge.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import RequestParamsPanel from '#lib/components/RequestParamsPanel.svelte';
  import DetailField from '#lib/components/audit/DetailField.svelte';
  import MetricChip from '#lib/components/audit/MetricChip.svelte';
  import {
    mediaCallCategory,
    firstTextBlock,
    firstBlobRef,
  } from '#lib/mediaCall.js';
  import { page } from '$app/state';
  import { scopeHref } from '#lib/tenant.js';
  import GuardrailBanner from '#lib/components/events/GuardrailBanner.svelte';
  import GuardrailPill from '#lib/components/events/GuardrailPill.svelte';
  import MediaEvent from '#lib/components/events/MediaEvent.svelte';
  import StoredMedia from '#lib/components/events/StoredMedia.svelte';
  import { guardrailsTone, dedupeBadgesByCode } from '#lib/badges.js';
  import { m } from '#lib/paraglide/messages.js';
  import type { DiffDetail } from '#lib/components/browse/DiffPanel.svelte';
  import SegmentedControl from '#lib/components/forms/SegmentedControl.svelte';
  import { asLimitBucket, type LimitBucket } from '#lib/limits.js';
  import { tagMarkColor, type TagColor } from '#lib/components/TagBadge.svelte';

  let slug = $derived(page.params.slug ?? '');
  // Portal member plane: trace + media ride the portal routes, and admin-only
  // deep-links (the clients/detection page) are suppressed.
  const selfScoped = isSelfScoped();
  // The portal workspace being viewed: a teammate's request needs it.
  const viewedWorkspace = portalWorkspace();

  type AuditLogRow = components['schemas']['AuditLogRow'];
  type LlmRow = Extract<AuditLogRow, { kind: 'llm' }>;
  type TraceResponse = components['schemas']['TraceResponse'];

  interface Props {
    row: LlmRow;
    /** app_id → display name. */
    appRegistry: Map<string, { name?: string }>;
    /** Priority-class names by id. A class is tenant data the row records by
     *  id only, so a renamed or deleted one resolves here or not at all —
     *  the row must never hold a class back from being changed. */
    qosClassNames?: Map<string, string>;
    ondiff?: (detail: DiffDetail) => void;
  }

  let { row, appRegistry, qosClassNames, ondiff }: Props = $props();

  /** The class's name, when this reader knows it. */
  const className = $derived(
    row.qos_class_id ? (qosClassNames?.get(row.qos_class_id) ?? null) : null,
  );

  // Why a limit refused the request, from the typed bucket — never the prose.
  const REFUSED_BY: Record<LimitBucket, () => string> = {
    organisation: m.audit_detail_limit_organisation,
    workspace: m.audit_detail_limit_workspace,
    member: m.audit_detail_limit_member,
    key: m.audit_detail_limit_key,
  };
  const refusedBy = $derived(asLimitBucket(row.limit_bucket));

  // Trace + blob state lives on the component instance — one drawer, one
  // lifecycle. The $effect cleanup revokes any in-flight blob URL when the
  // row collapses and the component unmounts.
  let trace = $state<TraceResponse | null>(null);
  let traceError = $state(false);
  let loadingTrace = $state(false);
  let showTrace = $state(false);
  let traceJsonMode = $state(false);
  let traceViewMode = $state<'effective' | 'original'>('effective');

  let viewingBlob = $state(false);

  async function viewTrace() {
    if (showTrace) { showTrace = false; return; }
    showTrace = true;
    if (trace) return;
    loadingTrace = true;
    // Member plane fetches its own request through the ownership-gated portal
    // route; admin uses the tenant-scoped trace route (with raw payloads).
    const { data, error: err } = selfScoped
      ? await portalApi.GET('/api/v1/portal/audit/{request_id}', {
          params: { path: { request_id: row.request_id }, query: workspaceQuery(viewedWorkspace()) },
        })
      : await adminApi.GET('/api/v1/admin/traces/{request_id}', {
          params: { path: { request_id: row.request_id }, query: { format: 'parsed_raw' } },
        });
    if (err || !data) {
      traceError = true;
    } else {
      trace = data;
    }
    loadingTrace = false;
  }



  // Per-unit decomposition of the row's total, in the order the units were
  // charged. `count` is what was CHARGED — the provider's reported count less
  // anything that partitions onto a line of its own — so the lines sum to
  // `cost` less `embedding_cost`.
  const billedLines = $derived(
    Object.entries(row.billed_units ?? {}).sort((a, b) => b[1].cost - a[1].cost),
  );
  // A provider quoting in its own currency leaves two figures on the row: what
  // it charges, and what the ledger recorded after conversion.
  const converted = $derived(row.source_currency !== row.cost_currency);
  // Six significant digits, trailing zeros trimmed — enough to reproduce the
  // conversion by hand without printing a float's full binary tail.
  const fxRateLabel = $derived(String(Number(row.fx_rate.toPrecision(6))));

  /** Whether the trace's events already show its response as the assistant's message. */
  function responseInEvents(t: TraceResponse): boolean {
    return !!t.events?.some((e) => e.type === 'message' && e.role === 'assistant' && e.content === t.response_content);
  }

  const ROLE_TAG = new Map<string, TagColor>([['system', 'violet'], ['user', 'blue'], ['assistant', 'teal'], ['tool', 'orange']]);

  function roleColor(r: string): string {
    const t = ROLE_TAG.get(r);
    return t ? `var(--tag-${t}-text)` : 'var(--text-secondary)';
  }

  function roleBg(r: string): string {
    const t = ROLE_TAG.get(r);
    return t ? `var(--tag-${t}-bg)` : 'var(--bg-secondary)';
  }

  /** The block's left rule is a mark, so it takes the role's chart colour, not its text shade. */
  function roleMark(r: string): string {
    const t = ROLE_TAG.get(r);
    return t ? tagMarkColor(t) : 'var(--text-secondary)';
  }
</script>

<div class="space-y-4">
  <!-- ─── Identity & Context ──────────────────────────────────────── -->
  <div class="grid grid-cols-1 md:grid-cols-3 gap-x-6 gap-y-2 text-xs">
    <DetailField label={m.audit_detail_request()} flex>
      <code class="font-mono text-[11px] text-(--text-primary) truncate" title={row.request_id}>
        {row.request_id ? row.request_id.slice(-8) : '--'}
      </code>
      {#if row.request_id}
        <CopyButton text={row.request_id} />
      {/if}
    </DetailField>
    {#if row.key_name || row.key_prefix}
      <DetailField label={m.audit_detail_api_key()}>
        <span class="ml-2 font-mono text-(--text-primary)">
          {row.key_name || ''}{#if row.key_prefix} <code class="bg-(--bg-secondary) px-0.5 rounded-sm">{row.key_prefix}...</code>{/if}
        </span>
      </DetailField>
    {/if}
    <DetailField label={m.audit_detail_api_version()} value={(row.api_version || '--').replace(/^"|"$/g, '')} />
    <DetailField label={m.audit_detail_app()}>
      {#if row.app_id && selfScoped}
        <span class="ml-2 text-(--text-primary)">{appName(appRegistry, row.app_id)}</span>
      {:else if row.app_id}
        <a href={scopeHref(slug, page.url.pathname, `/clients?tab=detection&edit_app=${encodeURIComponent(row.app_id)}`)}
           class="ml-2 text-(--accent) hover:underline"
           title={m.audit_detail_edit_client({ id: row.app_id })}
           onclick={(e) => e.stopPropagation()}>
          {appName(appRegistry, row.app_id)}
        </a>
      {:else if row.user_agent && selfScoped}
        <span class="ml-2 text-(--text-tertiary) italic">{m.audit_detail_unknown()}</span>
      {:else if row.user_agent}
        <a href={scopeHref(slug, page.url.pathname, `/clients?tab=detection&add_ua=${encodeURIComponent(row.user_agent)}`)}
           class="ml-2 text-(--accent) hover:underline italic"
           title={m.audit_detail_register_client()}
           onclick={(e) => e.stopPropagation()}>
          {m.audit_detail_unknown_register()}
        </a>
      {:else}
        <span class="ml-2 text-(--text-tertiary) italic">{m.audit_detail_unknown()}</span>
      {/if}
    </DetailField>
    {#if row.user_agent}
      <DetailField label={m.audit_detail_user_agent()} colSpan={2}>
        <span class="font-mono text-(--text-primary) block truncate" title={row.user_agent}>{row.user_agent}</span>
      </DetailField>
    {/if}
    {#if row.detection_method}
      <DetailField label={m.audit_detail_detection()} value={row.detection_method} />
    {/if}
    <!-- Forwarded end-client identity (Inline AI traffic): the gateway-relayed end
         user takes the identity slot with the internal (inline-AI) account it
         authenticated as in parentheses; IP and groups follow as plain fields. -->
    {#if row.end_user}
      <DetailField label={m.audit_detail_end_user()} colSpan={2}>
        <span class="ml-2 text-(--text-primary)" title={m.audit_detail_forwarded_hint()}>
          {row.end_user}{#if row.user_email} <span class="text-(--text-tertiary)">({row.user_email})</span>{/if}
        </span>
      </DetailField>
    {/if}
    {#if row.client_ip}
      <DetailField label={m.audit_detail_client_ip()}>
        <span class="ml-2 font-mono text-(--text-primary)">{row.client_ip}</span>
      </DetailField>
    {/if}
    {#if row.end_user_groups && row.end_user_groups.length > 0}
      <DetailField label={m.audit_detail_end_user_groups()} value={row.end_user_groups.join(', ')} />
    {/if}
  </div>

  <!-- ─── Media Details ──────────────────────────────────────────── -->
  {#if row.media_call}
    {@const mcall = row.media_call}
    {@const mcat = mediaCallCategory(mcall)}
    {@const mparams = mcall.params ?? {}}
    {@const minput = firstTextBlock(mcall.input)}
    {@const req_blob = firstBlobRef(mcall.input)}
    {@const resp_blob = firstBlobRef(mcall.output)}
    <div class="space-y-2 pt-2 border-t border-(--border)">
      <h4 class="text-[10px] font-semibold uppercase tracking-wider text-(--text-secondary)">{m.audit_detail_media_details()}</h4>
      <div class="grid grid-cols-1 md:grid-cols-3 gap-x-6 gap-y-2 text-xs">
        <DetailField label={m.audit_detail_endpoint()} value={mcall.endpoint} />
        {#if minput}
          <DetailField label={m.audit_detail_input_text()} colSpan={2}>
            <span class="font-mono text-(--text-primary) block truncate" title={minput}>{minput.substring(0, 80)}{minput.length > 80 ? '...' : ''}</span>
          </DetailField>
        {/if}
        {#if mparams && Object.keys(mparams).length > 0}
          <DetailField label={m.audit_detail_params()}>
            <span class="font-mono text-(--text-primary) block truncate">{JSON.stringify(mparams)}</span>
          </DetailField>
        {/if}
        {#if req_blob?.size_bytes}
          <DetailField label={m.audit_detail_file_size()} value={formatBytes(Number(req_blob.size_bytes))} />
        {/if}
        {#if req_blob?.media_type}
          <DetailField label={m.audit_detail_file_type()} value={req_blob.media_type} />
        {/if}
        {#if mcall.output_units}
          <DetailField label={m.audit_detail_output_units()} value={String(mcall.output_units)} />
        {/if}
      </div>

      <!-- Media Blob Viewer -->
      {#if resp_blob || req_blob}
        {@const preview = resp_blob ?? req_blob}
        {@const preview_mime = preview?.media_type ?? ''}
        {@const preview_kind = resp_blob ? 'response_body' : 'request_upload'}
        <div class="pt-3 border-t border-(--border)">
          <h5 class="text-[10px] font-semibold uppercase tracking-wider text-(--text-secondary) mb-2">{m.audit_detail_media_preview()}</h5>
          {#if viewingBlob && preview}
            <StoredMedia
              hash={preview.content_hash}
              blobType={preview_kind}
              requestId={row.request_id}
              kind={['image', 'audio', 'video'].includes(preview_mime.split('/')[0]) ? preview_mime.split('/')[0] : mcat}
              alt={m.audit_detail_media_alt()}
              compact />
          {:else if preview}
            <button
              onclick={() => (viewingBlob = true)}
              class="text-xs text-(--accent) hover:underline font-medium"
            >
              {m.audit_detail_view_media()}
            </button>
          {/if}
        </div>
      {/if}
    </div>
  {/if}

  <!-- ─── Cost ─────────────────────────────────────────────────────
       The row's total, in the currency the ledger recorded it in — which is
       the tenant's accounting currency AS IT WAS when the row was written, not
       as it is now, so a later settings change never restates it. -->
  <div class="space-y-2 pt-2 border-t border-(--border)">
    <div class="flex items-baseline gap-2 flex-wrap">
      <h4 class="text-[10px] font-semibold uppercase tracking-wider text-(--text-secondary)">
        {m.audit_detail_cost()}
      </h4>
      <span class="font-mono text-sm text-(--text-primary)">
        {formatPrice(row.cost, row.cost_currency)}
      </span>
      <span class="text-[10px] text-(--text-tertiary)">{row.cost_currency}</span>
      {#if converted}
        <!-- The provider quotes in its own currency; both figures belong on the
             row, or the total looks unrelated to what the provider charges. -->
        <span class="text-[11px] text-(--text-secondary)" title={m.audit_detail_fx_hint()}>
          {m.audit_detail_provider_charge()}
          <span class="ml-1 font-mono text-(--text-primary)">
            {formatPrice(row.source_cost, row.source_currency)}
          </span>
          <span class="ml-1">
            {m.audit_detail_fx_rate({ rate: fxRateLabel, from: row.source_currency, to: row.cost_currency })}
          </span>
        </span>
      {/if}
    </div>
    {#if billedLines.length > 0}
      <table class="text-[11px] w-full max-w-md">
        <thead>
          <tr class="text-(--text-secondary) text-left">
            <th class="font-medium pb-1">{m.audit_detail_billed_unit()}</th>
            <th class="font-medium pb-1 text-right">
              <span title={m.audit_detail_billed_count_hint()}>{m.audit_detail_billed_count()}</span>
            </th>
            <th class="font-medium pb-1 text-right">{m.audit_detail_cost()}</th>
          </tr>
        </thead>
        <tbody>
          {#each billedLines as [unit, line] (unit)}
            <tr class="border-t border-(--border)">
              <td class="py-1 text-(--text-primary)">{rateUnitLabel(unit)}</td>
              <td class="py-1 text-right font-mono text-(--text-secondary)">{formatCount(line.count)}</td>
              <td class="py-1 text-right font-mono text-(--text-primary)">{formatPrice(line.cost, row.cost_currency)}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </div>

  <!-- ─── Extended Metrics ─────────────────────────────────────────
       Renders when there's at least one chip to show, or when there's
       nothing else to say AND no error_detail follows (the explicit "No
       extended metrics" fallback). When error_detail is the only follow-up,
       we skip the strip entirely so the operator doesn't see an empty
       bordered band floating above the error block. -->
  {#if row.reasoning_tokens || row.cache_read_tokens || row.cache_creation_tokens || row.embedding_cost || row.embedding_tokens || row.zero_completion || (row.native_finish_reason && row.native_finish_reason !== row.finish_reason) || !row.error_detail}
    <div class="flex flex-wrap items-center gap-3 text-[11px] pt-2 border-t border-(--border)">
      {#if row.reasoning_tokens}
        <MetricChip label={m.audit_detail_reasoning_tokens()} value={formatTokens(row.reasoning_tokens)} />
      {/if}
      {#if row.cache_read_tokens}
        <MetricChip label={m.audit_detail_cache_read_tokens()} value={formatTokens(row.cache_read_tokens)} />
      {/if}
      {#if row.cache_creation_tokens}
        <MetricChip label={m.audit_detail_cache_write_tokens()} value={formatTokens(row.cache_creation_tokens)} />
      {/if}
      {#if row.embedding_cost || row.embedding_tokens}
        <!-- Without this the row's total exceeds the completion's own cost with
             nothing to explain the gap: a Semantic alias buys an embedding on
             every request that is not an exact repeat. Gated on tokens as well
             as cost — an unpriced or pass-through embedding model records real
             tokens at $0, and the round-trip still happened. -->
        <MetricChip
          label={m.audit_detail_embedding_cost()}
          value={`${formatPrice(row.embedding_cost, row.cost_currency)} · ${formatTokens(row.embedding_tokens)}`}
        />
      {/if}
      {#if row.zero_completion}
        <MetricChip
          label={m.audit_detail_zero_completion()}
          value={m.audit_detail_zero_completion_value()}
          title={m.audit_detail_cost_forced_zero()}
          valueClass="text-(--warning)"
        />
      {/if}
      {#if row.native_finish_reason && row.native_finish_reason !== row.finish_reason}
        <MetricChip label={m.audit_detail_native_finish_reason()} value={row.native_finish_reason} />
      {/if}
      {#if !row.reasoning_tokens && !row.cache_read_tokens && !row.cache_creation_tokens && !row.embedding_cost && !row.embedding_tokens && !row.zero_completion && !(row.native_finish_reason && row.native_finish_reason !== row.finish_reason)}
        <p class="text-(--text-secondary) italic">{m.audit_detail_no_extended_metrics()}</p>
      {/if}
    </div>
  {/if}

  <!-- ─── Limit refusal: which limit stopped it ───────────────────── -->
  {#if refusedBy}
    <div class="flex items-center gap-2 px-3 py-2 rounded-lg border border-(--error-border) bg-(--error-bg) text-sm text-(--error-text)" data-testid="limit-refusal">
      <Icon name="blocked" size="sm" tone="error" />
      <span>{REFUSED_BY[refusedBy]()}</span>
    </div>
  {/if}

  {#if row.endpoint_url}
    <div class="flex items-center gap-2 text-xs text-(--text-secondary)" data-testid="answered-by">
      <span>{m.audit_detail_answered_by()}</span>
      <span class="font-mono text-(--text-primary)">{row.endpoint_url}</span>
    </div>
  {/if}

  <!-- ─── Priority and what the request waited for a turn ─────────── -->
  {#if className || (row.queue_wait_ms ?? 0) > 0}
    <div class="flex items-center gap-4 text-xs text-(--text-secondary)" data-testid="qos">
      {#if className}
        <span>
          {m.audit_detail_priority_class()}
          <span class="text-(--text-primary)">{className}</span>
        </span>
      {/if}
      {#if (row.queue_wait_ms ?? 0) > 0}
        <span>
          {m.audit_detail_waited_for_capacity()}
          <span class="font-mono text-(--text-primary)">{formatDuration(row.queue_wait_ms ?? 0)}</span>
          {#if (row.latency_total_ms ?? 0) > 0}
            <span class="text-(--text-tertiary)">· {m.audit_detail_wait_included_in_latency()}</span>
          {/if}
        </span>
      {/if}
    </div>
  {/if}

  <!-- ─── Error Detail (multi-line) ───────────────────────────────── -->
  {#if row.error_detail}
    <div class="space-y-1">
      <span class="block text-[10px] font-semibold uppercase tracking-wider text-(--text-secondary)">{m.audit_detail_error_detail()}</span>
      <pre class="text-xs font-mono text-(--error) whitespace-pre-wrap p-2 rounded-sm bg-(--error)/5 border border-(--error) max-h-32 overflow-y-auto">{row.error_detail}</pre>
    </div>
  {/if}

  <!-- ─── Actions ─────────────────────────────────────────────────── -->
  <div class="flex flex-wrap gap-2 pt-2 border-t border-(--border)">
    <button
      onclick={(e) => { e.stopPropagation(); viewTrace(); }}
      class="inline-flex items-center gap-1.5 px-3 py-1.5 border border-(--accent) rounded-lg text-xs font-medium text-(--accent) hover:bg-(--accent)/10 transition-colors"
    >
      <Icon name="chat" size="sm" color="var(--accent)" />
      {showTrace ? m.audit_detail_hide_content() : m.audit_detail_view_content()}
    </button>
    {#if row.conversation_session_id}
      <a
        href={sessionHref(slug, page.url.pathname, row.conversation_session_id, viewedWorkspace())}
        class="inline-flex items-center gap-1.5 px-3 py-1.5 border border-(--accent) rounded-lg text-xs font-medium text-(--accent) hover:bg-(--accent)/10 transition-colors"
        onclick={(e) => e.stopPropagation()}
      >
        {m.audit_detail_view_session()}
      </a>
    {/if}
  </div>
</div>

<!-- Bottom: typed audit badges (one chip per AuditBadge variant) -->
{#if row.badges && row.badges.length > 0}
  {@const td = row.transform_diff as { injection_blocks?: { transform: string }[]; messages_original_count?: number; messages_after_count?: number } | null | undefined}
  {@const modifyingTransforms = Array.from(new Set((td?.injection_blocks ?? []).map(b => b.transform).filter(Boolean)))}
  {@const messageCount = td && typeof td.messages_original_count === 'number' && typeof td.messages_after_count === 'number'
    ? { before: td.messages_original_count, after: td.messages_after_count } : undefined}
  {@const catchall = (row.catchall_path || row.catchall_method)
    ? { method: row.catchall_method, path: row.catchall_path } : undefined}
  <div class="mt-4 pt-3 border-t border-(--border)">
    <h4 class="text-xs uppercase tracking-wider text-(--text-secondary) font-medium mb-2.5">{m.audit_detail_badges()}</h4>
    <div class="flex flex-wrap gap-1.5">
      {#each dedupeBadgesByCode(row.badges) as badge (badge.code)}
        <Badge {badge} context={{ modifyingTransforms, messageCount, catchall }} />
      {/each}
    </div>
  </div>
{/if}

<!-- Trace Viewer Panel -->
{#if showTrace}
  <div class="mt-4 pt-4 border-t border-(--border)">
    {#if loadingTrace}
      <div class="flex items-center gap-2 text-xs text-(--text-secondary) py-4 justify-center">
        <div class="w-3 h-3 border border-(--accent) border-t-transparent rounded-full animate-spin"></div>
        {m.audit_detail_loading_trace()}
      </div>
    {:else if traceError}
      <p class="text-xs text-(--text-secondary) py-4 text-center">{m.audit_detail_no_content()}</p>
    {:else if trace}
      {@const hasContent = (trace.events && trace.events.length > 0)
        || trace.response_content
        || trace.media_meta
        || trace.params
        || trace.system_prompt}
      <div class="space-y-2">
        <!-- Error envelope — surfaced for any audit row that carries an
             error_detail / error_category. Always rendered first when the
             row is an error so an operator sees the failure context up top,
             even when there's also a partial trace (upstream 4xx/5xx with
             captured content). For pre-pipeline errors this is the entire
             "content". -->
        {#if trace.error_detail || trace.error_category || (trace.status_code && trace.status_code >= 400)}
          <div class="rounded-lg border border-(--error-border) bg-(--error-bg) p-3 space-y-2">
            <div class="flex items-center gap-2 flex-wrap">
              <span class="text-[10px] font-semibold uppercase tracking-wider text-(--error-text)">{m.audit_detail_error()}</span>
              {#if trace.status_code}
                <span class="px-1.5 py-0.5 text-[10px] font-mono rounded-sm bg-(--error)/15 text-(--error-text)">HTTP {trace.status_code}</span>
              {/if}
              {#if trace.error_category}
                <span class="px-1.5 py-0.5 text-[10px] rounded-sm bg-(--error)/10 text-(--error-text)">{trace.error_category}</span>
              {/if}
              {#if trace.model_used}
                <span class="text-[10px] font-mono text-(--text-secondary)">{trace.model_used}</span>
              {/if}
              {#if trace.provider}
                <span class="text-[10px] text-(--text-secondary)">via {trace.provider}</span>
              {/if}
            </div>
            {#if trace.error_detail}
              <pre class="text-xs font-mono text-(--error-text) whitespace-pre-wrap wrap-break-word">{trace.error_detail}</pre>
            {/if}
            {#if !hasContent}
              <p class="text-[10px] text-(--text-secondary) italic">
                {m.audit_detail_request_failed_no_content()}
              </p>
            {/if}
          </div>
        {/if}
        <div class="flex items-center gap-2 mb-3">
          {#if trace.session_id}
            <span class="text-xs text-(--text-secondary)">{m.audit_detail_session_label()}</span>
            <a href={sessionHref(slug, page.url.pathname, trace.session_id, viewedWorkspace())} class="text-xs font-mono text-(--accent) hover:underline">{trace.session_id.substring(0, 8)}...</a>
            <span class="text-xs text-(--text-secondary)">{m.audit_detail_turn({ n: (trace.turn_number || 0) + 1 })}</span>
          {/if}
          {#if trace.events}
            {@const hasIB = (trace.transform_diff?.injection_blocks?.length ?? 0) > 0 || trace.transform_diff?.injected_system_prompt}
            {#if hasIB}
              <!-- The trace sits inside a clickable row: the toggle's clicks stop here. -->
              <div role="toolbar" tabindex="-1" onclick={(e) => e.stopPropagation()} onkeydown={(e) => e.stopPropagation()}>
                <SegmentedControl
                  bind:value={traceViewMode}
                  tone="success"
                  size="xs"
                  surface="secondary"
                  label={m.conv_view_lens()}
                  options={[
                    { value: 'effective', label: m.audit_detail_effective() },
                    { value: 'original', label: m.audit_detail_original() },
                  ]} />
              </div>
            {/if}
            <button
              onclick={(e) => { e.stopPropagation(); traceJsonMode = !traceJsonMode; }}
              class="ml-auto px-2 py-1 rounded-sm text-[10px] font-medium transition-colors {traceJsonMode ? 'bg-(--accent) text-(--accent-fg)' : 'bg-(--bg-secondary) text-(--text-secondary) hover:text-(--text-primary)'}"
            >
              {traceJsonMode ? m.audit_detail_parsed() : 'JSON'}
            </button>
          {/if}
        </div>

        {#if traceJsonMode}
          <!-- Raw JSON view: full trace data as-is -->
          <div class="rounded-lg bg-(--bg-primary) border border-(--border) p-3 overflow-x-auto max-h-96 overflow-y-auto relative group">
            <div class="sticky top-0 float-right opacity-0 group-hover:opacity-100 transition-opacity z-10">
              <CopyButton text={JSON.stringify(trace, null, 2)} />
            </div>
            <pre class="text-xs font-mono text-(--text-secondary) whitespace-pre-wrap">{JSON.stringify(trace, null, 2)}</pre>
          </div>
        {:else}
          <!-- Canonical request parameters + tools available (collapsed by default). -->
          {#if trace.params}
            <RequestParamsPanel params={trace.params} />
          {/if}
          {#if trace.events && trace.events.length > 0}
            {@const vMode = traceViewMode}
            {@const sysBlocks = (trace.transform_diff?.injection_blocks ?? []).filter((b: InjectionBlock) => b.field === 'system_prompt')}
            {@const injectedSP = trace.transform_diff?.injected_system_prompt}
            {#each trace.events as ev}
              {#if ev.type === 'system_prompt'}
                {@const isModified = vMode === 'effective' && (sysBlocks.length > 0 || !!injectedSP)}
                <div class="rounded-lg px-3 py-2 border-l-2" style="background: {isModified ? 'var(--tag-teal-bg)' : 'var(--tag-violet-bg)'}; border-color: {tagMarkColor(isModified ? 'teal' : 'violet')}">
                  <div class="flex items-center gap-2">
                    <span class="text-[10px] font-semibold uppercase tracking-wider" style="color: {isModified ? 'var(--tag-teal-text)' : 'var(--tag-violet-text)'}">system</span>
                    {#if isModified}
                      <span class="px-1.5 py-0.5 text-[9px] font-semibold rounded-sm bg-(--tag-teal-bg) text-(--tag-teal-text) border border-(--success-border)">{m.audit_detail_modified()}</span>
                    {/if}
                  </div>
                  <pre class="text-xs font-mono text-(--text-primary) whitespace-pre-wrap mt-1">{ev.content}</pre>
                  {#if isModified && sysBlocks.length > 0}
                    {#each sysBlocks as block}
                      <div class="mt-2 border-l-2 border-(--success) pl-3 bg-(--success-bg) rounded-r-lg py-2">
                        <span class="text-[10px] font-semibold uppercase tracking-wider text-(--success)">{block.transform}</span>
                        <span class="text-[9px] text-(--text-secondary) ml-2">{block.action}</span>
                        <pre class="mt-1 whitespace-pre-wrap font-mono text-xs text-(--tag-teal-text)">{block.content}</pre>
                      </div>
                    {/each}
                    {#if injectedSP}
                      <button
                        onclick={(e) => { e.stopPropagation(); ondiff?.({ title: m.audit_detail_diff_title_system_prompt(), original: ev.content ?? '', effective: injectedSP, transform: sysBlocks[0]?.transform, phase: 'request', scope: 'system_prompt' }); }}
                        class="mt-2 text-[10px] text-(--accent) hover:underline"
                      >{m.audit_detail_show_diff()}</button>
                    {/if}
                  {/if}
                </div>
              {:else if ev.type === 'message'}
                {@const gs = ev.guardrails ?? []}
                <div
                  class="rounded-lg border-l-2 {gs.length > 0 ? 'border overflow-hidden' : ''}"
                  style="background: {roleBg(ev.role || 'user')}; border-color: {gs.length > 0 ? `var(--${guardrailsTone(gs)})` : roleMark(ev.role || 'user')}"
                >
                  <div class="px-3 py-2">
                    <div class="flex items-center gap-2">
                      <span class="text-[10px] font-semibold uppercase tracking-wider" style="color: {roleColor(ev.role || 'user')}">{ev.role}</span>
                      {#each gs as g}
                        <GuardrailPill guardrail={g} />
                      {/each}
                    </div>
                    {#if ev.thinking}
                      <pre class="text-xs font-mono text-(--text-secondary) whitespace-pre-wrap mt-1 italic">{m.audit_detail_thinking()} {ev.thinking}</pre>
                    {/if}
                    <pre class="text-xs font-mono text-(--text-primary) whitespace-pre-wrap mt-1">{ev.content}</pre>
                  </div>
                  {#each gs as g}
                    <GuardrailBanner guardrail={g} />
                  {/each}
                </div>
              {:else if ev.type === 'tool_call'}
                <div class="rounded-lg px-3 py-2 border-l-2" style="background: var(--tag-orange-bg); border-color: {tagMarkColor('orange')}">
                  <span class="text-[10px] font-semibold uppercase tracking-wider" style="color: var(--tag-orange-text)">tool_call: {ev.name}</span>
                  <pre class="text-xs font-mono text-(--text-primary) whitespace-pre-wrap mt-1">{JSON.stringify(ev.arguments, null, 2)}</pre>
                </div>
              {:else if ev.type === 'tool_result'}
                <div class="rounded-lg px-3 py-2 border-l-2" style="background: var(--tag-cyan-bg); border-color: {tagMarkColor('cyan')}">
                  <span class="text-[10px] font-semibold uppercase tracking-wider" style="color: var(--tag-cyan-text)">tool_result</span>
                  <pre class="text-xs font-mono text-(--text-primary) whitespace-pre-wrap mt-1">{ev.content}</pre>
                </div>
              {:else if ev.type === 'media'}
                <div class="rounded-lg px-3 py-2 border-l-2" style="background: var(--tag-violet-bg); border-color: {tagMarkColor('violet')}">
                  <div class="flex items-center gap-2">
                    <span class="text-[10px] font-semibold uppercase tracking-wider" style="color: var(--tag-violet-text)">{ev.content_type ?? 'media'}</span>
                    <span class="text-[10px] text-(--text-secondary)">{ev.role}</span>
                    {#if ev.media_type}
                      <span class="px-1.5 py-0.5 text-[9px] font-medium rounded-sm bg-(--tag-violet-bg) text-(--tag-violet-text)">{ev.media_type}</span>
                    {/if}
                    {#if ev.size_bytes}
                      <span class="text-[10px] text-(--text-secondary)">{ev.size_bytes > 1024 ? `${(ev.size_bytes / 1024).toFixed(0)} KB` : `${ev.size_bytes} B`}</span>
                    {/if}
                    {#if ev.content_hash}
                      <span class="px-1.5 py-0.5 text-[9px] font-medium rounded-sm bg-(--tag-teal-bg) text-(--tag-teal-text)">{m.audit_detail_stored()}</span>
                    {:else if !ev.data && !ev.url}
                      <span class="px-1.5 py-0.5 text-[9px] font-medium rounded-sm bg-(--bg-elevated) text-(--text-secondary)">{m.audit_detail_not_stored()}</span>
                    {/if}
                  </div>
                  {#if ev.title}
                    <p class="text-xs text-(--text-secondary) mt-1">{ev.title}</p>
                  {/if}
                  <MediaEvent event={ev} compact />
                </div>
              {:else if ev.type === 'tools_changed'}
                {@const tcLabel = ev.kind === 'policy_modified' ? m.audit_detail_tools_changed_policy() : m.audit_detail_tools_changed_turns()}
                <div class="rounded-lg px-3 py-2 border-l-2 border-(--accent) bg-(--accent)/10">
                  <div class="flex items-center gap-2">
                    <span class="text-[10px] font-semibold uppercase tracking-wider text-(--accent)">tools changed</span>
                    <span class="text-xs text-(--text-primary)">{tcLabel}</span>
                  </div>
                  {#if ev.previous_hash || ev.current_hash}
                    <div class="mt-1 text-[10px] text-(--text-secondary) font-mono">
                      {#if ev.previous_hash}<span title={ev.previous_hash}>{m.audit_detail_previous()} {ev.previous_hash.slice(0, 8)}…</span>{/if}
                      {#if ev.previous_hash && ev.current_hash}<span class="mx-2">&rarr;</span>{/if}
                      {#if ev.current_hash}<span title={ev.current_hash}>{m.audit_detail_current()} {ev.current_hash.slice(0, 8)}…</span>{/if}
                    </div>
                  {/if}
                </div>
              {:else if ev.type === 'media_api_call'}
                {@const mcall = ev.media_call}
                {@const mcat = mediaCallCategory(mcall)}
                {@const minput = firstTextBlock(mcall?.input)}
                {@const moutput = firstTextBlock(mcall?.output)}
                {@const req_blob = firstBlobRef(mcall?.input)}
                {@const resp_blob = firstBlobRef(mcall?.output)}
                <div class="space-y-2">
                  <div class="flex items-center gap-2">
                    {#if mcat === 'embedding'}
                      <span class="px-1.5 py-0.5 rounded-full text-[9px] font-medium bg-(--tag-blue-bg) text-(--tag-blue-text)">{m.audit_detail_embedding()}</span>
                    {:else if mcat === 'audio'}
                      <span class="px-1.5 py-0.5 rounded-full text-[9px] font-medium bg-(--tag-teal-bg) text-(--tag-teal-text)">{m.audit_detail_audio()}</span>
                    {:else if mcat === 'image'}
                      <span class="px-1.5 py-0.5 rounded-full text-[9px] font-medium bg-(--tag-violet-bg) text-(--tag-violet-text)">{m.audit_detail_image()}</span>
                    {:else if mcat === 'video'}
                      <span class="px-1.5 py-0.5 rounded-full text-[9px] font-medium bg-(--tag-indigo-bg) text-(--tag-indigo-text)">{m.audit_detail_video()}</span>
                    {:else}
                      <span class="px-1.5 py-0.5 rounded-full text-[9px] font-medium bg-(--bg-secondary) text-(--text-secondary)">{mcat}</span>
                    {/if}
                    <span class="text-xs font-medium text-(--text-primary)">{mcall?.endpoint}</span>
                    {#if mcall?.model}
                      <span class="text-[9px] text-(--text-secondary)">({mcall.model})</span>
                    {/if}
                  </div>
                  <div class="rounded-lg px-3 py-2 border-l-2" style="background: var(--tag-blue-bg); border-color: {tagMarkColor('blue')}">
                    <span class="text-[10px] font-semibold uppercase tracking-wider" style="color: var(--tag-blue-text)">{m.audit_detail_request()}</span>
                    {#if minput}
                      <p class="text-xs text-(--text-primary) whitespace-pre-wrap mt-1">{minput}</p>
                    {/if}
                    {#if req_blob && (mcat === 'audio' || mcat === 'image')}
                      <StoredMedia
                        hash={req_blob.content_hash}
                        blobType="request_upload"
                        requestId={row.request_id}
                        kind={mcat}
                        alt={m.audit_detail_uploaded_alt()}
                        download={mcat === 'audio' ? 'upload.mp3' : undefined}
                        compact />
                    {:else if !minput}
                      <p class="text-[10px] text-(--text-secondary) mt-1 italic">{mcall?.endpoint}</p>
                    {/if}
                  </div>
                  <div class="rounded-lg px-3 py-2 border-l-2" style="background: var(--tag-teal-bg); border-color: {tagMarkColor('teal')}">
                    <span class="text-[10px] font-semibold uppercase tracking-wider" style="color: var(--tag-teal-text)">{m.audit_detail_response()}</span>
                    {#if moutput}
                      <p class="text-xs text-(--text-primary) whitespace-pre-wrap mt-1">{moutput}</p>
                    {/if}
                    {#if resp_blob}
                      <div class="mt-1">
                        <StoredMedia
                          hash={resp_blob.content_hash}
                          blobType="response_body"
                          requestId={row.request_id}
                          kind={mcat}
                          alt={m.audit_detail_generated_alt()}
                          download="response.{mcat === 'image' ? 'png' : mcat === 'audio' ? 'mp3' : 'mp4'}"
                          compact />
                      </div>
                    {:else if mcat === 'video' && mcall?.job}
                      <div class="mt-1 text-[10px]">
                        <p class="text-(--text-secondary)">{m.audit_detail_video_job()} <span class="font-mono text-(--text-primary)">{mcall.job.job_id}</span></p>
                        <p class="text-(--text-secondary)">{m.audit_detail_status_label()} <span class="text-(--text-primary)">{mcall.job.status}</span></p>
                      </div>
                    {:else if mcat === 'embedding'}
                      <p class="text-xs text-(--success) mt-1">{m.audit_detail_embedding_vectors({ count: mcall?.output_units ?? 1 })}</p>
                    {:else if !moutput}
                      <p class="text-[10px] text-(--text-secondary) mt-1 italic">{m.audit_detail_processing()}</p>
                    {/if}
                  </div>
                </div>
              {/if}
            {/each}
          {:else}
            <div class="rounded-lg px-3 py-2 border-l-2 border-(--text-secondary) bg-(--bg-secondary)/30">
              <span class="text-[10px] font-semibold uppercase tracking-wider text-(--text-secondary)">{m.audit_detail_no_conversation_events()}</span>
              <p class="text-xs text-(--text-secondary) mt-1">{m.audit_detail_toggle_raw_hint()}</p>
            </div>
          {/if}

          <!-- Response (only if not already in events) -->
          {#if trace.response_content && !responseInEvents(trace) && !trace.media_meta}
            <div class="rounded-lg px-3 py-2 border-l-2" style="background: var(--tag-teal-bg); border-color: {tagMarkColor('teal')}">
              <span class="text-[10px] font-semibold uppercase tracking-wider text-(--tag-teal-text)">response</span>
              <pre class="text-xs font-mono text-(--text-primary) whitespace-pre-wrap mt-1">{trace.response_content}</pre>
            </div>
          {/if}

          <!-- Media metadata block (for media audit records) -->
          {#if trace.media_meta}
            {@const mm = trace.media_meta}
            {@const mm_call = mm.media_call}
            {@const mm_req_blob = firstBlobRef(mm_call?.input)}
            <div class="rounded-lg border border-(--border) bg-(--bg-secondary)/30 p-3 space-y-2">
              <div class="flex items-center gap-2 flex-wrap">
                <span class="text-[10px] font-semibold uppercase tracking-wider text-(--text-secondary)">{m.audit_detail_media_metadata()}</span>
                {#if mm.model_used}
                  <span class="text-[10px] font-mono text-(--text-secondary)">{mm.model_used}</span>
                {/if}
                {#if mm.provider}
                  <span class="text-[10px] text-(--text-secondary)">via {mm.provider}</span>
                {/if}
              </div>
              <div class="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
                {#if mm_call?.endpoint}<div class="text-(--text-secondary)">{m.audit_detail_endpoint()}</div><div class="font-mono text-(--text-primary)">{mm_call.endpoint}</div>{/if}
                {#if mm_req_blob?.media_type}<div class="text-(--text-secondary)">{m.audit_detail_file_type()}</div><div class="font-mono text-(--text-primary)">{mm_req_blob.media_type}</div>{/if}
                {#if mm_req_blob?.size_bytes}<div class="text-(--text-secondary)">{m.audit_detail_file_size()}</div><div class="font-mono text-(--text-primary)">{mm_req_blob.size_bytes > 1024 ? `${(mm_req_blob.size_bytes / 1024).toFixed(0)} KB` : `${mm_req_blob.size_bytes} B`}</div>{/if}
                {#if mm_call?.output_units}<div class="text-(--text-secondary)">{m.audit_detail_output_units()}</div><div class="font-mono text-(--text-primary)">{mm_call.output_units}</div>{/if}
                {#if mm.spend?.amount}<div class="text-(--text-secondary)">{m.audit_detail_cost()}</div><div class="font-mono text-(--text-primary)">{formatPrice(mm.spend.amount, mm.spend.currency)}</div>{/if}
                {#if mm.latency_ms}<div class="text-(--text-secondary)">{m.audit_detail_latency()}</div><div class="font-mono text-(--text-primary)">{mm.latency_ms}ms</div>{/if}
              </div>
              {#if mm_call?.params && Object.keys(mm_call.params).length > 0}
                <div>
                  <p class="text-[9px] uppercase tracking-wider text-(--text-secondary) mb-0.5">{m.audit_detail_params()}</p>
                  <pre class="text-[11px] font-mono text-(--text-primary) whitespace-pre-wrap">{JSON.stringify(mm_call.params, null, 2)}</pre>
                </div>
              {/if}
            </div>
          {/if}
        {/if}

        <!-- Transform summary (only if there's actual content). -->
        {#if trace.transform_diff}
          {@const td = trace.transform_diff}
          {@const allBlocks = td.injection_blocks ?? []}
          {@const toolBlocks = allBlocks.filter((b: InjectionBlock) => b.scope === 'tools')}
          {@const paramBlocks = allBlocks.filter((b: InjectionBlock) => b.scope === 'params')}
          {@const reqPrograms = td.transform_programs ?? []}
          {@const rspPrograms = td.response_transform_programs ?? []}
          {@const hasContent = reqPrograms.length > 0 || toolBlocks.length > 0 || paramBlocks.length > 0 || rspPrograms.length > 0 || ((td.response_blocked_tools?.length ?? 0) > 0)}
          {#if hasContent}
            <div class="rounded-lg px-3 py-2 bg-(--bg-primary) border border-(--border) space-y-2">
              <span class="block text-[10px] font-semibold uppercase tracking-wider text-(--text-secondary)">{m.audit_detail_transforms_applied()}</span>
              {#if reqPrograms.length > 0}
                <div class="space-y-1">
                  {#each reqPrograms as prog}
                    {@const isError = prog.outcome === 'errored'}
                    <div class="flex items-center gap-2 text-xs">
                      <span class="{isError ? 'text-(--warning)' : 'text-(--success)'}">{isError ? 'E' : 'T'}</span>
                      <span class="text-(--text-primary)">{prog.name}</span>
                      {#if isError}<span class="text-(--warning)">— {m.audit_detail_error_fail_open()}</span>{:else if prog.outcome === 'passed'}<span class="text-(--text-secondary)">— {m.audit_detail_no_change()}</span>{/if}
                    </div>
                  {/each}
                </div>
              {/if}
              {#if toolBlocks.length > 0}
                {#each toolBlocks as block}
                  <div class="flex items-center gap-2 text-xs">
                    <span class="{block.action === 'remove' ? 'text-(--error)' : 'text-(--warning)'}">{block.action === 'remove' ? 'B' : 'R'}</span>
                    <span class="text-(--text-primary)">{block.content}</span>
                    <span class="text-(--text-secondary)">— {block.transform}</span>
                  </div>
                {/each}
              {/if}
              {#if paramBlocks.length > 0}
                {#each paramBlocks as block}
                  <div class="flex items-center gap-2 text-xs">
                    <span class="text-(--warning)">C</span>
                    <span class="text-(--text-primary)">{block.field}: {block.content}</span>
                  </div>
                {/each}
              {/if}
              {#if rspPrograms.length > 0 || td.response_blocked_tools?.length}
                <div class="pt-1 border-t border-(--border)">
                  <span class="text-[10px] font-semibold uppercase tracking-wider text-(--text-secondary)">{m.audit_detail_response()}</span>
                  {#each rspPrograms as prog}
                    {@const isError = prog.outcome === 'errored'}
                    <div class="flex items-center gap-2 text-xs mt-1">
                      <span class="{isError ? 'text-(--warning)' : 'text-(--success)'}">{isError ? 'E' : 'T'}</span>
                      <span class="text-(--text-primary)">{prog.name}</span>
                      {#if isError}<span class="text-(--warning)">— {m.audit_detail_error_word()}</span>{:else if prog.outcome === 'passed'}<span class="text-(--text-secondary)">— {m.audit_detail_no_change()}</span>{/if}
                    </div>
                  {/each}
                  {#each td.response_blocked_tools ?? [] as bt}
                    <div class="flex items-center gap-2 text-xs mt-1">
                      <span class="text-(--error)">B</span>
                      <span class="text-(--text-primary)">{bt.name}</span>
                      <span class="text-(--text-secondary)">— {bt.description} {m.audit_detail_response_phase()}</span>
                    </div>
                  {/each}
                </div>
              {/if}
              {#if td.step_diffs?.length}
                <details class="pt-1 border-t border-(--border)">
                  <summary class="text-[10px] font-semibold uppercase tracking-wider text-(--accent) cursor-pointer select-none hover:text-(--accent-hover)">
                    {m.audit_detail_step_diffs({ count: td.step_diffs.length })}
                  </summary>
                  {#each td.step_diffs as sd}
                    <div class="mt-1.5">
                      <span class="text-[10px] font-semibold text-(--accent)">{sd.name}</span>
                      <pre class="mt-1 text-[11px] font-mono leading-relaxed whitespace-pre-wrap overflow-x-auto p-2 rounded-sm bg-(--bg-primary) border border-(--border)">{#each sd.diff.split('\n') as line}{#if line.startsWith('+')}<span class="text-(--success)">{line}</span>{:else if line.startsWith('-')}<span class="text-(--error)">{line}</span>{:else if line.startsWith('@@')}<span class="text-(--accent)">{line}</span>{:else}<span class="text-(--text-secondary)">{line}</span>{/if}
{/each}</pre>
                    </div>
                  {/each}
                </details>
              {/if}
            </div>
          {/if}
        {/if}
      </div>
    {/if}
  </div>
{/if}
