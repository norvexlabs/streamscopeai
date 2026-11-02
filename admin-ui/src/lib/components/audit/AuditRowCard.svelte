<script lang="ts">
  // Unified row-card for the audit list. One shape for every kind — header
  // strip (chevron, kind chip, time, user, latency, status) on top, a
  // kind-specific body line below. Used by the `/audit?kind=all` interleave
  // view so LLM / MCP / Web / A2A rows render with consistent chrome and
  // chronological sort isn't broken by per-kind table headers.
  //
  // Expansion is owned by the parent — AuditRowCard signals via onToggle
  // and lets the page mount the appropriate detail component below.

  import type { AuditLogRow } from '#lib/api-types.js';
  import { formatDuration, formatTokens, formatCost, formatDateTime, formatFinishReason, finishReasonColor, formatErrorCategory, errorCategoryColor, formatTaskState } from '#lib/formatters.js';
  import TagBadge from '#lib/components/TagBadge.svelte';
  import Badge from '#lib/components/Badge.svelte';
  import { m } from '#lib/paraglide/messages.js';
  import { ATTENTION_BADGE_CODES, dedupeBadgesByCode } from '#lib/badges.js';
  import { auditKindColor, auditKindLabel, type AuditKind } from '#lib/colormaps/audit_kinds.js';

  const NIL_UUID = '00000000-0000-0000-0000-000000000000';

  interface Props {
    row: AuditLogRow;
    expanded: boolean;
    onToggle: () => void;
    /**
     * Cross-user pivot — filter the list to this user. Omitted in the portal
     * member plane (the row is always the caller), where the user identity
     * renders as plain text instead of a pivot button.
     */
    onFilterUser?: (email: string) => void;
    /**
     * Whether to render the LLM/MCP/Web chip in the header. The page passes
     * `false` when the operator has narrowed to a single kind (the chip is
     * redundant) and `true` for the interleaved `kind=all` view.
     */
    showKindChip?: boolean;
  }

  let { row, expanded, onToggle, onFilterUser, showKindChip = true }: Props = $props();

  const kind = $derived(row.kind as AuditKind);
  const latencyMs = $derived(row.latency_total_ms ?? null);
  // Surface the security/policy/failure badges (guardrail, blocked tool, SSRF,
  // …) on the collapsed row so a flagged record is visible without expanding.
  // The full badge set still renders in the kind-specific detail below.
  const attentionBadges = $derived(
    dedupeBadgesByCode((row.badges ?? []).filter((b) => ATTENTION_BADGE_CODES.has(b.code)))
  );
</script>

<div
  class="border-b border-(--border) hover:bg-(--bg-elevated) transition-colors cursor-pointer"
  onclick={onToggle}
  role="button"
  tabindex="0"
  aria-expanded={expanded}
  onkeydown={(e) => { if ((e.key === 'Enter' || e.key === ' ') && e.target === e.currentTarget) { e.preventDefault(); onToggle(); } }}
>
  <!-- Header strip: chevron + kind chip + time + user + latency + status -->
  <div class="flex items-center gap-3 px-4 py-2.5 text-sm">
    <span class="text-(--text-secondary) w-4 inline-block transition-transform {expanded ? 'rotate-90' : ''}">&#9654;</span>
    {#if showKindChip}
      <TagBadge color={auditKindColor[kind]} class="uppercase tracking-wider">
        {auditKindLabel(kind)}
      </TagBadge>
    {/if}
    <span class="text-(--text-secondary) whitespace-nowrap font-mono text-xs">
      {formatDateTime(row.timestamp)}
    </span>
    <div class="flex-1 min-w-0">
      {#if !row.user_id || row.user_id === NIL_UUID}
        <span class="text-sm text-(--text-secondary)">&mdash;</span>
      {:else if onFilterUser}
        <button
          onclick={(e) => { e.stopPropagation(); onFilterUser?.(row.user_email || ''); }}
          class="text-sm text-(--accent) hover:text-(--accent-hover) transition-colors truncate max-w-50 block text-left"
          title={row.user_email || row.user_id}
        >
          {row.user_email || row.user_id?.substring(0, 8) + '...'}
        </button>
      {:else}
        <!-- Self-scoped: no cross-user pivot, render identity as plain text. -->
        <span class="text-sm text-(--text-secondary) truncate max-w-50 block" title={row.user_email || row.user_id}>
          {row.user_email || row.user_id?.substring(0, 8) + '...'}
        </span>
      {/if}
    </div>
    {#if attentionBadges.length > 0}
      <div class="flex items-center gap-1.5 shrink-0">
        {#each attentionBadges as badge (badge.code)}
          <Badge {badge} />
        {/each}
      </div>
    {/if}
    <span class="text-right font-mono text-sm text-(--text-primary) whitespace-nowrap min-w-15">
      {#if latencyMs == null}--{:else if latencyMs === 0}&lt;1ms{:else}{formatDuration(latencyMs)}{/if}
    </span>
    <!-- Status pill — LLM uses finish_reason + optional error chip; MCP/Web collapses to one pill. -->
    {#if row.kind === 'llm'}
      <div class="flex flex-wrap items-center gap-1.5">
        <span
          class="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium border"
          style="color: {finishReasonColor(row.finish_reason)}; border-color: color-mix(in srgb, {finishReasonColor(row.finish_reason)} 19%, transparent); background-color: color-mix(in srgb, {finishReasonColor(row.finish_reason)} 6%, transparent)"
          title="{m.audit_row_raw_label()} {row.finish_reason}"
        >
          {row.finish_reason_display || formatFinishReason(row.finish_reason)}
        </span>
        {#if row.error_category}
          {@const errColor = errorCategoryColor(row.error_category)}
          <span
            class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium border"
            style="color: {errColor}; border-color: color-mix(in srgb, {errColor} 19%, transparent); background-color: color-mix(in srgb, {errColor} 6%, transparent)"
            title={row.error_detail || ''}
          >
            <span class="w-1.5 h-1.5 rounded-full" style="background-color: {errColor}"></span>
            {formatErrorCategory(row.error_category)}{#if row.status_code} {row.status_code}{/if}
          </span>
        {/if}
      </div>
    {:else if row.kind === 'mcp' || row.kind === 'a2a'}
      {#if row.error_code != null || (row.status_code != null && row.status_code >= 400)}
        <span class="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium border border-(--error) bg-(--error)/10 text-(--error)" title={row.error_message || ''}>
          {#if row.error_code}rpc {row.error_code}{:else}HTTP {row.status_code}{/if}
        </span>
      {:else}
        <span class="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium border border-(--success) bg-(--success)/10 text-(--success)">ok</span>
      {/if}
    {:else}
      {#if row.error_category != null || (row.status_code != null && row.status_code >= 400)}
        <span class="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium border border-(--error) bg-(--error)/10 text-(--error)" title={row.error_detail || ''}>
          {row.error_category ?? `HTTP ${row.status_code}`}
        </span>
      {:else}
        <span class="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium border border-(--success) bg-(--success)/10 text-(--success)">ok</span>
      {/if}
    {/if}
  </div>
  <!-- Body line: kind-specific summary -->
  <div class="pl-12 pr-4 pb-2.5 text-xs text-(--text-secondary) flex items-center gap-2 flex-wrap">
    {#if row.kind === 'llm'}
      <span class="font-mono text-(--text-primary)">{row.model_requested || '--'}</span>
      {#if row.model_used && row.model_used !== row.model_requested}
        <span class="font-mono">&rarr; {row.model_used}</span>
      {/if}
      {#if row.stream}
        <span class="text-[9px] px-1 py-0.5 rounded-sm bg-(--accent)/10 text-(--accent) font-medium uppercase">sse</span>
      {/if}
      <span>&middot;</span>
      <span class="font-mono">{formatTokens((row.prompt_tokens || 0) + (row.completion_tokens || 0))} tok ({formatTokens(row.prompt_tokens)}/{formatTokens(row.completion_tokens)})</span>
      <span>&middot;</span>
      <!-- The row's own currency, not the tenant's current one: an audit row
           records what the ledger said when it was written. -->
      <span class="font-mono">{formatCost(row.cost, row.cost_currency)}</span>
    {:else if row.kind === 'mcp'}
      {#if row.virtual_server_slug}
        <span class="font-mono text-(--text-primary)">{row.virtual_server_slug}</span>
        <span>&middot;</span>
      {/if}
      <span class="font-mono px-1.5 py-0.5 rounded-sm bg-(--bg-secondary) text-(--text-primary)">{row.method}</span>
      {#if row.tool_id || row.prompt_id || row.resource_uri}
        <span>&middot;</span>
        <span class="font-mono text-(--text-primary)">{row.tool_id || row.prompt_id || row.resource_uri}</span>
      {/if}
    {:else if row.kind === 'a2a'}
      {#if row.agent_slug}
        <!-- The direction: the row's caller (user, shown in the header) is
             talking TO this agent. -->
        <span class="text-(--text-tertiary)">&rarr;</span>
        <span class="font-mono text-(--text-primary)">{row.agent_slug}</span>
        <span>&middot;</span>
      {/if}
      <span class="font-mono px-1.5 py-0.5 rounded-sm bg-(--bg-secondary) text-(--text-primary)">{row.method}</span>
      {#if row.task_state}
        <span>&middot;</span>
        <span class="font-mono text-(--text-primary)">{formatTaskState(row.task_state)}</span>
      {/if}
    {:else}
      <span class="inline-flex items-center px-1.5 py-0.5 rounded-full border border-(--border) bg-(--bg-secondary) text-(--text-secondary)">
        {row.surface}
      </span>
      <span class="font-mono px-1.5 py-0.5 rounded-sm bg-(--bg-secondary) text-(--text-primary)">
        {row.operation}
      </span>
      {#if row.query}
        <span class="font-mono text-(--text-primary) truncate max-w-100" title={row.query}>{row.query}</span>
      {/if}
      {#if row.operation === 'search' && (row.result_count ?? 0) > 0}
        <span>&middot;</span>
        <span class="font-mono">{row.result_count} {m.audit_row_hits()}</span>
      {/if}
    {/if}
  </div>
</div>
