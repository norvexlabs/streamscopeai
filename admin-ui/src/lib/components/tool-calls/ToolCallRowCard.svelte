<script lang="ts">
  // Unified row-card for the /tool-calls list. One shape across every kind —
  // header strip (chevron, optional kind chip, time, user, latency, status)
  // on top, a kind-specific body line below. Mirrors AuditRowCard, but the
  // body vocabulary speaks tool-call-per-row rather than turn-per-row.
  //
  // Expansion is owned by the parent — this card signals via onToggle and
  // the page mounts the matching detail component below.

  import type { ToolCallRow } from '#lib/api-types.js';
  import { formatDuration, formatDateTime } from '#lib/formatters.js';
  import TagBadge from '#lib/components/TagBadge.svelte';
  import { auditKindColor, auditKindLabel, type AuditKind } from '#lib/colormaps/audit_kinds.js';

  const NIL_UUID = '00000000-0000-0000-0000-000000000000';

  interface Props {
    row: ToolCallRow;
    expanded: boolean;
    onToggle: () => void;
    onFilterUser: (email: string) => void;
    /**
     * Whether to show the LLM/MCP/Web chip in the header. The page passes
     * `false` when the operator has narrowed to a single kind (the chip is
     * redundant) and `true` for the interleaved `kind=all` view.
     */
    showKindChip?: boolean;
  }

  let { row, expanded, onToggle, onFilterUser, showKindChip = true }: Props = $props();

  const kind = $derived(row.kind as AuditKind);
  const latencyMs = $derived(row.latency_total_ms ?? null);

  // Pair the per-outcome styling with the tag palette so blocked / redacted /
  // args_modified all render through the same shared `<span>` skeleton.
  type OutcomeStyle = { label: string; bg: string; fg: string; border: string };
  function outcomeStyle(o: string): OutcomeStyle {
    switch (o) {
      case 'ok':
        return { label: 'ok', bg: 'var(--success-bg)', fg: 'var(--success)', border: 'var(--success-border)' };
      case 'blocked_request':
        return { label: 'blocked (req)', bg: 'var(--error-bg)', fg: 'var(--error)', border: 'var(--error-border)' };
      case 'blocked_response':
        return { label: 'blocked (resp)', bg: 'var(--error-bg)', fg: 'var(--error)', border: 'var(--error-border)' };
      case 'redacted':
        return { label: 'redacted', bg: 'var(--warning-bg)', fg: 'var(--warning)', border: 'var(--warning-border)' };
      case 'args_modified':
        return { label: 'args modified', bg: 'var(--tag-teal-bg)', fg: 'var(--tag-teal-text)', border: 'var(--tag-teal-bg)' };
      default:
        return { label: o, bg: 'var(--bg-elevated)', fg: 'var(--text-secondary)', border: 'var(--border)' };
    }
  }

  function riskFg(r: string): string {
    switch (r) {
      case 'danger': return 'var(--error)';
      case 'caution': return 'var(--warning)';
      case 'blocked': return 'var(--error)';
      case 'unknown': return 'var(--text-secondary)';
      default: return 'var(--success)';
    }
  }

  // MCP method → vocabulary label + accent.
  function methodKind(m: string): { label: string; color: string } {
    if (m === 'tools/call') return { label: 'tool', color: 'var(--accent)' };
    if (m === 'resources/read') return { label: 'resource', color: 'var(--tag-violet-text)' };
    if (m === 'prompts/get') return { label: 'prompt', color: 'var(--tag-teal-text)' };
    return { label: m, color: 'var(--text-secondary)' };
  }
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
      {#if row.kind === 'llm'}
        {#if row.user_email}
          <button
            onclick={(e) => { e.stopPropagation(); onFilterUser(row.user_email ?? ''); }}
            class="text-sm text-(--accent) hover:text-(--accent-hover) transition-colors truncate max-w-50 block text-left"
            title={row.user_email}
          >
            {row.user_email}
          </button>
        {:else}
          <span class="text-sm text-(--text-secondary) truncate max-w-50 block" title={row.user_display}>
            {row.user_display || '—'}
          </span>
        {/if}
      {:else if !row.user_id || row.user_id === NIL_UUID}
        <span class="text-sm text-(--text-secondary)">&mdash;</span>
      {:else}
        <button
          onclick={(e) => { e.stopPropagation(); onFilterUser(row.user_email ?? ''); }}
          class="text-sm text-(--accent) hover:text-(--accent-hover) transition-colors truncate max-w-50 block text-left"
          title={row.user_email || row.user_id}
        >
          {row.user_email || row.user_id?.substring(0, 8) + '...'}
        </button>
      {/if}
    </div>
    <span class="text-right font-mono text-sm text-(--text-primary) whitespace-nowrap min-w-15">
      {#if latencyMs == null}--{:else if latencyMs === 0}&lt;1ms{:else}{formatDuration(latencyMs)}{/if}
    </span>
    <!-- Status pill — LLM uses outcomes + optional risk; MCP/Web collapse to one pill. -->
    {#if row.kind === 'llm'}
      <div class="flex flex-wrap items-center gap-1.5">
        {#each row.outcomes as o (o)}
          {@const s = outcomeStyle(o)}
          <span
            class="inline-flex items-center px-1.5 py-0.5 rounded-full text-[10px] font-semibold uppercase border"
            style="color: {s.fg}; border-color: {s.border}; background: {s.bg}"
          >{s.label}</span>
        {/each}
        {#if row.risk_level && row.risk_level !== 'safe' && row.risk_level !== 'blocked'}
          {@const fg = riskFg(row.risk_level)}
          <span
            class="inline-flex items-center px-1.5 py-0.5 rounded-full text-[10px] font-semibold uppercase"
            style="color: {fg}; background: color-mix(in srgb, {fg} 10%, transparent)"
            title={row.risk_title || ''}
          >{row.risk_level}</span>
        {/if}
      </div>
    {:else if row.kind === 'mcp'}
      {#if row.error_code != null || (row.status_code != null && row.status_code >= 400)}
        <span class="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium border border-(--error-border) bg-(--error-bg) text-(--error-text)" title={row.error_message || ''}>
          {#if row.error_code}rpc {row.error_code}{:else}HTTP {row.status_code}{/if}
        </span>
      {:else}
        <span class="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium border border-(--success-border) bg-(--success-bg) text-(--success-text)">ok</span>
      {/if}
    {:else}
      {#if row.error_category != null || (row.status_code != null && row.status_code >= 400)}
        <span class="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium border border-(--error-border) bg-(--error-bg) text-(--error-text)" title={row.error_detail || ''}>
          {row.error_category ?? `HTTP ${row.status_code}`}
        </span>
      {:else}
        <span class="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium border border-(--success-border) bg-(--success-bg) text-(--success-text)">ok</span>
      {/if}
    {/if}
  </div>
  <!-- Body line: kind-specific summary -->
  <div class="pl-12 pr-4 pb-2.5 text-xs text-(--text-secondary) flex items-center gap-2 flex-wrap">
    {#if row.kind === 'llm'}
      <span class="text-(--text-secondary)">&#9881;</span>
      <span class="font-mono text-(--text-primary)">{row.tool_name}</span>
      {#if row.argument_summary}
        <span>&middot;</span>
        <span class="font-mono truncate max-w-xl" title={row.argument_summary}>{row.argument_summary}</span>
      {/if}
    {:else if row.kind === 'mcp'}
      {@const mk = methodKind(row.method)}
      {#if row.virtual_server_slug}
        <span class="font-mono text-(--text-primary)">{row.virtual_server_slug}</span>
        <span>&middot;</span>
      {/if}
      <span
        class="inline-flex items-center px-1.5 py-0.5 rounded-full text-[10px] font-medium border"
        style="border-color: color-mix(in srgb, {mk.color} 25%, transparent); color: {mk.color}; background-color: color-mix(in srgb, {mk.color} 8%, transparent);"
      >{mk.label}</span>
      {#if row.tool_id || row.prompt_id || row.resource_uri}
        <span class="font-mono text-(--text-primary) truncate max-w-xl">
          {row.tool_id || row.prompt_id || row.resource_uri}
        </span>
      {/if}
    {:else}
      <span class="inline-flex items-center px-1.5 py-0.5 rounded-full border border-(--border) bg-(--bg-secondary) text-(--text-secondary)">
        {row.surface}
      </span>
      <span class="font-mono px-1.5 py-0.5 rounded-sm bg-(--bg-secondary) text-(--text-primary)">
        {row.operation}
      </span>
      {#if row.query}
        <span class="font-mono text-(--text-primary) truncate max-w-xl" title={row.query}>{row.query}</span>
      {/if}
      {#if row.operation === 'search' && (row.result_count ?? 0) > 0}
        <span>&middot;</span>
        <span class="font-mono">{row.result_count} hits</span>
      {/if}
    {/if}
  </div>
</div>
