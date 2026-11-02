<script lang="ts">
  import type { components } from '#lib/generated/api-types.js';
  import { formatBytes, formatDuration } from '#lib/formatters.js';
  import { formatArgValue, parseArgs } from './tool-helpers';
  import { m } from '#lib/paraglide/messages.js';

  type WebAuditLogEntry = components['schemas']['WebAuditLogEntry'];
  type WebProviderResponse = components['schemas']['WebProviderResponse'];

  interface Props {
    /** Single web call (audit row). Mounted by both
        WebAuditDetail and the per-turn child panel in sessions. */
    row: WebAuditLogEntry;
    /** Default-collapse the response viewer to keep large bodies tidy. */
    defaultExpanded?: boolean;
  }

  let { row, defaultExpanded = false }: Props = $props();
  // Capture initial value into the local toggle so the user's later open
  // /close interaction isn't clobbered if the parent re-renders. Reading
  // `defaultExpanded` once via the local `initial` const avoids the
  // reactive-capture warning Svelte 5 emits for `$state(propA)`.
  // svelte-ignore state_referenced_locally
  let expanded = $state(defaultExpanded);

  // Accent / icon color for the request header — matches the amber tint
  // used by the existing web_* badge family in `lib/badges.ts`.
  const HEADER_COLOR = 'var(--warning)';
  const BORDER_COLOR = 'var(--warning-border)';

  let argsObj = $derived(parseArgs(row.request_args ?? null));

  // Discriminate between Stripped and Captured. The untagged enum:
  //   - Stripped variant: { stripped: true, size_bytes, reason }
  //   - Captured variant: any other JSON value (object, array, string …)
  // Branching on `.stripped === true` keeps the type guard simple — the
  // wire shape is the source of truth.
  function isStripped(
    v: WebProviderResponse | null | undefined,
  ): v is { stripped: true; size_bytes: number; reason: string } {
    return (
      v !== null
      && v !== undefined
      && typeof v === 'object'
      && 'stripped' in v
      && (v as { stripped?: unknown }).stripped === true
    );
  }

  let providerResponse = $derived<WebProviderResponse | null>(
    row.provider_response ?? null,
  );
  let stripped = $derived(isStripped(providerResponse));

  let isError = $derived(
    row.error_category != null
      || (row.status_code != null && row.status_code >= 400),
  );
</script>

<div
  class="rounded-xl bg-(--bg-primary) border overflow-hidden"
  style="border-color: {isError ? 'var(--error-border)' : BORDER_COLOR}"
>
  <!-- ── Request header + arguments ─────────────────────────────────── -->
  <div class="flex items-center gap-2 px-4 py-2.5 border-b border-(--border)">
    <span style="color: {isError ? 'var(--error)' : HEADER_COLOR}">&#128269;</span>
    <span
      class="text-xs font-semibold"
      style="color: {isError ? 'var(--error)' : HEADER_COLOR}"
    >
      {row.operation === 'fetch' ? 'web_fetch' : 'web'}
    </span>
    <span class="inline-flex items-center px-1.5 py-0.5 rounded-full text-[9px] font-medium uppercase border border-(--border) bg-(--bg-secondary) text-(--text-secondary)">
      {row.surface === 'substitution' ? 'substitution' : 'mcp'}
    </span>
    {#if row.backend}
      <span class="inline-flex items-center px-1.5 py-0.5 rounded-full text-[9px] font-medium uppercase border border-(--border) bg-(--bg-secondary) text-(--text-secondary)">
        {row.backend}
      </span>
    {/if}
    {#if isError}
      <span
        class="inline-flex items-center px-1.5 py-0.5 rounded-full text-[9px] font-semibold uppercase"
        style="color: var(--error); background: var(--error-bg)"
        title={row.error_detail ?? ''}
      >
        {row.error_category ?? m.event_error()}
      </span>
    {/if}
    <span class="ml-auto text-[10px] font-mono text-(--text-secondary)">
      {row.result_count ?? 0} {row.operation === 'fetch' ? m.event_doc() : m.event_hits()}
      {#if row.upstream_latency_ms != null}
        · {formatDuration(row.upstream_latency_ms)}
      {/if}
    </span>
  </div>

  <div class="px-4 py-2.5">
    {#if argsObj}
      <table class="w-full">
        <tbody>
          {#each Object.entries(argsObj) as [key, val]}
            <tr>
              <td class="pr-3 py-0.5 text-[11px] font-mono text-(--text-secondary) whitespace-nowrap align-top">
                {key}
              </td>
              <td class="py-0.5 text-[11px] font-mono text-(--text-primary) break-all">
                {formatArgValue(val)}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {:else if row.query}
      <div class="text-[11px] font-mono text-(--text-primary) break-all">
        {row.query}
      </div>
    {:else}
      <div class="text-[11px] text-(--text-secondary) italic">{m.event_no_arguments()}</div>
    {/if}
  </div>

  <!-- ── Response (collapsible) ─────────────────────────────────────── -->
  {#if providerResponse !== null || row.response_summary}
    <div class="border-t border-(--border)">
      <button
        type="button"
        onclick={() => (expanded = !expanded)}
        class="w-full flex items-center gap-2 px-4 py-2 text-left text-[11px] text-(--text-secondary) hover:bg-(--bg-elevated) transition-colors"
      >
        <span class="inline-block transition-transform {expanded ? 'rotate-90' : ''}">&#9654;</span>
        <span class="font-semibold uppercase tracking-wider text-[10px]">{m.event_response()}</span>
        {#if stripped && providerResponse}
          {@const s = providerResponse as { stripped: true; size_bytes: number; reason: string }}
          <span
            class="ml-2 inline-flex items-center px-1.5 py-0.5 rounded-full text-[9px] font-medium border bg-(--warning)/10 border-(--warning)/30 text-(--warning)"
            title={m.event_provider_response_stripped_tooltip()}
          >
            {m.event_stripped()} · {formatBytes(s.size_bytes)}
          </span>
        {:else if row.bytes_in != null}
          <span class="ml-2 text-[10px] text-(--text-secondary) font-mono">
            {formatBytes(row.bytes_in)}
          </span>
        {/if}
      </button>

      {#if expanded}
        {#if stripped && providerResponse}
          {@const s = providerResponse as { stripped: true; size_bytes: number; reason: string }}
          <div class="px-4 py-3 bg-(--warning)/10 border-t border-(--warning)/30 text-[11px] text-(--text-primary)">
            <span class="font-semibold text-(--warning)">{m.event_response_oversized()}</span>
            <span class="text-(--text-secondary)">
              {m.event_stripped_at({ size: formatBytes(s.size_bytes), reason: s.reason })}
            </span>
            <div class="mt-1 text-[10px] text-(--text-secondary)">
              {m.event_raise_cap_before()}<code class="font-mono">audit_provider_response_max_kb</code>{m.event_raise_cap_after()}
            </div>
          </div>
        {:else if providerResponse}
          <pre class="px-4 py-3 text-[11px] font-mono text-(--text-primary) whitespace-pre-wrap break-all bg-(--bg-primary)/40 max-h-96 overflow-auto">{JSON.stringify(providerResponse, null, 2)}</pre>
        {:else if row.response_summary}
          <pre class="px-4 py-3 text-[11px] font-mono text-(--text-primary) whitespace-pre-wrap break-all bg-(--bg-primary)/40 max-h-96 overflow-auto">{JSON.stringify(row.response_summary, null, 2)}</pre>
        {/if}

        <!-- URL-filter verdicts: a search with one or more denied hits, or
             a fetch that ran the chain. Mirrors the per-tool result table
             pattern from ToolResultEvent. -->
        {#if row.url_results}
          {@const verdicts = Array.isArray(row.url_results) ? row.url_results : []}
          {#if verdicts.length > 0}
            <div class="px-4 py-3 border-t border-(--border) space-y-1">
              <span class="block text-[10px] font-semibold uppercase tracking-wider text-(--text-secondary)">
                {m.event_url_filter_verdicts({ count: verdicts.length })}
              </span>
              {#each verdicts as v}
                {@const verdict = (v as { verdict?: string }).verdict ?? 'unknown'}
                {@const url = (v as { url?: string }).url ?? ''}
                {@const reason = (v as { reason?: string | null }).reason ?? null}
                <div class="flex items-start gap-2 text-[11px]">
                  <span
                    class="inline-flex items-center px-1.5 py-0.5 rounded-sm text-[9px] font-medium uppercase {verdict === 'allow' ? 'bg-(--success)/10 text-(--success) border border-(--success)/30' : 'bg-(--error)/10 text-(--error) border border-(--error)/30'}"
                  >
                    {verdict}
                  </span>
                  <span class="font-mono text-(--text-primary) break-all flex-1">{url}</span>
                  {#if reason}
                    <span class="text-(--text-secondary) text-[10px]">{reason}</span>
                  {/if}
                </div>
              {/each}
            </div>
          {/if}
        {/if}
      {/if}
    </div>
  {/if}
</div>
