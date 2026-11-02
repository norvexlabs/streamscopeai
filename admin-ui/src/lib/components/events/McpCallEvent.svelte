<script lang="ts">
  import type { components } from '#lib/generated/api-types.js';
  import { formatArgValue, parseJsonObj } from './tool-helpers';
  import { page } from '$app/state';
  import { scopeHref } from '#lib/tenant.js';
  import { isSelfScoped } from '#lib/selfScoped.js';
  import { m as msg } from '#lib/paraglide/messages.js';

  let slug = $derived(page.params.slug ?? '');
  // Portal member plane has no tool-policy page — suppress the deep-link there.
  const selfScoped = isSelfScoped();

  type McpTransformDiff = components['schemas']['McpTransformDiff'];

  type McpCallEvent = {
    type: 'mcp_call';
    request_id: string;
    timestamp: string;
    method: string;
    tool_id?: string | null;
    prompt_id?: string | null;
    resource_uri?: string | null;
    virtual_server_slug?: string | null;
    upstream_server_name?: string | null;
    status_code?: number | null;
    error_code?: number | null;
    error_message?: string | null;
    latency_ms?: number | null;
    transform_diff?: McpTransformDiff | null;
    params?: unknown;
    result?: unknown;
    turn?: number;
  };

  interface Props {
    event: McpCallEvent;
  }

  let { event }: Props = $props();

  let isError = $derived(
    event.error_code != null || (event.status_code != null && event.status_code >= 400),
  );

  // Surface the policy rule id if a rule fired on this call. Mirrors the
  // chip the LLM tool-call event renders for `blocked.rule_id`.
  let ruleId = $derived(event.transform_diff?.policy_classification?.rule_id ?? null);

  // When this is an intercepted `sampling/createMessage`, render an inline
  // chip + a one-line summary so operators can see at a glance that the
  // gateway answered (not the agent). The matching `llm_audit` row lives
  // under the same `session_id` — operators can pivot via Session view.
  let samplingIntercept = $derived(event.transform_diff?.sampling_intercept ?? null);

  let target = $derived(event.tool_id || event.prompt_id || event.resource_uri || null);
  let formatLatency = $derived(
    event.latency_ms != null ? `${event.latency_ms} ms` : null,
  );
  let borderColor = $derived(isError ? 'var(--error-border)' : 'var(--tag-indigo-bg)');
  let headerColor = $derived(isError ? 'var(--error)' : 'var(--tag-indigo-text)');

  // Extract the user-facing arguments object — same shape as
  // ToolCallEvent.arguments for visual parity.
  let argsObj = $derived.by((): Record<string, unknown> | null => {
    const p = event.params;
    if (!p || typeof p !== 'object') return null;
    const params = p as Record<string, unknown>;
    if (event.method === 'tools/call'  && params.arguments && typeof params.arguments === 'object') {
      return params.arguments as Record<string, unknown>;
    }
    if (event.method === 'prompts/get' && params.arguments && typeof params.arguments === 'object') {
      return params.arguments as Record<string, unknown>;
    }
    if (event.method === 'resources/read' && typeof params.uri === 'string') {
      return { uri: params.uri };
    }
    return params;
  });

  // Concatenate text content from the response.
  let resultText = $derived.by((): string | null => {
    const r = event.result;
    if (!r || typeof r !== 'object') return null;
    const result = r as Record<string, unknown>;
    if (Array.isArray(result.content)) {
      const parts = (result.content as unknown[])
        .filter((c): c is Record<string, unknown> => typeof c === 'object' && c !== null)
        .map((c) => (typeof c.text === 'string' ? c.text : null))
        .filter((t): t is string => !!t);
      if (parts.length > 0) return parts.join('\n');
    }
    if (Array.isArray(result.contents)) {
      const parts = (result.contents as unknown[])
        .filter((c): c is Record<string, unknown> => typeof c === 'object' && c !== null)
        .map((c) => (typeof c.text === 'string' ? c.text : null))
        .filter((t): t is string => !!t);
      if (parts.length > 0) return parts.join('\n');
    }
    if (Array.isArray(result.messages)) {
      const parts: string[] = [];
      for (const m of result.messages as unknown[]) {
        if (typeof m === 'object' && m !== null) {
          const c = (m as Record<string, unknown>).content;
          if (typeof c === 'object' && c !== null && typeof (c as Record<string, unknown>).text === 'string') {
            parts.push((c as { text: string }).text);
          }
        }
      }
      if (parts.length > 0) return parts.join('\n');
    }
    return null;
  });
  let resultObj = $derived(resultText ? parseJsonObj(resultText) : null);

  // Hide expansion for list-style methods (`initialize`, `tools/list`, …)
  // — the response is a noisy capability dump, the request is empty.
  let isListLike = $derived(
    ['initialize', 'tools/list', 'resources/list', 'prompts/list'].includes(event.method),
  );
  let hasArgs   = $derived(argsObj && Object.keys(argsObj).length > 0);
  let hasResult = $derived(resultText != null || event.result != null);
  let canExpand = $derived(!isListLike && (hasArgs || hasResult));

  let expanded = $state(false);
</script>

<!-- MCP gateway call — sits between LLM turns at its actual timestamp.
     Collapsed by default: a single inline badge with method, target,
     latency, and chips. Click to expand and see the JSON-RPC request
     params + response result inline. Centred because the call is
     neither user-side nor assistant-side — it's the proxy dispatching
     on the agent's behalf. -->
<div class="flex justify-center">
  <div
    class="max-w-[85%] rounded-xl bg-(--bg-primary) border overflow-hidden w-full"
    style="border-color: {borderColor}"
  >
    <!-- Collapsed badge row — clickable when there's something to show. -->
    <button
      type="button"
      class="w-full flex items-center gap-2 px-4 py-2 text-left {canExpand ? 'hover:bg-(--bg-elevated) cursor-pointer transition-colors' : 'cursor-default'}"
      onclick={() => { if (canExpand) expanded = !expanded; }}
      disabled={!canExpand}
    >
      {#if canExpand}
        <span
          class="inline-block text-[10px] transition-transform {expanded ? 'rotate-90' : ''}"
          style="color: {headerColor}"
        >&#9654;</span>
      {:else}
        <span class="text-(--text-secondary) text-xs">·</span>
      {/if}
      <span style="color: {headerColor}">&#9874;</span>
      <span class="text-[10px] font-semibold uppercase tracking-wider" style="color: {headerColor}">MCP</span>
      <span class="font-mono text-xs px-1.5 py-0.5 rounded-sm bg-(--bg-secondary) text-(--text-primary)">
        {event.method}
      </span>
      {#if target}
        <span class="font-mono text-xs text-(--text-primary) truncate" title={target}>{target}</span>
      {/if}
      {#if ruleId}
        <a
          href={selfScoped ? undefined : scopeHref(slug, page.url.pathname, `/policy?rule_id=${encodeURIComponent(ruleId)}`)}
          onclick={(e) => e.stopPropagation()}
          title={msg.event_view_rule({ id: ruleId })}
          class="inline-flex items-center px-1.5 py-0.5 rounded-sm text-[10px] font-mono font-semibold text-(--warning) bg-(--warning-bg) border border-(--warning-border) hover:bg-(--warning-bg) transition-colors"
        >{ruleId}</a>
      {/if}
      {#if samplingIntercept?.kind === 'served'}
        <span
          class="inline-flex items-center px-1.5 py-0.5 rounded-sm text-[10px] font-semibold bg-(--accent)/15 text-(--accent) border border-(--accent)"
          title={msg.event_sampling_served_tooltip({ model: samplingIntercept.model ?? msg.event_no_model(), latency: samplingIntercept.latency_ms })}
        >{msg.event_intercepted()}</span>
      {:else if samplingIntercept?.kind === 'failed'}
        <span
          class="inline-flex items-center px-1.5 py-0.5 rounded-sm text-[10px] font-semibold bg-(--error-bg) text-(--error) border border-(--error)/30"
          title={msg.event_sampling_failed_tooltip({ reason: samplingIntercept.reason })}
        >{msg.event_intercept_failed()}</span>
      {/if}
      {#if isError}
        <span
          class="inline-flex items-center px-1.5 py-0.5 rounded-full text-[9px] font-semibold uppercase"
          style="color: var(--error); background: var(--error-bg)"
          title={event.error_message || ''}
        >
          {#if event.error_code}rpc {event.error_code}{:else}HTTP {event.status_code}{/if}
        </span>
      {/if}
      <span class="ml-auto flex items-center gap-2 text-[10px] text-(--text-secondary)">
        {#if event.virtual_server_slug}
          <span class="font-mono">{event.virtual_server_slug}</span>
        {/if}
        {#if event.upstream_server_name}
          <span class="font-mono opacity-70">→ {event.upstream_server_name}</span>
        {/if}
        {#if formatLatency}
          <span class="font-mono">{formatLatency}</span>
        {/if}
      </span>
    </button>

    <!-- Inline error message banner — same red bar pattern as ToolCallEvent's blocked banner. -->
    {#if event.error_message && !expanded}
      <div class="px-4 py-2 text-xs text-(--error) font-mono border-t border-(--error)/30 bg-(--error-bg)">
        {event.error_message}
      </div>
    {/if}

    <!-- Expanded detail panel — request args (table) + response (text/JSON). -->
    {#if expanded}
      <div class="border-t border-(--border) divide-y divide-(--border)">
        {#if hasArgs && argsObj}
          <div class="px-4 py-2.5">
            <p class="text-[10px] font-semibold uppercase tracking-wider text-(--text-secondary) mb-1">{msg.event_request()}</p>
            <table class="w-full">
              <tbody>
                {#each Object.entries(argsObj) as [key, val]}
                  <tr>
                    <td class="pr-3 py-0.5 text-[11px] font-mono text-(--text-secondary) whitespace-nowrap align-top">{key}</td>
                    <td class="py-0.5 text-[11px] font-mono text-(--text-primary) break-all">{formatArgValue(val)}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        {/if}
        {#if hasResult}
          <div class="px-4 py-2.5">
            <p class="text-[10px] font-semibold uppercase tracking-wider text-(--text-secondary) mb-1">{msg.event_response()}</p>
            {#if resultObj}
              <table class="w-full">
                <tbody>
                  {#each Object.entries(resultObj) as [key, val]}
                    <tr>
                      <td class="pr-3 py-0.5 text-[11px] font-mono text-(--text-secondary) whitespace-nowrap align-top">{key}</td>
                      <td class="py-0.5 text-[11px] font-mono text-(--text-primary) break-all">{formatArgValue(val)}</td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            {:else if resultText}
              <pre class="text-xs font-mono text-(--text-secondary) whitespace-pre-wrap max-h-64 overflow-y-auto">{resultText}</pre>
            {:else if event.result}
              <pre class="text-xs font-mono text-(--text-secondary) whitespace-pre-wrap max-h-64 overflow-y-auto">{JSON.stringify(event.result, null, 2)}</pre>
            {/if}
          </div>
        {/if}
        {#if event.error_message}
          <div class="px-4 py-2 text-xs text-(--error) font-mono bg-(--error-bg)">
            {event.error_message}
          </div>
        {/if}
      </div>
    {/if}
  </div>
</div>
