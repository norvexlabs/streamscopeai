<script lang="ts">
  // Per-invocation expansion body for LLM rows in the /tool-calls feed.
  // The audit page renders a per-turn `<LlmAuditDetail>` (the whole LLM
  // exchange); this is the narrower per-call view — one ToolCall paired
  // with one ToolResult, plus jump links and the redaction banner.

  import type { ToolInvocation } from '#lib/api-types.js';
  import ToolCallEvent from '#lib/components/events/ToolCallEvent.svelte';
  import ToolResultEvent from '#lib/components/events/ToolResultEvent.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import { page } from '$app/state';
  import { thref } from '#lib/tenant.js';
  import { auditHref } from '#lib/deeplinks.js';

  let slug = $derived(page.params.slug ?? '');

  interface Props {
    item: ToolInvocation;
  }

  let { item }: Props = $props();
</script>

<div class="space-y-3">
  <!-- Jump links -->
  <div class="flex items-center gap-3 text-xs">
    <a
      href={thref(slug, `/sessions/${item.session_id}`)}
      class="text-(--accent) hover:underline inline-flex items-center gap-1"
    >
      <Icon name="externalLink" size="sm" color="var(--accent)" />
      Jump to session
    </a>
    <a
      href={thref(slug, auditHref({ kind: 'llm', request_id: item.call_request_id }))}
      class="text-(--accent) hover:underline inline-flex items-center gap-1"
    >
      <Icon name="externalLink" size="sm" color="var(--accent)" />
      Jump to audit
    </a>
  </div>

  <!-- Redaction diff -->
  {#if item.redaction}
    <div class="rounded-lg border border-(--warning-border) bg-(--warning-bg) px-3 py-2 text-[11px]">
      <div class="font-semibold text-(--warning) mb-1">Redacted — {item.redaction.rule_name}</div>
      <div class="text-(--text-secondary) mb-1">{item.redaction.reason}</div>
      <div class="font-mono text-(--error)/80"><span class="text-(--text-secondary)">was:</span> {item.redaction.original_content.slice(0, 240)}{item.redaction.original_content.length > 240 ? '…' : ''}</div>
      <div class="font-mono text-(--success)/80"><span class="text-(--text-secondary)">now:</span> {item.redaction.redacted_content.slice(0, 240)}{item.redaction.redacted_content.length > 240 ? '…' : ''}</div>
    </div>
  {/if}

  <!-- Canonical call event — the backend always sets this to a `tool_call`
       variant of ConversationEvent. The rule-identity banner for blocked
       calls is rendered inside the component from `call_event.blocked`. -->
  {#if item.call_event.type === 'tool_call'}
    <ToolCallEvent event={item.call_event} />
  {/if}

  <!-- Canonical result event (paired) — absent when the call was blocked,
       since no result exists. The rule banner inside `ToolCallEvent` already
       explains the absence, so no fallback is needed here. -->
  {#if item.result_event && item.result_event.type === 'tool_result'}
    <ToolResultEvent event={item.result_event} defaultExpanded={true} />
  {/if}
</div>
