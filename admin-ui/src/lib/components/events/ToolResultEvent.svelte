<script lang="ts">
  import { parseJsonObj, formatArgValue } from './tool-helpers';
  import { m } from '#lib/paraglide/messages.js';
  import { guardrailsTone, type GuardrailInfo } from '#lib/badges.js';
  import GuardrailBanner from './GuardrailBanner.svelte';
  import GuardrailPill from './GuardrailPill.svelte';

  type RedactionInfo = {
    tool_use_id: string;
    tool_name?: string | null;
    original_content: string;
    redacted_content: string;
    rule_name: string;
    reason: string;
    rule_id: string;
  };

  type ToolResultEvent = {
    type: 'tool_result';
    tool_call_id: string;
    content: string;
    is_new?: boolean;
    turn?: number;
    redacted?: RedactionInfo | null;
    guardrails?: GuardrailInfo[];
  };

  interface Props {
    event: ToolResultEvent;
    showPrior?: boolean;
    defaultExpanded?: boolean;
  }

  let { event, showPrior = true, defaultExpanded = false }: Props = $props();

  // Snapshot `defaultExpanded` at mount time only. Making this a reactive
  // `$effect` would reset the user's manual expand/collapse every time the
  // parent list re-renders — surprising and unwanted.
  // svelte-ignore state_referenced_locally
  let expanded = $state(defaultExpanded);
  let showOriginal = $state(false);
  let resultObj = $derived(parseJsonObj(event.content));
  let isRedacted = $derived(!!event.redacted);
  let guardrails = $derived(event.guardrails ?? []);
  let borderColor = $derived(
    guardrails.length > 0
      ? `var(--${guardrailsTone(guardrails)})`
      : isRedacted
        ? 'var(--warning)'
        : 'var(--tag-cyan-bg)',
  );
  let headerColor = $derived(isRedacted ? 'var(--warning)' : 'var(--tag-cyan-text)');
</script>

{#if !(event.is_new === false && !showPrior)}
  <div class="flex justify-start {event.is_new === false ? 'opacity-40' : ''}">
    <div
      class="max-w-[85%] rounded-xl bg-(--bg-primary) border overflow-hidden"
      style="border-color: {borderColor}"
    >
      <button
        type="button"
        onclick={() => (expanded = !expanded)}
        class="w-full flex items-center gap-2 px-4 py-2.5 text-left hover:bg-(--bg-elevated) transition-colors"
      >
        <span
          class="inline-block text-[10px] transition-transform {expanded ? 'rotate-90' : ''}"
          style="color: {headerColor}"
        >&#9654;</span>
        <span style="color: {headerColor}">&#8626;</span>
        <span class="text-[10px] font-semibold uppercase tracking-wider" style="color: {headerColor}">{m.event_result()}</span>
        {#if isRedacted}
          <span
            class="inline-flex items-center px-1.5 py-0.5 rounded-full text-[9px] font-semibold uppercase"
            style="color: var(--warning); background: var(--warning-bg)"
          >{m.event_redacted()}</span>
        {/if}
        {#each guardrails as guardrail}
          <GuardrailPill {guardrail} />
        {/each}
        {#if event.tool_call_id}
          <span class="text-[10px] font-mono text-(--text-secondary)">{event.tool_call_id}</span>
        {/if}
        <span class="text-[10px] text-(--text-secondary)">{m.event_n_chars({ count: (event.content ?? '').length })}</span>
        {#if event.is_new === false}
          <span class="text-[9px] px-1.5 py-0.5 rounded-sm bg-(--bg-secondary) text-(--text-secondary) font-medium">{m.event_prior()}</span>
        {/if}
      </button>
      {#if expanded}
        <div class="px-4 pb-3 max-h-64 overflow-y-auto">
          {#if isRedacted && showOriginal && event.redacted}
            <pre class="text-xs font-mono text-(--error)/80 whitespace-pre-wrap">{event.redacted.original_content}</pre>
          {:else if resultObj}
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
          {:else}
            <pre class="text-xs font-mono text-(--text-secondary) whitespace-pre-wrap">{event.content}</pre>
          {/if}
        </div>
      {/if}
      {#if event.redacted}
        <div class="flex items-start gap-2 px-4 py-2 border-t border-(--warning-border) bg-(--warning-bg)">
          <span class="inline-flex items-center px-1.5 py-0.5 rounded-sm text-[10px] font-mono font-semibold text-(--warning) bg-(--warning-bg) border border-(--warning-border)">{event.redacted.rule_id}</span>
          <div class="flex-1 text-[11px] leading-snug">
            <span class="font-semibold text-(--warning)">{event.redacted.rule_name || m.event_redacted_by_policy()}</span>
            <span class="text-(--warning)/80"> {m.event_result_rewritten()}</span>
            {#if event.redacted.reason}
              <div class="text-[10px] text-(--warning)/80 mt-0.5 wrap-break-word">{event.redacted.reason}</div>
            {/if}
          </div>
          <button
            type="button"
            onclick={(e) => { e.stopPropagation(); showOriginal = !showOriginal; expanded = true; }}
            class="text-[9px] uppercase tracking-wider text-(--warning)/80 hover:text-(--warning) font-semibold border border-(--warning-border) px-1.5 py-0.5 rounded-sm"
            title={m.event_toggle_redacted_original()}
          >{showOriginal ? m.event_show_redacted() : m.event_show_original()}</button>
        </div>
      {/if}
      {#each guardrails as guardrail}
        <GuardrailBanner {guardrail} />
      {/each}
    </div>
  </div>
{/if}
