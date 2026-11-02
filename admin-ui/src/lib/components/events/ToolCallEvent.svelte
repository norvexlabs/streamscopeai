<script lang="ts">
  import { parseArgs, formatArgValue, formatArgs } from './tool-helpers';
  import { page } from '$app/state';
  import { scopeHref } from '#lib/tenant.js';
  import { isSelfScoped } from '#lib/selfScoped.js';
  import Icon from '#lib/components/Icon.svelte';
  import { m as msg } from '#lib/paraglide/messages.js';

  let slug = $derived(page.params.slug ?? '');
  // Portal member plane has no tool-policy page — suppress the deep-link there
  // (render the rule id as plain text via an href-less anchor).
  const selfScoped = isSelfScoped();

  type ToolCallBlock = {
    rule_id?: string | null;
    rule_title?: string | null;
    reason: string;
    phase: string;
  };

  type ToolArgModification = {
    field: string;
    original: unknown;
    effective: unknown;
    rule_id: string;
  };

  type InterceptionInfo = {
    rule_id: string;
    rule_title?: string | null;
    replaced_name: string;
    server_type?: string | null;
  };

  type ToolCallEvent = {
    type: 'tool_call';
    name: string;
    id: string;
    arguments: unknown;
    risk_level?: string | null;
    risk_description?: string | null;
    is_new?: boolean;
    turn?: number;
    blocked?: ToolCallBlock | null;
    intercepted?: InterceptionInfo | null;
    modifications?: ToolArgModification[] | null;
  };

  interface Props {
    event: ToolCallEvent;
    showPrior?: boolean;
  }

  let { event, showPrior = true }: Props = $props();

  let argsObj = $derived(parseArgs(event.arguments));
  let isDanger = $derived(event.risk_level === 'danger');
  let isBlocked = $derived(!!event.blocked);
  let isIntercepted = $derived(!!event.intercepted);
  let modsByField = $derived.by(() => {
    const out = new Map<string, ToolArgModification>();
    for (const m of event.modifications ?? []) {
      out.set(m.field, m);
    }
    return out;
  });
  // A blocked call always overrides the border color to red; the banner
  // below makes the reason explicit.
  let borderColor = $derived(
    isBlocked
      ? 'var(--error)'
      : isDanger
        ? 'var(--error)'
        : isIntercepted
          ? 'var(--accent)'
          : 'var(--tag-orange-bg)',
  );
  let headerColor = $derived(
    isBlocked || isDanger
      ? 'var(--error)'
      : isIntercepted
        ? 'var(--accent)'
        : 'var(--tag-orange-text)',
  );
</script>

{#if !(event.is_new === false && !showPrior)}
  <div class="flex justify-end {event.is_new === false ? 'opacity-40' : ''}">
    <div
      class="max-w-[85%] rounded-xl bg-(--bg-primary) border overflow-hidden"
      style="border-color: {borderColor}"
    >
      <div class="flex items-center gap-2 px-4 py-2.5 border-b border-(--border)">
        <span style="color: {headerColor}">&#9881;</span>
        <span class="text-xs font-semibold" style="color: {headerColor}">{event.name}</span>
        {#if isBlocked}
          <span
            class="inline-flex items-center px-1.5 py-0.5 rounded-full text-[9px] font-semibold uppercase"
            style="color: var(--error); background: var(--error-bg)"
          >{msg.event_blocked()}</span>
        {:else if event.risk_level && event.risk_level !== 'safe'}
          <span
            class="inline-flex items-center px-1.5 py-0.5 rounded-full text-[9px] font-semibold uppercase"
            style="color: {event.risk_level === 'danger' ? 'var(--error)' : 'var(--warning)'};
                   background: {event.risk_level === 'danger' ? 'var(--error-bg)' : 'var(--warning-bg)'}"
            title={event.risk_description || ''}
          >{event.risk_level}</span>
        {/if}
        {#if event.id}
          <span class="text-[10px] font-mono text-(--text-secondary)">{event.id}</span>
        {/if}
        {#if event.is_new === false}
          <span class="text-[9px] px-1.5 py-0.5 rounded-sm bg-(--bg-secondary) text-(--text-secondary) font-medium">{msg.event_prior()}</span>
        {/if}
      </div>
      <div class="px-4 py-2.5">
        {#if argsObj}
          <table class="w-full">
            <tbody>
              {#each Object.entries(argsObj) as [key, val]}
                {@const mod = modsByField.get(key)}
                <tr>
                  <td class="pr-3 py-0.5 text-[11px] font-mono text-(--text-secondary) whitespace-nowrap align-top">{key}</td>
                  <td class="py-0.5 text-[11px] font-mono text-(--text-primary) break-all">
                    {#if mod}
                      <span class="line-through text-(--text-secondary)">{formatArgValue(mod.original)}</span>
                      <span class="mx-1 text-(--text-secondary)">→</span>
                      <span>{formatArgValue(mod.effective)}</span>
                      <span class="ml-1 inline-flex items-center px-1 py-0 rounded-sm text-[9px] font-mono text-(--warning) bg-(--warning-bg) border border-(--warning-border)">{mod.rule_id}</span>
                    {:else}
                      {formatArgValue(val)}
                    {/if}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        {:else}
          <pre class="text-xs font-mono text-(--text-secondary) whitespace-pre-wrap">{formatArgs(event.arguments)}</pre>
        {/if}
      </div>
      {#if event.blocked}
        <div class="flex items-start gap-2 px-4 py-2 border-t border-(--error)/30 bg-(--error-bg)">
          {#if event.blocked.rule_id}
            <a
              href={selfScoped ? undefined : scopeHref(slug, page.url.pathname, `/policy?rule_id=${encodeURIComponent(event.blocked.rule_id)}`)}
              title={msg.event_view_rule({ id: event.blocked.rule_id })}
              class="inline-flex items-center px-1.5 py-0.5 rounded-sm text-[10px] font-mono font-semibold text-(--error) bg-(--error)/20 border border-(--error)/40 hover:bg-(--error)/30 hover:text-(--error) transition-colors"
            >{event.blocked.rule_id}</a>
          {/if}
          <div class="flex-1 text-[11px] leading-snug">
            {#if event.blocked.rule_title}
              <span class="font-semibold text-(--error)">{event.blocked.rule_title}</span>
              <span class="text-(--error)/80"> {msg.event_blocked_by_policy_suffix()}</span>
            {:else}
              <span class="font-semibold text-(--error)">{msg.event_blocked_by_policy()}</span>
            {/if}
            {#if event.blocked.reason}
              <div class="text-[10px] text-(--error)/80 mt-0.5 wrap-break-word">{event.blocked.reason}</div>
            {/if}
          </div>
          <span class="text-[9px] uppercase tracking-wider text-(--error)/70 font-semibold">{event.blocked.phase}</span>
        </div>
      {/if}
      {#if event.intercepted}
        <div class="flex items-start gap-2 px-4 py-2 border-t border-(--accent)/30 bg-(--accent)/10">
          <Icon name="arrowsLR" size="sm" color="var(--accent)" />
          <a
            href={selfScoped ? undefined : scopeHref(slug, page.url.pathname, `/policy?rule_id=${encodeURIComponent(event.intercepted.rule_id)}`)}
            title={msg.event_view_rule({ id: event.intercepted.rule_id })}
            class="inline-flex items-center px-1.5 py-0.5 rounded-sm text-[10px] font-mono font-semibold text-(--accent) bg-(--accent)/20 border border-(--accent)/40 hover:bg-(--accent)/30 transition-colors"
          >{event.intercepted.rule_id}</a>
          <div class="flex-1 text-[11px] leading-snug" style="color: var(--accent)">
            {#if event.intercepted.rule_title}
              <span class="font-semibold">{event.intercepted.rule_title}</span>
              <span class="opacity-80"> {msg.event_intercepted_by_policy_suffix()}</span>
            {:else}
              <span class="font-semibold">{msg.event_intercepted_by_policy()}</span>
              <span class="opacity-80"> {msg.event_run_server_side()}</span>
            {/if}
          </div>
          <span class="text-[9px] uppercase tracking-wider opacity-70 font-semibold" style="color: var(--accent)">{msg.event_request()}</span>
        </div>
      {/if}
    </div>
  </div>
{/if}
