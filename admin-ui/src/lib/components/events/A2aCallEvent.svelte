<script lang="ts">
  // A2A gateway call — one agent invoking another — in the session timeline.
  //
  // Rendered from the backend's canonical projection: the message the caller
  // sent, the agent's reply, and any artifacts it produced all arrive as content
  // blocks, so this component never re-parses the A2A wire. A policy block and
  // every guardrail finding render with the same banners the LLM and MCP paths
  // use, because a refusal means the same thing on all three.
  import { page } from '$app/state';
  import { scopeHref } from '#lib/tenant.js';
  import { auditHref } from '#lib/deeplinks.js';
  import { isSelfScoped } from '#lib/selfScoped.js';
  import { formatTaskState } from '#lib/formatters.js';
  import { guardrailsTone, type GuardrailInfo } from '#lib/badges.js';
  import { m } from '#lib/paraglide/messages.js';
  import Icon from '#lib/components/Icon.svelte';
  import GuardrailBanner from '#lib/components/events/GuardrailBanner.svelte';
  import ContentBlocks from '#lib/components/events/ContentBlocks.svelte';
  import type { ContentBlock } from '#lib/components/events/blocks.js';

  type A2aArtifact = {
    artifact_id: string;
    name?: string | null;
    description?: string | null;
    blocks: ContentBlock[];
  };

  type A2aCallEvent = {
    type: 'a2a_call';
    request_id: string;
    timestamp: string;
    method: string;
    agent_slug?: string | null;
    agent_name?: string | null;
    caller_label?: string | null;
    caller_kind?: string | null;
    context_id?: string | null;
    task_id?: string | null;
    task_state?: string | null;
    request_blocks?: ContentBlock[];
    response_blocks?: ContentBlock[];
    artifacts?: A2aArtifact[];
    status_code?: number | null;
    error_code?: number | null;
    error_message?: string | null;
    latency_ms?: number | null;
    blocked?: { rule_id?: string | null; rule_title?: string | null; reason: string; phase: string } | null;
    guardrails?: GuardrailInfo[];
    turn?: number;
  };

  interface Props {
    event: A2aCallEvent;
    defaultExpanded?: boolean;
  }

  let { event, defaultExpanded = false }: Props = $props();
  // Capture the initial value into the local toggle so a parent re-render can't
  // clobber the user's own expand/collapse.
  // svelte-ignore state_referenced_locally
  let expanded = $state(defaultExpanded);

  let slug = $derived(page.params.slug ?? '');
  const selfScoped = isSelfScoped();

  let guardrails = $derived(event.guardrails ?? []);
  let requestBlocks = $derived(event.request_blocks ?? []);
  let responseBlocks = $derived(event.response_blocks ?? []);
  let artifacts = $derived(event.artifacts ?? []);

  let isError = $derived(
    event.error_code != null || (event.status_code != null && event.status_code >= 400),
  );
  let borderColor = $derived(
    guardrails.length > 0
      ? `var(--${guardrailsTone(guardrails)})`
      : isError
        ? 'var(--error-border)'
        : 'var(--tag-violet-bg)',
  );
  let headerColor = $derived(isError ? 'var(--error)' : 'var(--tag-violet-text)');
  let canExpand = $derived(
    requestBlocks.length > 0 || responseBlocks.length > 0 || artifacts.length > 0,
  );

  // Remote ids are opaque and long (the agent mints them). The tail is what
  // distinguishes them; the full id is on the chip's title and in the link.
  const shortId = (id: string) => (id.length > 8 ? id.slice(-8) : id);

  // The caller — the authenticated principal that dispatched the call. Naming
  // it is the whole point of the header: this party is talking TO the agent.
  let callerLabel = $derived(event.caller_label ?? m.event_a2a_caller_client());
  // The caller glyph tracks the principal kind: a person for a user key, a
  // client/app surface for an app-authenticated one.
  let callerIcon = $derived<'user' | 'desktop'>(event.caller_kind === 'app' ? 'desktop' : 'user');
  let agentLabel = $derived(event.agent_slug ?? event.agent_name ?? m.event_a2a_agent_fallback());
</script>

<!-- Centred like the MCP bubble: the call is neither user-side nor
     assistant-side — it is the gateway dispatching on the agent's behalf. -->
<div class="flex justify-center">
  <div
    class="max-w-[85%] rounded-xl bg-(--bg-primary) border overflow-hidden w-full"
    style="border-color: {borderColor}"
  >
    <button
      type="button"
      class="w-full flex flex-col gap-1 px-4 py-2 text-left {canExpand ? 'hover:bg-(--bg-elevated) cursor-pointer transition-colors' : 'cursor-default'}"
      onclick={() => { if (canExpand) expanded = !expanded; }}
      disabled={!canExpand}
    >
      <!-- Line 1 — WHO called WHOM. The single fact the surface exists to make
           legible: this caller is talking to this agent. Everything else on the
           row (method, ids) is demoted to the muted line below. -->
      <div class="flex items-center gap-2 w-full min-w-0">
        {#if canExpand}
          <span
            class="inline-block text-[10px] transition-transform shrink-0 {expanded ? 'rotate-90' : ''}"
            style="color: {headerColor}"
          >&#9654;</span>
        {:else}
          <span class="text-(--text-secondary) text-xs shrink-0">·</span>
        {/if}
        <span class="text-[10px] font-semibold uppercase tracking-wider shrink-0" style="color: {headerColor}">A2A</span>
        <!-- caller ──▶ agent -->
        <span class="flex items-center gap-1.5 min-w-0">
          <Icon name={callerIcon} size="sm" color="var(--text-secondary)" />
          <span class="text-xs text-(--text-secondary) truncate" title={callerLabel}>{callerLabel}</span>
          <Icon name="arrowRight" size="sm" color={headerColor} />
          <Icon name="users" size="sm" color={headerColor} />
          <span class="font-mono text-xs font-semibold text-(--text-primary) truncate" title={event.agent_name ?? agentLabel}>{agentLabel}</span>
        </span>
        {#if event.task_state}
          <span class="px-1.5 py-0.5 rounded-full text-[9px] font-medium bg-(--bg-secondary) text-(--text-secondary) shrink-0">
            {formatTaskState(event.task_state)}
          </span>
        {/if}
        {#if event.blocked?.rule_id}
          <a
            href={selfScoped ? undefined : scopeHref(slug, page.url.pathname, `/policy?rule_id=${encodeURIComponent(event.blocked.rule_id)}`)}
            onclick={(e) => e.stopPropagation()}
            title={m.event_view_rule({ id: event.blocked.rule_id })}
            class="inline-flex items-center px-1.5 py-0.5 rounded-sm text-[10px] font-mono font-semibold text-(--warning) bg-(--warning-bg) border border-(--warning-border) shrink-0"
          >{event.blocked.rule_id}</a>
        {/if}
        {#if isError}
          <span
            class="inline-flex items-center px-1.5 py-0.5 rounded-full text-[9px] font-semibold uppercase shrink-0"
            style="color: var(--error); background: var(--error-bg)"
            title={event.error_message || ''}
          >
            {#if event.error_code}rpc {event.error_code}{:else}HTTP {event.status_code}{/if}
          </span>
        {/if}
        {#if event.latency_ms != null}
          <span class="ml-auto font-mono text-[10px] text-(--text-secondary) shrink-0">{event.latency_ms} ms</span>
        {/if}
      </div>

      <!-- Line 2 — the mechanics: the operation, and the remote correlators. A
           task is one unit of work on the agent and a context is the
           conversation it belongs to; several gateway calls (send, poll, cancel)
           share them, so each chip links to the audit feed filtered to that id —
           the way an operator follows one remote task. A full load: from the
           audit page itself it is a fresh deep link (the page reads its URL once). Kept muted so it never
           competes with the caller → agent line. -->
      <div class="flex items-center gap-1.5 flex-wrap pl-6 text-[10px] text-(--text-secondary)">
        <span class="font-mono px-1.5 py-0.5 rounded-sm bg-(--bg-secondary) text-(--text-secondary)">{event.method}</span>
        {#if event.task_id}
          <a
            data-sveltekit-reload
            href={selfScoped ? undefined : scopeHref(slug, page.url.pathname, auditHref({ kind: 'a2a', search: event.task_id }))}
            onclick={(e) => e.stopPropagation()}
            title={m.event_a2a_task({ id: event.task_id })}
            class="font-mono px-1.5 py-0.5 rounded-sm bg-(--bg-secondary) text-(--text-secondary) hover:text-(--accent)"
          >T·{shortId(event.task_id)}</a>
        {/if}
        {#if event.context_id}
          <a
            data-sveltekit-reload
            href={selfScoped ? undefined : scopeHref(slug, page.url.pathname, auditHref({ kind: 'a2a', search: event.context_id }))}
            onclick={(e) => e.stopPropagation()}
            title={m.event_a2a_context({ id: event.context_id })}
            class="font-mono px-1.5 py-0.5 rounded-sm bg-(--bg-secondary) text-(--text-secondary) hover:text-(--accent)"
          >C·{shortId(event.context_id)}</a>
        {/if}
      </div>
    </button>

    <!-- The call was refused: it is still shown (the caller really did attempt
         it), with the rule that stopped it. -->
    {#if event.blocked}
      <div class="px-4 py-2 text-xs border-t border-(--warning-border) bg-(--warning-bg)">
        <span class="font-semibold text-(--warning)">{m.event_a2a_blocked()}</span>
        <span class="text-(--text-secondary)">{event.blocked.rule_title ?? event.blocked.reason}</span>
      </div>
    {/if}

    {#each guardrails as g, i (i)}
      <div class="border-t border-(--border)">
        <GuardrailBanner guardrail={g} />
      </div>
    {/each}

    {#if event.error_message && !expanded}
      <div class="px-4 py-2 text-xs text-(--error) font-mono border-t border-(--error)/30 bg-(--error-bg)">
        {event.error_message}
      </div>
    {/if}

    {#if expanded}
      <div class="border-t border-(--border) divide-y divide-(--border)">
        {#if requestBlocks.length > 0}
          <div class="px-4 py-2.5">
            <p class="text-[10px] font-semibold uppercase tracking-wider text-(--text-secondary) mb-1">{m.event_a2a_message()}</p>
            <ContentBlocks blocks={requestBlocks} />
          </div>
        {/if}
        {#if responseBlocks.length > 0}
          <div class="px-4 py-2.5">
            <p class="text-[10px] font-semibold uppercase tracking-wider text-(--text-secondary) mb-1">{m.event_a2a_reply()}</p>
            <ContentBlocks blocks={responseBlocks} />
          </div>
        {/if}
        {#each artifacts as artifact, i (i)}
          <div class="px-4 py-2.5">
            <p class="text-[10px] font-semibold uppercase tracking-wider text-(--text-secondary) mb-1">
              {m.event_a2a_artifact()}
              <span class="font-mono normal-case text-(--text-primary)">{artifact.name ?? artifact.artifact_id}</span>
            </p>
            {#if artifact.description}
              <p class="text-[11px] text-(--text-secondary) mb-1">{artifact.description}</p>
            {/if}
            <ContentBlocks blocks={artifact.blocks} />
          </div>
        {/each}
        {#if event.error_message}
          <div class="px-4 py-2 text-xs text-(--error) font-mono bg-(--error-bg)">
            {event.error_message}
          </div>
        {/if}
      </div>
    {/if}
  </div>
</div>
