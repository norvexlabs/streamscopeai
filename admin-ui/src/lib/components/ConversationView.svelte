<script lang="ts">
  // Shared conversation renderer — the SINGLE render path for a session's event
  // stream, used by BOTH the admin session page and the portal member session
  // page. Owns the per-event dispatch (messages, media, tool/mcp/web calls,
  // turn boundaries, transforms) plus its expand/JSON state. The page owns the
  // surrounding header, toolbar, banners, footer and the diff side-sheet (driven
  // by the `ondiff` callback). Plane-aware: links resolve under /t or /portal/t
  // via `scopeHref`, and `selfScoped` suppresses admin-only deep-links.
  import { page } from '$app/state';
  import { scopeHref } from '#lib/tenant.js';
  import { tagClasses } from '#lib/components/TagBadge.svelte';
  import { linkageTag } from '#lib/colormaps/linkage.js';
  import { setSelfScoped, portalWorkspace, sessionHref } from '#lib/selfScoped.js';
  import { auditHref } from '#lib/deeplinks.js';
  import { eventMetadata, eventRaw, eventTurn, assertNever } from '#lib/api-types.js';
  import type { LinkedSession } from '#lib/api-types.js';
  import type { components } from '#lib/generated/api-types.js';
  import { formatDuration, formatTokens, formatSpend, finishReasonColor, formatFinishReason } from '#lib/formatters.js';
  import { summarizeTransforms, formatTelemetryDropped, type InjectionBlock } from '#lib/diff-utils.js';
  import { guardrailsTone } from '#lib/badges.js';
  import { m } from '#lib/paraglide/messages.js';
  import type { DiffDetail } from '#lib/components/browse/DiffPanel.svelte';
  import Badge from '#lib/components/Badge.svelte';
  import { dedupeBadgesByCode, turnScopedBadges } from '#lib/badges.js';
  import Icon from '#lib/components/Icon.svelte';
  import ProviderIcon from '#lib/components/ProviderIcon.svelte';
  import CopyButton from '#lib/components/CopyButton.svelte';
  import RequestParamsPanel from '#lib/components/RequestParamsPanel.svelte';
  import ToolCallEvent from '#lib/components/events/ToolCallEvent.svelte';
  import McpCallEvent from '#lib/components/events/McpCallEvent.svelte';
  import ToolResultEvent from '#lib/components/events/ToolResultEvent.svelte';
  import ToolsChangedEvent from '#lib/components/events/ToolsChangedEvent.svelte';
  import MediaEvent from '#lib/components/events/MediaEvent.svelte';
  import StoredMedia from '#lib/components/events/StoredMedia.svelte';
  import WebCallEvent from '#lib/components/events/WebCallEvent.svelte';
  import A2aCallEvent from '#lib/components/events/A2aCallEvent.svelte';
  import GuardrailBanner from '#lib/components/events/GuardrailBanner.svelte';
  import GuardrailPill from '#lib/components/events/GuardrailPill.svelte';
  import {
    mediaCallCategory,
    mediaCallTitle,
    firstTextBlock,
    firstBlobRef,
    isMultipartEndpoint,
  } from '#lib/mediaCall.js';
  import hljs from 'highlight.js/lib/common';
  import { renderMarkdown as renderMd } from '#lib/markdown.js';
  import 'highlight.js/styles/github-dark-dimmed.css';

  type ConversationEvent = components['schemas']['ConversationEvent'];
  type DetectedSpawnPoint = components['schemas']['DetectedSpawnPoint'];
  type DomainRequestMeta = components['schemas']['DomainRequestMeta'];
  type WebAuditLogEntry = components['schemas']['WebAuditLogEntry'];
  type TurnParam = { turn: number; params: DomainRequestMeta };
  type TransformDiff = components['schemas']['TransformDiff'];

  interface Props {
    events: ConversationEvent[];
    turnParams?: TurnParam[];
    linkedChildren?: LinkedSession[];
    /** Spawn points detected in THIS session's stream — anchors child cards to
     *  the exact `Agent`/`Task` call (and content-matches header-linked children). */
    detectedSpawnPoints?: DetectedSpawnPoint[];
    /** Bindable OUT: session_ids of linked children this component rendered inline
     *  (anchored to a spawn call, or at a rendered turn boundary). The page excludes
     *  them from its bottom "Child Sessions" list so each child appears exactly once. */
    placedChildIds?: Set<string>;
    renderMode: 'rendered' | 'raw';
    viewMode: 'effective' | 'original';
    showPrior: boolean;
    selfScoped?: boolean;
    /** Open the diff side-sheet (admin only). Omitted in the portal → no diff buttons. */
    ondiff?: (d: DiffDetail) => void;
    /** Web-children cache keyed by orchestrating request_id (admin only). */
    webSearches?: Record<string, WebAuditLogEntry[] | null | undefined>;
    /** Lazy-load web children (admin only); absent → no web-calls affordance. */
    onLoadWeb?: (requestId: string) => void;
  }

  let {
    events,
    turnParams = [],
    linkedChildren = [],
    detectedSpawnPoints = [],
    placedChildIds = $bindable(new Set<string>()),
    renderMode,
    viewMode,
    showPrior,
    selfScoped = false,
    ondiff,
    webSearches = {},
    onLoadWeb,
  }: Props = $props();

  let slug = $derived(page.params.slug ?? '');
  // Propagate the plane to shared leaves (suppress admin-only deep-links). The
  // plane is fixed for the component's life, so the initial value is correct.
  // svelte-ignore state_referenced_locally
  setSelfScoped(selfScoped);
  // The portal workspace being viewed rides every session link it renders.
  const viewedWorkspace = portalWorkspace();

  let expandedBlocks = $state<Record<string, boolean>>({});
  let showJsonTurns = $state<Record<number, boolean>>({});

  // A tool_call id is only turn-unique (Gemini/legacy synthesize a per-turn
  // `call_0`), so a child anchors to the composite (turn, id).
  const spawnKey = (turn: number, id: string) => `${turn}:${id}`;
  const normPrompt = (s: string | null | undefined) =>
    (s ?? '').toLowerCase().replace(/\s+/g, ' ').trim().slice(0, 120);

  // Content-match a child's first message to a detected spawn point: exact
  // normalized equality first, else the LONGEST prefix-overlap match, and only for
  // a prompt long enough to disambiguate (short prompts over-match). Prevents
  // anchoring the wrong sibling when previews share a prefix.
  function contentMatch(child: LinkedSession): DetectedSpawnPoint | undefined {
    const cp = normPrompt(child.first_user_prompt);
    if (cp.length < 12) return undefined;
    let best: DetectedSpawnPoint | undefined;
    let bestLen = -1;
    for (const p of detectedSpawnPoints) {
      const pp = normPrompt(p.prompt_preview);
      if (pp.length === 0) continue;
      if (pp === cp) return p; // exact wins outright
      if ((pp.startsWith(cp) || cp.startsWith(pp)) && pp.length > bestLen) {
        best = p;
        bestLen = pp.length;
      }
    }
    return best;
  }

  /** Resolve each linked child to the EXACT spawn call it anchors to, when one is
   *  identifiable: (1) the stored agent-confirmed anchor matched against a detected
   *  point; (2) content-match of the child's first message to a detected point
   *  (covers header-linked children that carry no stored anchor). Unmatched children
   *  are left to the by-turn / linked-sessions fallback — never dropped. */
  const spawnAnchoredChildren = $derived.by(() => {
    const byKey = new Map<string, LinkedSession[]>();
    const claimed = new Set<LinkedSession>();
    for (const child of linkedChildren) {
      let match: DetectedSpawnPoint | undefined;
      if (child.linkage_spawn_tool_call_id) {
        match = detectedSpawnPoints.find(
          (p) =>
            p.tool_call_id === child.linkage_spawn_tool_call_id &&
            (child.linkage_spawn_turn == null || p.turn_number === child.linkage_spawn_turn),
        );
      }
      if (!match) match = contentMatch(child);
      if (match) {
        const key = spawnKey(match.turn_number, match.tool_call_id);
        (byKey.get(key) ?? byKey.set(key, []).get(key)!).push(child);
        claimed.add(child);
      }
    }
    return { byKey, claimed };
  });

  /** Map of turn number → child sessions spawned at that turn — the FALLBACK for
   *  children not anchored to a specific spawn call (kept out of `byKey`). */
  const childrenByTurn = $derived.by(() => {
    const map = new Map<number, LinkedSession[]>();
    const { claimed } = spawnAnchoredChildren;
    for (const child of linkedChildren) {
      if (claimed.has(child)) continue;
      const turn = child.linkage_spawn_turn ?? -1;
      if (!map.has(turn)) map.set(turn, []);
      map.get(turn)!.push(child);
    }
    return map;
  });

  // Turn numbers that actually render a boundary (where by-turn children appear).
  const renderedTurnNums = $derived(
    new Set(events.filter((e) => e.type === 'turn_boundary').map((e) => e.turn ?? -1)),
  );

  // Surface (bindable OUT) exactly the children this component renders inline:
  // spawn-anchored ones, plus by-turn ones whose boundary actually renders. The
  // page excludes these from its bottom list so a child is shown in exactly one
  // place — and a child placed NOWHERE inline (unrendered turn) still falls to the
  // page's list, never dropped.
  $effect(() => {
    const placed = new Set<string>();
    for (const arr of spawnAnchoredChildren.byKey.values())
      for (const c of arr) placed.add(c.session_id);
    for (const [turn, arr] of childrenByTurn)
      if (renderedTurnNums.has(turn)) for (const c of arr) placed.add(c.session_id);
    placedChildIds = placed;
  });

  /** Build a map of turn number → metadata by scanning all events. */
  const turnMetadata = $derived.by(() => {
    type TurnMeta = ReturnType<typeof eventMetadata> & {};
    const map = new Map<number, TurnMeta>();
    for (const ev of events) {
      const meta = eventMetadata(ev);
      const turn = eventTurn(ev);
      if (meta && turn != null && !map.has(turn)) map.set(turn, meta);
    }
    return map;
  });

  /** Map of turn number → DomainRequestMeta (request params + tool catalog). */
  const paramsByTurn = $derived.by(() => {
    const map = new Map<number, DomainRequestMeta>();
    for (const tp of turnParams) map.set(tp.turn, tp.params);
    return map;
  });

  /** Collect raw values per turn for the JSON toggle. */
  const turnRawMap = $derived.by(() => {
    const map = new Map<number, unknown[]>();
    for (const ev of events) {
      const raw = eventRaw(ev);
      const turn = eventTurn(ev);
      if (raw && turn != null) {
        if (!map.has(turn)) map.set(turn, []);
        const arr = map.get(turn)!;
        const s = JSON.stringify(raw);
        if (!arr.some((r: unknown) => JSON.stringify(r) === s)) arr.push(raw);
      }
    }
    return map;
  });

  function toggleBlock(key: string) {
    expandedBlocks[key] = !expandedBlocks[key];
  }

  // Hoisted out of the template: an object literal inside `{@const … { … }}`
  // trips knip's lib-component parser (entry files are fine), degrading its
  // whole-graph dead-code analysis.
  function msgCount(td: TransformDiff | null | undefined): { before: number; after: number } | undefined {
    if (td && typeof td.messages_original_count === 'number' && typeof td.messages_after_count === 'number') {
      return { before: td.messages_original_count, after: td.messages_after_count };
    }
    return undefined;
  }

  function formatTimeGap(ms: number): string {
    if (ms < 1000) return m.conv_immediately();
    if (ms < 60_000) return m.conv_seconds_later({ n: (ms / 1000).toFixed(0) });
    if (ms < 3600_000) return m.conv_minutes_later({ n: (ms / 60_000).toFixed(0) });
    if (ms < 86400_000) return m.conv_hours_later({ n: (ms / 3600_000).toFixed(1) });
    return m.conv_days_later({ n: (ms / 86400_000).toFixed(0) });
  }

  function renderMarkdown(text: string): string {
    return renderMd(text, hljs);
  }

  /** Known framework-injected metadata block prefixes (XML-tagged, not real user content). */
  const METADATA_BLOCK_TAGS: [string, () => string][] = [
    ['<available-deferred-tools>', () => m.conv_meta_deferred_tools()],
    ['<system-reminder>', () => m.conv_meta_system_reminder()],
    ['<session_context>', () => m.conv_meta_session_context()],
    ['<local-command-', () => m.conv_meta_local_command()],
    ['<command-', () => m.conv_meta_command()],
    ['[SUGGESTION MODE', () => m.conv_meta_suggestion_mode()],
    ['[SYSTEM', () => m.conv_meta_system_block()],
  ];

  /** Detect framework-injected metadata and return its label, or null for real content. */
  function detectMetadataBlock(content: string | null | undefined): string | null {
    if (!content) return null;
    const trimmed = content.trimStart();
    for (const [prefix, label] of METADATA_BLOCK_TAGS) {
      if (trimmed.startsWith(prefix)) return label();
    }
    return null;
  }
</script>

<!-- Linked child-session card. Rendered either right after the exact spawn call
     (precise anchor) or at the turn boundary (fallback), from the same markup. -->
{#snippet childCard(child: LinkedSession)}
  <a href={sessionHref(slug, page.url.pathname, child.session_id, viewedWorkspace())} class="mt-2 flex items-center gap-3 px-4 py-3 rounded-lg border border-(--accent) bg-(--accent)/5 hover:bg-(--accent)/10 transition-colors">
    <div class="flex-1 min-w-0">
      <p class="text-sm text-(--text-primary) line-clamp-1">{child.first_user_prompt || m.conv_sub_agent_session()}</p>
      <div class="flex items-center gap-2 mt-0.5 text-[10px] text-(--text-secondary)">
        {#if child.app_id}<span>{child.app_id}</span><span>&middot;</span>{/if}
        <span>{child.turn_count === 1 ? m.conv_turn({ count: child.turn_count }) : m.conv_turns({ count: child.turn_count })}</span>
        <span>&middot;</span>
        <span>{formatTokens(child.total_tokens)}</span>
        {#if child.linkage_confidence}
          <span class="px-1.5 py-0.5 text-[9px] font-semibold rounded-full border border-current/30
            {tagClasses(linkageTag(child.linkage_confidence))}">
            {child.linkage_confidence}
          </span>
        {/if}
      </div>
    </div>
    <span class="text-xs text-(--accent)">&rarr;</span>
  </a>
{/snippet}

    <div class="max-w-full space-y-2">
      {#each events as event, idx}
        <!-- Time Gap: merged into turn boundary, skip standalone rendering -->
        {#if event.type === 'time_gap'}
          <!-- absorbed into next turn_boundary -->

        <!-- Compaction Marker -->
        {:else if event.type === 'compaction'}
          <div class="flex items-center gap-3 py-1">
            <div class="flex-1 border-t border-dashed border-(--warning)"></div>
            <span class="text-xs text-(--warning) font-medium flex items-center gap-1.5 px-3 py-1 rounded-full bg-(--warning)/10 border border-(--warning)">
              <span>&#9986;</span>
              {m.conv_context_compacted()}
              {#if event.messages_before && event.messages_after}
                : {m.conv_compacted_messages({ before: event.messages_before, after: event.messages_after })}
              {/if}
            </span>
            <div class="flex-1 border-t border-dashed border-(--warning)"></div>
          </div>
          {#if event.summary}
            <div class="rounded-lg border border-dashed border-(--warning) bg-(--warning)/5 overflow-hidden">
              <button
                onclick={() => toggleBlock(`compact-${idx}`)}
                class="w-full flex items-center gap-2 px-3 py-2 text-left hover:bg-(--warning)/8 transition-colors"
              >
                <span class="inline-block text-[10px] transition-transform {expandedBlocks[`compact-${idx}`] ? 'rotate-90' : ''} text-(--warning)">&#9654;</span>
                <span class="text-[10px] font-semibold uppercase tracking-wider text-(--warning)">{m.conv_compaction_summary()}</span>
                <span class="text-[10px] text-(--text-secondary)">{m.conv_n_chars({ count: event.summary.length })}</span>
              </button>
              {#if expandedBlocks[`compact-${idx}`]}
                <div class="px-3 pb-2 text-sm text-(--text-primary)">
                  {#if renderMode === 'rendered'}
                    {@html renderMarkdown(event.summary)}
                  {:else}
                    <pre class="whitespace-pre-wrap font-mono text-xs">{event.summary}</pre>
                  {/if}
                </div>
              {/if}
            </div>
          {/if}

        <!-- Tools Changed Marker (between turns or modified by policy on this turn) -->
        {:else if event.type === 'tools_changed'}
          <ToolsChangedEvent {event} />

        <!-- Context Reset Marker (baseline changed but no compaction) -->
        {:else if event.type === 'context_reset'}
          <div class="flex items-center gap-3 py-1">
            <div class="flex-1 border-t border-dashed border-(--accent)"></div>
            <span class="text-xs text-(--accent) font-medium flex items-center gap-1.5 px-3 py-1 rounded-full bg-(--accent)/10 border border-(--accent)">
              <span>&#8635;</span>
              {m.conv_context_reset()}
              {#if event.message_count}
                &middot; {m.conv_n_messages({ count: event.message_count })}
              {/if}
            </span>
            <div class="flex-1 border-t border-dashed border-(--accent)"></div>
          </div>

        <!-- Turn Boundary (with time gap merged if preceding event is time_gap) -->
        {:else if event.type === 'turn_boundary'}
          {@const prevEvent = idx > 0 ? events[idx - 1] : null}
          {@const timeGap = prevEvent?.type === 'time_gap' ? prevEvent.gap_ms : null}
          {@const meta = turnMetadata.get(event.turn ?? -1)}
          {@const turnNum = event.turn ?? -1}
          {@const hasRaw = turnRawMap.has(turnNum)}

          <div id="turn-{turnNum}" class="py-1 scroll-mt-16">
            <!-- Main line: Turn N · model_requested → [icon] server / model_used · finish_reason -->
            <div class="flex items-center gap-3">
              <div class="flex-1 border-t border-(--border)"></div>
              <span class="text-[10px] text-(--text-secondary) font-mono flex items-center gap-2">
                {m.conv_turn_n({ n: (event.turn ?? 0) + 1 })}
                {#if meta}
                  {#if meta.model_requested || meta.model_used}
                    <span class="text-(--text-secondary)">&middot;</span>
                    <span class="inline-flex items-center gap-1">
                      {meta.model_requested || meta.model_used}
                      {#if meta.upstream_server_name}
                        <span class="text-(--text-secondary)">&rarr;</span>
                        <ProviderIcon name={meta.provider || ''} size="sm" className="shrink-0 text-(--text-secondary)" />
                        <span>{meta.upstream_server_name}{#if meta.model_used && meta.model_used !== (meta.model_requested || meta.model_used)}<span class="text-(--text-secondary)"> /</span> {meta.model_used}{/if}</span>
                      {:else if meta.model_used && meta.model_requested && meta.model_used !== meta.model_requested}
                        <span class="text-(--text-secondary)">&rarr;</span>
                        <span>{meta.model_used}</span>
                      {/if}
                    </span>
                  {/if}
                  {#if meta.finish_reason}
                    <span class="text-(--text-secondary)">&middot;</span>
                    <span
                      class="inline-flex items-center px-1.5 py-0.5 rounded-full border"
                      style="color: {finishReasonColor(meta.finish_reason)}; border-color: color-mix(in srgb, {finishReasonColor(meta.finish_reason)} 19%, transparent); background-color: color-mix(in srgb, {finishReasonColor(meta.finish_reason)} 6%, transparent)"
                    >
                      {formatFinishReason(meta.finish_reason)}
                    </span>
                  {/if}
                {/if}
              </span>
              <div class="flex-1 border-t border-(--border)"></div>
            </div>
            <!-- Sub line: stats + labels + transforms -->
            {#if meta}
              <div class="flex items-center justify-center gap-2 mt-0.5">
                <span class="text-[10px] text-(--text-secondary) font-mono flex items-center gap-2">
                  {formatTokens(meta.tokens_in)}&rarr;{formatTokens(meta.tokens_out)}{#if meta.cache_read_tokens || meta.cache_creation_tokens || meta.reasoning_tokens} ({#if meta.cache_read_tokens}{formatTokens(meta.cache_read_tokens)}$${/if}{#if meta.cache_creation_tokens}{#if meta.cache_read_tokens}{' '}{/if}{formatTokens(meta.cache_creation_tokens)}+$${/if}{#if meta.reasoning_tokens}{#if meta.cache_read_tokens || meta.cache_creation_tokens}{' '}{/if}{formatTokens(meta.reasoning_tokens)}R{/if}){/if}
                  <span>&middot;</span>
                  <span>{formatDuration(meta.latency_ms)}</span>
                  {#if meta.ttft_ms > 0}
                    <span>&middot;</span>
                    <span>TTFT {formatDuration(meta.ttft_ms)}</span>
                  {/if}
                  {#if timeGap}
                    <span>&middot;</span>
                    <span>{formatTimeGap(timeGap)}</span>
                  {/if}
                </span>
                {#if meta.badges && meta.badges.length > 0}
                  {@const td = meta.transform_diff}
                  {@const modifyingTransforms = Array.from(new Set((td?.injection_blocks ?? []).map(b => b.transform).filter(Boolean)))}
                  {@const messageCount = msgCount(td)}
                  {#each dedupeBadgesByCode(turnScopedBadges(meta.badges)) as badge (badge.code)}
                    <Badge {badge} context={{ modifyingTransforms, messageCount }} />
                  {/each}
                {/if}
                <!-- Transform summary badge -->
                {#if meta.transform_diff || (meta.badges && meta.badges.length > 0)}
                {@const txSummary = summarizeTransforms(meta.transform_diff)}
                {#if txSummary.hasData}
                  <button
                    onclick={() => toggleBlock(`diff-${turnNum}`)}
                    class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded-sm text-[9px] font-medium transition-colors {expandedBlocks[`diff-${turnNum}`] ? 'bg-(--success) text-(--success-fg)' : 'bg-(--tag-teal-bg) text-(--success) hover:bg-(--success-bg)'}"
                    title={m.conv_transform_summary()}
                  >
                    {#if txSummary.requestTransforms > 0 || txSummary.responseTransforms > 0}
                      <span>T&times;{txSummary.requestTransforms + txSummary.responseTransforms}</span>
                    {/if}
                    {#if txSummary.blockedTools + txSummary.responseBlockedTools > 0}
                      <span class="text-(--error)">B&times;{txSummary.blockedTools + txSummary.responseBlockedTools}</span>
                    {/if}
                    {#if txSummary.requestErrors > 0}
                      <span class="text-(--warning)">E&times;{txSummary.requestErrors}</span>
                    {/if}
                  </button>
                {/if}
                {/if}
                <!-- Telemetry-dropped chip: client in-band telemetry scrubbed during protocol conversion. -->
                {#if meta.transform_diff?.telemetry_dropped}
                {@const dropped = meta.transform_diff.telemetry_dropped}
                {#if dropped.length > 0}
                  <span
                    data-testid="telemetry-dropped-chip"
                    class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded-sm text-[9px] font-medium bg-(--bg-elevated) text-(--text-secondary) border border-(--border)"
                    title={m.conv_stripped_protocol_hop({ detail: formatTelemetryDropped(meta.transform_diff) })}
                  >
                    {m.conv_telemetry()}&times;{dropped.length}
                  </span>
                {/if}
                {/if}
                <!-- Web Calls child panel — only when this turn carries a
                     `web_substituted_*` badge. Click loads the
                     orchestrator's web children once via the
                     /audit/{request_id}/web endpoint. Mirrors
                     the transform-summary toggle pattern next to it. -->
                {#if meta.request_id && onLoadWeb && meta.badges?.some((b) => b.code.startsWith('web_substitut'))}
                {@const wsKey = `websearches-${turnNum}`}
                {@const expanded = expandedBlocks[wsKey] ?? false}
                {@const ws = webSearches[meta.request_id]}
                  <button
                    onclick={() => {
                      toggleBlock(wsKey);
                      if (meta.request_id) onLoadWeb?.(meta.request_id);
                    }}
                    class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded-sm text-[9px] font-medium transition-colors {expanded ? 'bg-(--warning) text-(--warning-fg)' : 'bg-(--warning-bg) text-(--warning) hover:bg-(--warning-bg)'}"
                    title={m.conv_web_searches_dispatched()}
                  >
                    <span>&#128269;</span>
                    <span>
                      {m.conv_web_calls()}{#if Array.isArray(ws)}&nbsp;({ws.length}){:else if ws === null}&nbsp;…{/if}
                    </span>
                  </button>
                {/if}
              </div>
            {:else if timeGap}
              <div class="flex items-center justify-center mt-0.5">
                <span class="text-[10px] text-(--text-secondary) font-mono">{formatTimeGap(timeGap)}</span>
              </div>
            {/if}
            {#if hasRaw}
              <div class="flex justify-center mt-0.5">
                <button
                  onclick={() => { showJsonTurns = { ...showJsonTurns, [turnNum]: !showJsonTurns[turnNum] }; }}
                  class="px-1.5 py-0.5 rounded-sm text-[9px] font-medium transition-colors {showJsonTurns[turnNum] ? 'bg-(--accent) text-(--accent-fg)' : 'bg-(--bg-secondary) text-(--text-secondary) hover:text-(--text-primary)'}"
                  title={m.conv_toggle_raw_json()}
                >
                  JSON
                </button>
              </div>
            {/if}
          </div>

          <!-- Inline JSON viewer for this turn -->
          {#if showJsonTurns[turnNum] && hasRaw}
            <div class="rounded-lg bg-(--bg-primary) border border-(--border) p-3 overflow-x-auto relative group">
              <div class="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity">
                <CopyButton text={JSON.stringify(turnRawMap.get(turnNum), null, 2)} />
              </div>
              <pre class="text-xs font-mono text-(--text-secondary) whitespace-pre-wrap">{JSON.stringify(turnRawMap.get(turnNum), null, 2)}</pre>
            </div>
          {/if}

          <!-- Inline web children — lazy-loaded once via the
               /audit/{request_id}/web endpoint, mounted under
               the same expandedBlocks keying as the transform-summary
               toggle. Each entry renders the canonical
               <WebCallEvent> component the audit detail uses. -->
          {#if onLoadWeb && expandedBlocks[`websearches-${turnNum}`] && meta?.request_id}
            {@const ws = webSearches[meta.request_id]}
            <div class="rounded-lg bg-(--bg-primary) border border-(--border) p-3 space-y-2">
              {#if ws === undefined || ws === null}
                <div class="text-xs text-(--text-secondary)">{m.conv_loading_web_searches()}</div>
              {:else if ws.length === 0}
                <div class="text-xs text-(--text-secondary)">{m.conv_no_web_calls()}</div>
              {:else}
                <span class="block text-[10px] font-semibold uppercase tracking-wider text-(--text-secondary)">
                  {m.conv_web_searches_count({ count: ws.length })}
                </span>
                {#each ws as row (row.request_id)}
                  <WebCallEvent {row} />
                {/each}
              {/if}
            </div>
          {/if}

          <!-- Inline transform summary + diffs viewer -->
          {#if expandedBlocks[`diff-${turnNum}`] && meta?.transform_diff}
            {@const td = meta.transform_diff}
            <div class="rounded-lg bg-(--bg-primary) border border-(--border) p-3 space-y-2">
              <span class="block text-[10px] font-semibold uppercase tracking-wider text-(--text-secondary)">{m.conv_transforms_applied()}</span>
              <!-- Request-side transform programs (typed outcome) -->
              {#if td.transform_programs?.length}
                <div class="space-y-1">
                  {#each td.transform_programs as prog}
                    {@const isError = prog.outcome === 'errored'}
                    <div class="flex items-center gap-2 text-xs">
                      <span class="{isError ? 'text-(--warning)' : 'text-(--success)'}">{isError ? 'E' : 'T'}</span>
                      <span class="text-(--text-primary)">{prog.name}</span>
                      {#if td.system_prompt_modified && !isError && prog.outcome === 'modified'}
                        <span class="text-(--text-secondary)">{m.conv_system_prompt_modified()}</span>
                      {:else if prog.outcome === 'passed'}
                        <span class="text-(--text-secondary)">{m.conv_no_change()}</span>
                      {/if}
                      {#if isError}
                        <span class="text-(--warning)">{m.conv_error_fail_open()}</span>
                      {/if}
                    </div>
                  {/each}
                </div>
              {/if}
              <!-- Request-phase tool removals — tool was stripped from
                   the tools list before the LLM ran, so it never appears in
                   the tool log below. Surfacing it here on the turn header
                   is the only place operators see "this tool was denied
                   before it could be called". -->
              {#if td.blocked_tools?.length}
                <div class="pt-1 border-t border-(--border)">
                  <span class="text-[10px] font-semibold uppercase tracking-wider text-(--text-secondary)">{m.conv_tools_removed_request()}</span>
                  {#each td.blocked_tools as bt}
                    <div class="flex items-center gap-2 text-xs mt-1">
                      <span class="text-(--error) font-semibold">−</span>
                      <span class="font-mono text-(--text-primary)">{bt.name}</span>
                      {#if bt.rule_id}
                        <span class="inline-flex items-center px-1 py-0 rounded-sm text-[9px] font-mono text-(--error) bg-(--error-bg) border border-(--error)/30">{bt.rule_id}</span>
                      {/if}
                      {#if bt.title}
                        <span class="text-(--text-secondary)">{bt.title}</span>
                      {:else}
                        <span class="text-(--text-secondary)">{bt.description}</span>
                      {/if}
                    </div>
                  {/each}
                </div>
              {/if}
              <!-- Response-side transform programs -->
              {#if td.response_transform_programs?.length}
                <div class="pt-1 border-t border-(--border)">
                  <span class="text-[10px] font-semibold uppercase tracking-wider text-(--text-secondary)">{m.conv_response_transforms()}</span>
                  {#each td.response_transform_programs as prog}
                    {@const isError = prog.outcome === 'errored'}
                    <div class="flex items-center gap-2 text-xs mt-1">
                      <span class="{isError ? 'text-(--warning)' : 'text-(--success)'}">{isError ? 'E' : 'T'}</span>
                      <span class="text-(--text-primary)">{prog.name}</span>
                      {#if isError}
                        <span class="text-(--warning)">{m.conv_error_dash()}</span>
                      {:else if prog.outcome === 'passed'}
                        <span class="text-(--text-secondary)">{m.conv_no_change()}</span>
                      {/if}
                    </div>
                  {/each}
                </div>
              {/if}
              {#if td.response_blocked_tools?.length}
                <div class="pt-1 border-t border-(--border)">
                  <span class="text-[10px] font-semibold uppercase tracking-wider text-(--text-secondary)">{m.conv_tool_calls_blocked_response()}</span>
                  {#each td.response_blocked_tools as bt}
                    <div class="flex items-center gap-2 text-xs mt-1">
                      <span class="text-(--error) font-semibold">!</span>
                      <span class="font-mono text-(--text-primary)">{bt.name}</span>
                      {#if bt.rule_id}
                        <span class="inline-flex items-center px-1 py-0 rounded-sm text-[9px] font-mono text-(--error) bg-(--error-bg) border border-(--error)/30">{bt.rule_id}</span>
                      {/if}
                      {#if bt.title}
                        <span class="text-(--text-secondary)">{bt.title}</span>
                      {:else}
                        <span class="text-(--text-secondary)">{bt.description}</span>
                      {/if}
                    </div>
                  {/each}
                </div>
              {/if}
              <!-- Step diffs (expandable) -->
              {#if td.step_diffs?.length}
                <details class="pt-1 border-t border-(--border)">
                  <summary class="text-[10px] font-semibold uppercase tracking-wider text-(--accent) cursor-pointer select-none hover:text-(--accent-hover)">
                    {m.conv_step_diffs_count({ count: td.step_diffs.length })}
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

          <!-- Inline child sessions with a spawn turn but no exact spawn-call
               anchor (fallback placement at the turn boundary). -->
          {#if childrenByTurn.has(turnNum)}
            {#each childrenByTurn.get(turnNum) ?? [] as child}
              {@render childCard(child)}
            {/each}
          {/if}

          <!-- Canonical request parameters + tools available (from domain normalization) -->
          {#if paramsByTurn.has(turnNum)}
            <RequestParamsPanel params={paramsByTurn.get(turnNum) ?? null} />
          {/if}

        <!-- System Prompt -->
        {:else if event.type === 'system_prompt'}
          {@const turnMeta = event.turn != null ? turnMetadata.get(event.turn) : undefined}
          {@const injectedPrompt = turnMeta?.transform_diff?.injected_system_prompt}
          {@const sysBlocks = (turnMeta?.transform_diff?.injection_blocks ?? []).filter((b: InjectionBlock) => b.field === 'system_prompt')}
          {@const isModified = viewMode === 'effective' && (!!injectedPrompt || sysBlocks.length > 0)}
          {@const displayContent = isModified && injectedPrompt ? injectedPrompt : (event.content ?? '')}
          <div class="rounded-xl border border-dashed {isModified ? 'bg-(--success-bg) border-(--success-border)' : 'bg-(--tag-violet-bg) border-(--tag-violet-mark)/30'} overflow-hidden">
            <button
              onclick={() => toggleBlock(`sys-${idx}`)}
              class="w-full flex items-center gap-2 px-4 py-2.5 text-left hover:bg-(--tag-violet-bg) transition-colors"
            >
              <span class="inline-block text-[10px] transition-transform {expandedBlocks[`sys-${idx}`] ? 'rotate-90' : ''}" style="color: {isModified ? 'var(--tag-teal-text)' : 'var(--tag-violet-text)'}">&#9654;</span>
              <span class="text-[10px] font-semibold uppercase tracking-wider" style="color: {isModified ? 'var(--tag-teal-text)' : 'var(--tag-violet-text)'}">{m.conv_system_prompt()}</span>
              <span class="text-[10px] text-(--text-secondary)">{m.conv_n_chars({ count: displayContent.length })}</span>
              {#if isModified}
                <span class="px-1.5 py-0.5 text-[9px] font-semibold rounded-sm bg-(--tag-teal-bg) text-(--tag-teal-text) border border-(--success-border)">{m.conv_modified()}</span>
              {/if}
            </button>
            {#if expandedBlocks[`sys-${idx}`]}
              <div class="px-4 pb-3 text-sm text-(--text-primary)">
                {#if isModified && sysBlocks.length > 0}
                  <!-- Effective view: show original content + structured injection blocks -->
                  {#if renderMode === 'rendered'}
                    {@html renderMarkdown(event.content ?? '')}
                  {:else}
                    <pre class="whitespace-pre-wrap font-mono text-xs">{event.content}</pre>
                  {/if}
                  <!-- Injection blocks from proxy (no frontend diffing) -->
                  {#each sysBlocks as block}
                    <div class="mt-3 border-l-2 border-(--success) pl-3 bg-(--success-bg) rounded-r-lg py-2">
                      <span class="text-[10px] font-semibold uppercase tracking-wider text-(--success)">{block.transform}</span>
                      <span class="text-[9px] text-(--text-secondary) ml-2">{block.action}</span>
                      <pre class="mt-1 whitespace-pre-wrap font-mono text-xs text-(--tag-teal-text)">{block.content}</pre>
                    </div>
                  {/each}
                  <!-- Diff link -->
                  {#if injectedPrompt && ondiff}
                    <button
                      onclick={() => ondiff?.({ title: m.conv_system_prompt(), original: event.content ?? '', effective: injectedPrompt, transform: sysBlocks[0]?.transform, phase: 'request', scope: 'system_prompt' })}
                      class="mt-2 text-[10px] text-(--accent) hover:underline"
                    >{m.conv_show_diff()} ↔</button>
                  {/if}
                {:else}
                  {#if renderMode === 'rendered'}
                    {@html renderMarkdown(displayContent)}
                  {:else}
                    <pre class="whitespace-pre-wrap font-mono text-xs">{displayContent}</pre>
                  {/if}
                {/if}
              </div>
            {/if}
          </div>

        <!-- Framework reminder: inline-split volatile block (<system-reminder>, etc.)
             — backend splits these out of user/assistant prose so we render a
             collapsed card instead of polluting the message bubble. Shares the
             visual pattern of the legacy whole-message `meta-${idx}` card below. -->
        {:else if event.type === 'framework_reminder'}
          {#if !event.is_new && !showPrior}
            <!-- Hidden prior reminder -->
          {:else}
            <div class="rounded-xl border border-dashed border-(--text-secondary) bg-(--bg-secondary)/30 overflow-hidden {!event.is_new ? 'opacity-40' : ''}">
              <button
                onclick={() => toggleBlock(`fwr-${idx}`)}
                class="w-full flex items-center gap-2 px-4 py-2 text-left hover:bg-(--bg-elevated) transition-colors"
              >
                <span class="inline-block text-[10px] transition-transform {expandedBlocks[`fwr-${idx}`] ? 'rotate-90' : ''} text-(--text-secondary)">&#9654;</span>
                <span class="text-[10px] font-semibold uppercase tracking-wider text-(--text-secondary)">{event.label}</span>
                <span class="text-[10px] text-(--text-secondary)">{m.conv_n_chars({ count: event.content?.length ?? 0 })}</span>
                {#if !event.is_new}
                  <span class="text-[9px] px-1.5 py-0.5 rounded-sm bg-(--bg-secondary) text-(--text-secondary) font-medium">{m.conv_prior()}</span>
                {/if}
              </button>
              {#if expandedBlocks[`fwr-${idx}`]}
                <div class="px-4 pb-3 text-sm text-(--text-primary)">
                  <pre class="whitespace-pre-wrap font-mono text-xs">{event.content}</pre>
                </div>
              {/if}
            </div>
          {/if}

        <!-- Message -->
        {:else if event.type === 'message'}
          {#if !event.is_new && !showPrior}
            <!-- Hidden prior message -->
          {:else}
            <!-- Framework metadata block: collapsed like system prompt -->
            {@const metaLabel = event.role === 'user' ? detectMetadataBlock(event.content) : null}
            {#if metaLabel}
              <div class="rounded-xl border border-dashed border-(--text-secondary) bg-(--bg-secondary)/30 overflow-hidden {!event.is_new ? 'opacity-40' : ''}">
                <button
                  onclick={() => toggleBlock(`meta-${idx}`)}
                  class="w-full flex items-center gap-2 px-4 py-2 text-left hover:bg-(--bg-elevated) transition-colors"
                >
                  <span class="inline-block text-[10px] transition-transform {expandedBlocks[`meta-${idx}`] ? 'rotate-90' : ''} text-(--text-secondary)">&#9654;</span>
                  <span class="text-[10px] font-semibold uppercase tracking-wider text-(--text-secondary)">{metaLabel}</span>
                  <span class="text-[10px] text-(--text-secondary)">{m.conv_n_chars({ count: event.content?.length ?? 0 })}</span>
                  {#if !event.is_new}
                    <span class="text-[9px] px-1.5 py-0.5 rounded-sm bg-(--bg-secondary) text-(--text-secondary) font-medium">{m.conv_prior()}</span>
                  {/if}
                </button>
                {#if expandedBlocks[`meta-${idx}`]}
                  <div class="px-4 pb-3 text-sm text-(--text-primary)">
                    <pre class="whitespace-pre-wrap font-mono text-xs">{event.content}</pre>
                  </div>
                {/if}
              </div>

            <!-- User message: left-aligned blue bubble. When the inbound-prompt
                 guardrail flagged this message, wrap it in a shield border +
                 banner — the request-phase sibling of the web ToolResult card. -->
            {:else if event.role === 'user'}
              {@const gs = event.guardrails ?? []}
              <div class="flex justify-start {!event.is_new ? 'opacity-40' : ''}">
                <div
                  class="max-w-[85%] rounded-2xl rounded-bl-md bg-(--tag-blue-bg) {gs.length > 0 ? 'border overflow-hidden' : ''}"
                  style={gs.length > 0 ? `border-color: var(--${guardrailsTone(gs)})` : ''}
                >
                  <div class="px-4 py-3">
                    <div class="flex items-center gap-2 {!event.is_new || gs.length > 0 ? 'mb-1' : ''}">
                      {#if !event.is_new}
                        <span class="text-[9px] px-1.5 py-0.5 rounded-sm bg-(--bg-secondary) text-(--text-secondary) font-medium inline-block">{m.conv_prior()}</span>
                      {/if}
                      {#each gs as g}
                        <GuardrailPill guardrail={g} />
                      {/each}
                    </div>
                    <div class="text-sm text-(--text-primary)">
                      {#if renderMode === 'rendered'}
                        {@html renderMarkdown(event.content ?? '')}
                      {:else}
                        <pre class="whitespace-pre-wrap font-mono text-xs">{event.content}</pre>
                      {/if}
                    </div>
                  </div>
                  {#each gs as g}
                    <GuardrailBanner guardrail={g} />
                  {/each}
                </div>
              </div>

            <!-- Assistant message: right-aligned green bubble -->
            {:else if event.role === 'assistant'}
              <div class="flex justify-end {!event.is_new ? 'opacity-40' : event.is_from_history ? 'opacity-70' : ''}">
                <div class="max-w-[85%] rounded-2xl rounded-br-md px-4 py-3 bg-(--tag-teal-bg)">
                  {#if !event.is_new}
                    <span class="text-[9px] px-1.5 py-0.5 rounded-sm bg-(--bg-secondary) text-(--text-secondary) font-medium mb-1 inline-block">{m.conv_prior()}</span>
                  {:else if event.is_from_history}
                    <span
                      class="text-[9px] px-1.5 py-0.5 rounded-sm bg-(--warning-bg) text-(--warning) border border-(--warning-border) font-medium mb-1 inline-block"
                      title={m.conv_client_history_tooltip()}
                    >{m.conv_client_history()}</span>
                  {/if}

                  <!-- Thinking block (collapsed by default) -->
                  {#if event.thinking}
                    <div class="mb-2 rounded-lg bg-(--bg-primary) border border-(--border) overflow-hidden">
                      <button
                        onclick={() => toggleBlock(`think-${idx}`)}
                        class="w-full flex items-center gap-2 px-3 py-2 text-left hover:bg-(--bg-elevated) transition-colors"
                      >
                        <span class="inline-block text-[10px] transition-transform {expandedBlocks[`think-${idx}`] ? 'rotate-90' : ''}" style="color: var(--tag-violet-text)">&#9654;</span>
                        <span class="text-[10px] font-semibold uppercase tracking-wider" style="color: var(--tag-violet-text)">{m.conv_thinking()}</span>
                        <span class="text-[10px] text-(--text-secondary)">{m.conv_n_chars({ count: event.thinking.length })}</span>
                      </button>
                      {#if expandedBlocks[`think-${idx}`]}
                        <div class="px-3 pb-2">
                          <pre class="text-xs font-mono text-(--text-secondary) whitespace-pre-wrap">{event.thinking}</pre>
                        </div>
                      {/if}
                    </div>
                  {/if}

                  <div class="text-sm text-(--text-primary)">
                    {#if renderMode === 'rendered'}
                      {@html renderMarkdown(event.content ?? '')}
                    {:else}
                      <pre class="whitespace-pre-wrap font-mono text-xs">{event.content}</pre>
                    {/if}
                  </div>

                </div>
              </div>

            <!-- In-array system message (e.g. Claude Code's Skill catalog):
                 system content that travels inside the messages array rather
                 than the request's system channel. Collapsed violet card. -->
            {:else if event.role === 'system'}
              <div class="rounded-xl border border-dashed border-(--tag-violet-mark)/30 bg-(--tag-violet-bg) overflow-hidden {!event.is_new ? 'opacity-40' : ''}">
                <button
                  onclick={() => toggleBlock(`sysmsg-${idx}`)}
                  class="w-full flex items-center gap-2 px-4 py-2.5 text-left hover:bg-(--bg-elevated) transition-colors"
                >
                  <span class="inline-block text-[10px] transition-transform {expandedBlocks[`sysmsg-${idx}`] ? 'rotate-90' : ''}" style="color: var(--tag-violet-text)">&#9654;</span>
                  <span class="text-[10px] font-semibold uppercase tracking-wider" style="color: var(--tag-violet-text)">{m.conv_system_message()}</span>
                  <span class="text-[10px] text-(--text-secondary)">{m.conv_n_chars({ count: event.content?.length ?? 0 })}</span>
                  {#if !event.is_new}
                    <span class="text-[9px] px-1.5 py-0.5 rounded-sm bg-(--bg-secondary) text-(--text-secondary) font-medium">{m.conv_prior()}</span>
                  {/if}
                </button>
                {#if expandedBlocks[`sysmsg-${idx}`]}
                  <div class="px-4 pb-3 text-sm text-(--text-primary)">
                    <pre class="whitespace-pre-wrap font-mono text-xs">{event.content}</pre>
                  </div>
                {/if}
              </div>

            <!-- Other roles -->
            {:else}
              <div class="flex justify-start {!event.is_new ? 'opacity-40' : ''}">
                <div class="max-w-[85%] rounded-xl px-4 py-3 bg-(--bg-secondary) border border-(--border)">
                  <span class="text-[10px] font-semibold uppercase tracking-wider text-(--text-secondary) mb-1 block">{event.role}</span>
                  <div class="text-sm text-(--text-primary)">
                    {#if renderMode === 'rendered'}
                      {@html renderMarkdown(event.content ?? '')}
                    {:else}
                      <pre class="whitespace-pre-wrap font-mono text-xs">{event.content}</pre>
                    {/if}
                  </div>
                </div>
              </div>
            {/if}
          {/if}

        <!-- Tool Call / Tool Result — shared components keep the session view
             and the /tool-calls invocation feed rendering identical. -->
        {:else if event.type === 'tool_call'}
          {@const spawned = spawnAnchoredChildren.byKey.get(spawnKey(event.turn, event.id)) ?? []}
          <ToolCallEvent {event} {showPrior} />
          <!-- Child sessions spawned by THIS exact call — anchored precisely,
               not just at the turn boundary. -->
          {#if spawned.length > 0}
            <div class="flex items-center gap-1.5 pl-1 text-[10px] font-semibold uppercase tracking-wider text-(--accent)">
              <Icon name="gitBranch" size="xs" />
              <span>{m.conv_spawned_here()}</span>
            </div>
            {#each spawned as child}
              {@render childCard(child)}
            {/each}
          {/if}

        {:else if event.type === 'tool_result'}
          <ToolResultEvent {event} {showPrior} />

        <!-- MCP gateway call (interleaved between LLM turns by the
             Phase 3b backend join). Distinct from `tool_call` because
             the call did NOT come from the LLM tool catalogue. -->
        {:else if event.type === 'mcp_call'}
          <McpCallEvent {event} />

        <!-- A2A gateway call — one agent invoking another, interleaved by the
             same session id that ties the LLM turns and MCP calls together.
             This is where an orchestrator's `tool_use` and the agent-to-agent
             exchange it triggered sit side by side. -->
        {:else if event.type === 'a2a_call'}
          <A2aCallEvent {event} />

        <!-- Web (search / fetch) call — interleaved by the canonical
             session-conversation pipeline. Surfaces direct `/mcp/web`
             dispatches AND substitution-loop children inline in the
             event stream. Click → focused view in /audit?kind=web. -->
        {:else if event.type === 'web_call'}
          {@const gs = event.guardrails ?? []}
          <div
            class="rounded-lg border-l-2 {gs.length > 0 ? 'border border-l-2' : ''} overflow-hidden"
            style={gs.length > 0 ? `border-color: var(--${guardrailsTone(gs)})` : 'border-color: var(--chart-4)'}
          >
          <div class="flex items-center gap-2 text-xs text-(--text-secondary) pl-3 py-1">
            <span class="px-1.5 py-0.5 rounded-sm text-[10px] uppercase tracking-wider bg-(--tag-amber-bg) text-(--tag-amber-text) font-medium">{m.conv_web()}</span>
            <span class="font-mono">{event.operation}</span>
            <span class="text-(--text-tertiary)">·</span>
            <span class="text-(--text-tertiary)">{event.surface}</span>
            {#if event.query}
              <span class="text-(--text-tertiary)">·</span>
              <span class="font-mono text-(--text-primary) truncate max-w-100" title={event.query}>{event.query}</span>
            {/if}
            {#if event.operation === 'search' && (event.result_count ?? 0) > 0}
              <span class="text-(--text-tertiary)">·</span>
              <span>{m.conv_hits({ count: event.result_count ?? 0 })}</span>
            {/if}
            {#if event.latency_ms != null}
              <span class="text-(--text-tertiary)">·</span>
              <span class="font-mono">{event.latency_ms}ms</span>
            {/if}
            {#each gs as g}
              <GuardrailPill guardrail={g} />
            {/each}
            {#if event.error_category}
              <span class="ml-1 px-1.5 py-0.5 rounded-sm text-[10px] border border-(--error) bg-(--error)/10 text-(--error)" title={event.error_detail || ''}>
                {event.error_category}
              </span>
            {/if}
            <a
              href={selfScoped ? undefined : scopeHref(slug, page.url.pathname, auditHref({ kind: 'web', request_id: event.request_id }))}
              class="ml-auto pr-2 text-(--accent) hover:underline"
              onclick={(e) => e.stopPropagation()}
            >
              {m.conv_details()} →
            </a>
          </div>
          {#each gs as g}
            <GuardrailBanner guardrail={g} />
          {/each}
          </div>

        <!-- Media Attachment -->
        {:else if event.type === 'media'}
          {#if !event.is_new && !showPrior}
            <!-- Hidden prior media -->
          {:else}
            <div class="flex {event.role === 'assistant' ? 'justify-end' : 'justify-start'} {!event.is_new ? 'opacity-40' : ''}">
              <div class="max-w-[85%] rounded-xl overflow-hidden border border-(--border) bg-(--bg-card)">
                <div class="px-3 py-2 flex items-center gap-2 text-[10px] uppercase tracking-wider text-(--text-secondary) border-b border-(--border)">
                  {#if event.content_type === 'image'}
                    <span>{m.conv_media_image()}</span>
                  {:else if event.content_type === 'document'}
                    <span>{m.conv_media_document()}</span>
                  {:else if event.content_type === 'audio'}
                    <span>{m.conv_media_audio()}</span>
                  {:else}
                    <span>{m.conv_media_media()}</span>
                  {/if}
                  <span class="font-mono">{event.media_type}</span>
                  {#if event.title}
                    <span class="text-(--text-primary)">{event.title}</span>
                  {/if}
                  {#if event.size_bytes}
                    <span>{event.size_bytes > 1024 ? `${(event.size_bytes / 1024).toFixed(1)}KB` : `${event.size_bytes}B`}</span>
                  {/if}
                  {#if !event.is_new}
                    <span class="px-1.5 py-0.5 rounded-sm bg-(--bg-secondary) font-medium">{m.conv_prior()}</span>
                  {/if}
                </div>
                <div class="p-3">
                  <MediaEvent {event} />
                </div>
              </div>
            </div>
          {/if}

        <!-- Standalone Media API Call — rendered from canonical media_call.
             Left bubble: request input (prompt / uploaded file).
             Right bubble: response output (generated media / transcription / job). -->
        {:else if event.type === 'media_api_call'}
          {@const mcall = event.media_call}
          {@const mcat = mediaCallCategory(mcall)}
          {@const mtitle = mediaCallTitle(mcall)}
          {@const minput = firstTextBlock(mcall?.input)}
          {@const moutput = firstTextBlock(mcall?.output)}
          {@const req_blob = firstBlobRef(mcall?.input)}
          {@const resp_blob = firstBlobRef(mcall?.output)}
          <div class="flex justify-start">
            <div class="max-w-[85%] rounded-2xl rounded-bl-md px-4 py-3 bg-(--tag-blue-bg)">
              <div class="flex items-center gap-2 mb-1">
                {#if mcat === 'embedding'}
                  <span class="px-1.5 py-0.5 rounded-full text-[9px] font-medium bg-(--tag-blue-bg) text-(--tag-blue-text)">{m.conv_media_embedding()}</span>
                {:else if mcat === 'audio'}
                  <span class="px-1.5 py-0.5 rounded-full text-[9px] font-medium bg-(--tag-teal-bg) text-(--tag-teal-text)">{m.conv_media_audio()}</span>
                {:else if mcat === 'image'}
                  <span class="px-1.5 py-0.5 rounded-full text-[9px] font-medium bg-(--tag-violet-bg) text-(--tag-violet-text)">{m.conv_media_image()}</span>
                {:else if mcat === 'video'}
                  <span class="px-1.5 py-0.5 rounded-full text-[9px] font-medium bg-(--tag-indigo-bg) text-(--tag-indigo-text)">{m.conv_media_video()}</span>
                {:else}
                  <span class="px-1.5 py-0.5 rounded-full text-[9px] font-medium bg-(--bg-secondary) text-(--text-secondary)">{mcat}</span>
                {/if}
                <span class="text-xs font-medium text-(--text-secondary)">{mtitle}</span>
              </div>
              {#if minput}
                <p class="text-sm text-(--text-primary) whitespace-pre-wrap">{minput}</p>
              {/if}
              {#if req_blob && isMultipartEndpoint(mcall?.endpoint) && (mcat === 'audio' || mcat === 'image')}
                <div class="mt-2">
                  <StoredMedia
                    hash={req_blob.content_hash}
                    blobType="request_upload"
                    requestId={eventMetadata(event)?.request_id}
                    kind={mcat}
                    alt={m.conv_uploaded()}
                    download={mcat === 'audio' ? 'upload.mp3' : 'upload.png'} />
                </div>
              {:else if !minput && req_blob}
                <p class="text-xs text-(--text-secondary) italic">{m.conv_file_uploaded()}</p>
              {:else if !minput && !req_blob}
                <p class="text-xs text-(--text-secondary) italic">{mtitle}</p>
              {/if}
            </div>
          </div>

          <div class="flex justify-end">
            <div class="max-w-[85%] rounded-2xl rounded-br-md px-4 py-3 bg-(--tag-teal-bg)">
              {#if moutput}
                <p class="text-sm text-(--text-primary) whitespace-pre-wrap">{moutput}</p>
              {/if}
              {#if resp_blob}
                <StoredMedia
                  hash={resp_blob.content_hash}
                  blobType="response_body"
                  requestId={eventMetadata(event)?.request_id}
                  kind={mcat}
                  alt={m.conv_generated()}
                  download="response.{mcat === 'image' ? 'png' : mcat === 'audio' ? 'mp3' : 'mp4'}" />
              {:else if mcat === 'video'}
                <div class="text-xs space-y-1">
                  <p class="text-(--text-secondary)">{m.conv_video_job_submitted()}</p>
                  {#if mcall?.job?.job_id}
                    <p class="font-mono text-(--text-primary)">{m.conv_job({ id: mcall.job.job_id })}</p>
                  {/if}
                  {#if mcall?.job?.status}
                    <p class="text-(--text-secondary)">{m.conv_status_label()} <span class="text-(--text-primary)">{mcall.job.status}</span></p>
                  {/if}
                  {#if event.metadata?.model_used}
                    <p class="text-(--text-secondary)">{m.conv_model_label()} <span class="text-(--text-primary)">{event.metadata.model_used}</span></p>
                  {/if}
                </div>
              {:else if mcat === 'embedding'}
                <p class="text-sm text-(--success)">{m.conv_embedding_vectors({ count: mcall?.output_units ?? 1 })}</p>
              {:else if !moutput && !resp_blob}
                <p class="text-xs text-(--text-secondary) italic">{m.conv_processing()}</p>
              {/if}
              <!-- Metadata footer -->
              {#if event.metadata}
                <div class="mt-2 pt-2 border-t border-(--border) flex items-center gap-3 text-[10px] text-(--text-secondary)">
                  {#if event.metadata.model_used}
                    <span class="font-mono">{event.metadata.model_used}</span>
                  {/if}
                  {#if event.metadata.spend && event.metadata.spend.amount > 0}
                    <span>{formatSpend(event.metadata.spend)}</span>
                  {/if}
                  {#if event.metadata.latency_ms > 0}
                    <span>{formatDuration(event.metadata.latency_ms)}</span>
                  {/if}
                  {#if event.metadata.provider}
                    <span>{event.metadata.provider}</span>
                  {/if}
                </div>
              {/if}
            </div>
          </div>
        {:else}
          <!-- Exhaustiveness guard: every ConversationEvent.type is handled
               above. A new variant (regen after a Rust enum change) narrows
               `event` here to something other than `never`, failing the build
               so the missing render branch can't ship silently. -->
          {assertNever(event)}
        {/if}
      {/each}

      <!-- (JSON viewers are now inline in each turn_boundary block) -->
    </div>
