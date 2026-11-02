<script lang="ts">
  // One session's conversation, on both planes: the console's session page and
  // the portal's render this one component through `plane`
  // (`#lib/browse/planes.js`). The portal reads within the workspace named by
  // `?workspace_id` (a teammate's session in a sharing workspace); the server
  // re-checks sharing and membership, and withholds expert findings from
  // members — the alert chips and banner below then render nothing.
  import { onMount, untrack } from 'svelte';
  import { page } from '$app/state';
  import { goto } from '$app/navigation';
  import type { ConversationResponse, CrossSessionIssue, LinkedSessionsResponse } from '#lib/api-types.js';
  import type { BrowsePlane } from '#lib/browse/planes.js';
  import type { components } from '#lib/generated/api-types.js';
  import { eventMetadata } from '#lib/api-types.js';
  import { extractError } from '#lib/api-helpers.js';
  import { toast } from '#lib/toast.svelte.js';
  import { onRefresh } from '#lib/hooks.svelte.js';
  import { scopeHref } from '#lib/tenant.js';
  import { sessionsHref } from '#lib/deeplinks.js';
  import { formatDuration, formatTokens, formatSpend, formatTimeAgo, parseAlertLines } from '#lib/formatters.js';
  import { setPortalWorkspace, setSelfScoped, sessionHref } from '#lib/selfScoped.js';
  import SegmentedControl from '#lib/components/forms/SegmentedControl.svelte';
  import Copyable from '#lib/components/Copyable.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import { tagClasses } from '#lib/components/TagBadge.svelte';
  import { linkageTag } from '#lib/colormaps/linkage.js';
  import ConversationView from '#lib/components/ConversationView.svelte';
  import SessionAlertBanner from '#lib/components/SessionAlertBanner.svelte';
  import SessionLinkList from '#lib/components/SessionLinkList.svelte';
  import DiffPanel, { type DiffDetail } from '#lib/components/browse/DiffPanel.svelte';
  import { m } from '#lib/paraglide/messages.js';

  type WebAuditLogEntry = components['schemas']['WebAuditLogEntry'];

  interface Props {
    plane: BrowsePlane;
    sessionId: string;
  }

  let { plane, sessionId }: Props = $props();

  // svelte-ignore state_referenced_locally
  const p = plane;
  if (p.portal) setSelfScoped(true);

  const slug = $derived(page.params.slug ?? '');
  // The workspace rides the URL from the list; the page's read and every detail
  // the rendered leaves fetch (stored media, tool definitions) carry it.
  const viewedWorkspace = () => page.url.searchParams.get('workspace_id') ?? undefined;
  setPortalWorkspace(viewedWorkspace);
  const sessionsList = $derived.by(() => {
    return scopeHref(slug, page.url.pathname, sessionsHref({ workspace_id: viewedWorkspace() }));
  });

  let conversation = $state<ConversationResponse | null>(null);
  let linkedData = $state<LinkedSessionsResponse | null>(null);
  // Children ConversationView placed inline (bound OUT): the Child Sessions
  // list shows only the rest, so each child appears once.
  let placedInline = $state(new Set<string>());
  let sessionIssues = $state<CrossSessionIssue[]>([]);
  let loading = $state(true);
  let error = $state('');
  let renderMode = $state<'rendered' | 'raw'>('rendered');
  let viewMode = $state<'effective' | 'original'>('effective');
  let showPrior = $state(false);
  let diff = $state<DiffDetail | null>(null);

  /** Web calls an LLM turn dispatched, by its `request_id`: `undefined` = not
   *  asked yet, `null` = loading, a list once loaded (empty on failure). */
  let webSearchesByRequest = $state<Record<string, WebAuditLogEntry[] | null | undefined>>({});

  async function loadWebCalls(requestId: string) {
    if (webSearchesByRequest[requestId] !== undefined) return;
    webSearchesByRequest = { ...webSearchesByRequest, [requestId]: null };
    try {
      const { data, error: err } = await p.webCalls(requestId, viewedWorkspace());
      if (err) console.warn('load web children:', extractError(err));
      webSearchesByRequest = { ...webSearchesByRequest, [requestId]: data?.items ?? [] };
    } catch (e) {
      console.warn('load web children:', e);
      webSearchesByRequest = { ...webSearchesByRequest, [requestId]: [] };
    }
  }

  let pendingScrollTarget = $state<string | null>(null);

  /** Open a linked session, optionally scrolled to a turn once it has loaded. */
  function navigateToSession(targetSessionId: string, scrollToTurn?: number | null) {
    pendingScrollTarget = scrollToTurn != null ? `turn-${scrollToTurn}` : null;
    void goto(sessionHref(slug, page.url.pathname, targetSessionId, viewedWorkspace()));
  }

  /** Whether any turn carries a transform with something to compare. */
  const hasTransformData = $derived.by(() => {
    if (!conversation?.events) return false;
    for (const ev of conversation.events) {
      const td = eventMetadata(ev)?.transform_diff;
      if (!td) continue;
      if (td.injected_system_prompt || td.effective_messages || td.original_response_content
          || (td.blocked_tools && td.blocked_tools.length > 0)
          || (td.response_blocked_tools && td.response_blocked_tools.length > 0)
          || (td.injection_blocks && td.injection_blocks.length > 0)) return true;
    }
    return false;
  });

  const unplacedChildren = $derived((linkedData?.children ?? []).filter((c) => !placedInline.has(c.session_id)));

  onMount(() => {
    try {
      const saved = localStorage.getItem('session_render_mode');
      if (saved === 'raw' || saved === 'rendered') renderMode = saved;
    } catch {
      // No storage: the default render mode.
    }
  });

  // Load on mount and whenever the session changes (a move to a linked one) —
  // only then: the load reads the URL's workspace, which must not re-run it.
  $effect(() => {
    void sessionId;
    void untrack(() => loadConversation()).then(() => {
      if (pendingScrollTarget) {
        const target = pendingScrollTarget;
        pendingScrollTarget = null;
        setTimeout(() => document.getElementById(target)?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 150);
      }
    });
  });

  // A refresh re-reads in place: the conversation stays shown. Not while the
  // session's own load runs: it would supersede it, and on failure keep the
  // previous session under the new URL.
  onRefresh(() => {
    if (!loading) void loadConversation(true);
  });

  // Only the latest load writes.
  let loadGen = 0;

  /** A `reload` (a refresh) keeps the conversation shown until the new one
   *  lands. */
  async function loadConversation(reload = false) {
    const gen = ++loadGen;
    if (!reload) {
      // Another session: nothing of the previous one stays on screen.
      loading = true;
      error = '';
      conversation = null;
      linkedData = null;
      sessionIssues = [];
    }
    const ws = viewedWorkspace();
    try {
      const [convRes, linkedRes, issuesRes] = await Promise.all([
        p.conversation(sessionId, ws),
        p.linked(sessionId, ws).then((r) => r.data ?? null).catch(() => null),
        p.issues(sessionId).catch(() => null),
      ]);
      if (gen !== loadGen) return;
      if (convRes.error) {
        // A failed refresh keeps the transcript and says so; only a first load
        // (or a move to another session) has nothing to keep.
        const message = extractError(convRes.error, m.browse_session_err_load());
        if (reload && conversation) toast.error(m.browse_refresh_failed(), { body: message });
        else { error = message; conversation = null; }
      } else {
        error = '';
        conversation = convRes.data ?? null;
      }
      // The side panels: a failed re-read keeps what they showed.
      if (linkedRes || !reload) linkedData = linkedRes;
      if (issuesRes || !reload) sessionIssues = issuesRes ?? [];
    } catch (e: unknown) {
      if (gen !== loadGen) return;
      const message = extractError(e, m.browse_session_err_load());
      if (reload && conversation) toast.error(m.browse_refresh_failed(), { body: message });
      else error = message;
    } finally {
      if (gen === loadGen) loading = false;
    }
  }

  function setRenderMode(mode: 'rendered' | 'raw') {
    renderMode = mode;
    try {
      localStorage.setItem('session_render_mode', mode);
    } catch {
      // No storage: the choice lasts the visit.
    }
  }

  const alertTone = (level: string | null | undefined) =>
    level === 'major'
      ? 'bg-(--error-bg) text-(--error) border border-(--error)/30'
      : level === 'minor'
        ? 'bg-(--warning-bg) text-(--warning) border border-(--warning-border)'
        : 'bg-(--tag-neutral-bg) text-(--tag-neutral-text) border border-(--border)';
  const alertMark = (level: string | null | undefined) => (level === 'major' ? '!!' : level === 'minor' ? '!' : '·');
</script>

<div>
  <div class="mb-6 rounded-xl border border-(--border) bg-(--bg-card) overflow-hidden">
    <div class="flex flex-wrap items-center justify-between gap-x-4 gap-y-2 px-5 py-3 border-b border-(--border) bg-(--bg-secondary)/50">
      <div class="flex items-center gap-3 min-w-0">
        <a href={sessionsList} aria-label={m.browse_session_back()} class="text-(--text-secondary) hover:text-(--text-primary) transition-colors shrink-0">
          <Icon name="arrowLeft" tone="neutral" />
        </a>
        <h2 class="text-lg font-bold shrink-0">{m.browse_session_title()}</h2>
        <span class="text-xs text-(--text-secondary)">
          <Copyable value={sessionId} label={`${sessionId.substring(0, 8)}...`} />
        </span>
      </div>
      <div class="flex flex-wrap items-center gap-2 ml-auto">
        <label class="flex items-center gap-1.5 text-xs text-(--text-secondary) cursor-pointer select-none">
          <input type="checkbox" bind:checked={showPrior} class="rounded-sm border-(--border) bg-(--bg-secondary)" />
          {m.browse_session_prior_context()}
        </label>
        {#if hasTransformData}
          <SegmentedControl
            bind:value={viewMode}
            tone="success"
            label={m.conv_view_lens()}
            options={[
              { value: 'effective', label: m.browse_session_effective(), title: m.browse_session_effective_title() },
              { value: 'original', label: m.browse_session_original(), title: m.browse_session_original_title() },
            ]} />
        {/if}
        <SegmentedControl
          value={renderMode}
          onchange={setRenderMode}
          label={m.conv_view_format()}
          options={[
            { value: 'rendered', label: m.browse_session_rendered() },
            { value: 'raw', label: m.browse_session_raw() },
          ]} />
      </div>
    </div>

    {#if conversation}
      <div class="px-5 py-3">
        <div class="flex items-center flex-wrap gap-x-3 gap-y-1 text-sm text-(--text-secondary) mb-3">
          {#if conversation.end_user}
            <!-- A gateway-forwarded end user takes the identity slot; the
                 internal (inline AI) account follows in parentheses. -->
            <span class="truncate max-w-75" title={m.browse_session_end_user_title()}>
              {conversation.end_user}{#if conversation.user_email} <span class="text-(--text-tertiary)">({conversation.user_email})</span>{/if}
            </span>
          {:else if conversation.user_email}
            <span class="truncate max-w-50">{conversation.user_email}</span>
          {/if}
          {#if conversation.key_name || conversation.key_prefix}
            <span class="w-1 h-1 rounded-full bg-(--text-secondary) shrink-0"></span>
            <span class="font-mono truncate max-w-45">{conversation.key_name || ''}{#if conversation.key_prefix} <code class="text-[10px] bg-(--bg-secondary) px-1 py-0.5 rounded-sm">{conversation.key_prefix}...</code>{/if}</span>
          {/if}
          {#if conversation.workspace_name}
            <span class="w-1 h-1 rounded-full bg-(--text-secondary) shrink-0"></span>
            <span class="inline-flex items-center gap-1">
              <Icon name="building" size="sm" tone="neutral" />
              <span>{conversation.workspace_name}</span>
            </span>
          {/if}
          <span class="w-1 h-1 rounded-full bg-(--text-secondary) shrink-0"></span>
          <span>{conversation.model || '--'}</span>
        </div>

        <div class="flex flex-wrap gap-2">
          <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-(--bg-primary) text-xs text-(--text-secondary)">
            {m.browse_session_turns({ count: conversation.summary.total_turns })}
          </span>
          <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-(--bg-primary) text-xs">
            <span class="text-(--text-primary) font-medium font-mono">{formatSpend(conversation.summary.spend)}</span>
          </span>
          <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-(--bg-primary) text-xs text-(--text-secondary)">
            {m.browse_session_tokens({ count: formatTokens(conversation.summary.total_tokens) })}{#if conversation.summary.total_input_tokens || conversation.summary.total_output_tokens}
              <span>&mdash;</span>
              {m.browse_session_in_out({ input: formatTokens(conversation.summary.total_input_tokens), output: formatTokens(conversation.summary.total_output_tokens) })}{/if}{#if (conversation.summary.total_cache_read_tokens ?? 0) > 0}
              <span>&middot;</span>
              {m.browse_session_cache_read({ count: formatTokens(conversation.summary.total_cache_read_tokens) })}{/if}{#if (conversation.summary.total_cache_creation_tokens ?? 0) > 0}
              <span>&middot;</span>
              {m.browse_session_cache_write({ count: formatTokens(conversation.summary.total_cache_creation_tokens) })}{/if}{#if (conversation.summary.total_reasoning_tokens ?? 0) > 0}
              <span>&middot;</span>
              {m.browse_session_reasoning({ count: formatTokens(conversation.summary.total_reasoning_tokens) })}{/if}
          </span>
          <span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-(--bg-primary) text-xs">
            <span class="text-(--text-primary) font-medium">{formatDuration(conversation.summary.duration_ms)}</span>
          </span>

          <!-- Expert alert chips, beside the figures. -->
          {#if conversation.alert_level}
            {@const alerts = parseAlertLines(conversation.alert_note, conversation.alert_level)}
            {#each alerts as alert, i (i)}
              <span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold {alertTone(alert.level)}">
                {alertMark(alert.level)} {alert.axis || alert.level}
              </span>
            {:else}
              <span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold {alertTone(conversation.alert_level)}">
                {alertMark(conversation.alert_level)} {conversation.alert_level}
              </span>
            {/each}
          {/if}
        </div>
      </div>
    {/if}
  </div>

  <!-- The session-level expert signal, stated once. -->
  <SessionAlertBanner level={conversation?.alert_level} note={conversation?.alert_note} />

  {#if conversation?.parent_session_id}
    {@const parentId = conversation.parent_session_id}
    {@const spawnTurn = conversation.linkage_spawn_turn}
    <button
      onclick={() => navigateToSession(parentId, spawnTurn)}
      class="mb-4 w-full rounded-xl border border-(--accent) bg-(--accent)/5 hover:bg-(--accent)/10 px-4 py-3 flex items-center gap-3 cursor-pointer transition-colors text-left"
    >
      <Icon name="arrowLeft" size="sm" color="var(--accent)" />
      <span class="text-sm text-(--text-primary)">
        {m.browse_session_parent()}
        <span class="text-(--accent) font-mono text-xs ml-1">{parentId.substring(0, 8)}...</span>
      </span>
      {#if conversation.linkage_confidence}
        <span class="px-2 py-0.5 text-[10px] font-semibold rounded-full border border-current/30 {tagClasses(linkageTag(conversation.linkage_confidence))}">
          {conversation.linkage_confidence}
        </span>
      {/if}
      {#if spawnTurn != null}
        <span class="text-xs text-(--text-secondary)">{m.browse_session_spawned_at({ turn: spawnTurn + 1 })}</span>
      {/if}
    </button>
  {/if}

  {#if sessionIssues.length > 0}
    <div class="mb-4 rounded-xl border border-(--border) bg-(--bg-card) px-4 py-3">
      <div class="flex items-center gap-2 mb-2.5">
        <Icon name="shield" tone="warning" size="sm" />
        <span class="text-xs font-semibold uppercase tracking-wider text-(--text-secondary)">
          {m.browse_session_issues({ count: sessionIssues.length })}
        </span>
      </div>
      <div class="space-y-2">
        {#each sessionIssues as issue (issue.id)}
          <div class="flex items-start gap-2.5">
            <span class="shrink-0 mt-0.5 px-1.5 py-0.5 text-[10px] font-semibold rounded uppercase {alertTone(issue.level)}">{issue.axis ?? issue.level ?? 'issue'}</span>
            <div class="flex-1 min-w-0">
              <p class="text-sm text-(--text-primary)">{issue.note}</p>
              <div class="mt-1">
                <SessionLinkList sessionIds={issue.source_session_ids} label={m.browse_session_issue_spans()} />
              </div>
            </div>
          </div>
        {/each}
      </div>
    </div>
  {/if}

  {#if loading}
    <div class="flex items-center gap-3 py-16 justify-center text-(--text-secondary)">
      <div class="w-5 h-5 border-2 border-(--accent) border-t-transparent rounded-full animate-spin"></div>
      {m.browse_session_loading()}
    </div>
  {:else if error}
    <div class="py-16 text-center">
      <p class="text-(--error)">{error}</p>
      <a href={sessionsList} class="text-sm text-(--accent) hover:underline mt-2 inline-block">{m.browse_session_back()}</a>
    </div>
  {:else if !conversation || !conversation.events || conversation.events.length === 0}
    <div class="py-16 text-center">
      <p class="text-(--text-secondary)">{m.browse_session_empty()}</p>
      <a href={sessionsList} class="text-sm text-(--accent) hover:underline mt-2 inline-block">{m.browse_session_back()}</a>
    </div>
  {:else}
    <ConversationView
      events={conversation.events}
      turnParams={conversation.turn_params}
      linkedChildren={linkedData?.children}
      detectedSpawnPoints={conversation.detected_spawn_points}
      bind:placedChildIds={placedInline}
      {renderMode}
      {viewMode}
      {showPrior}
      selfScoped={p.portal}
      ondiff={(d) => (diff = d)}
      webSearches={webSearchesByRequest}
      onLoadWeb={loadWebCalls}
    />

    <div class="max-w-full mt-6 bg-(--bg-card) rounded-xl border border-(--border) px-6 py-3">
      <div class="flex flex-wrap items-center gap-x-6 gap-y-1 text-sm">
        <div><span class="text-(--text-secondary)">{m.browse_session_sum_turns()} </span><span class="font-mono text-(--text-primary)">{conversation.summary.total_turns}</span></div>
        <div><span class="text-(--text-secondary)">{m.browse_session_sum_tokens()} </span><span class="font-mono text-(--text-primary)">{formatTokens(conversation.summary.total_tokens)}</span></div>
        {#if conversation.summary.total_input_tokens || conversation.summary.total_output_tokens}
          <div><span class="text-(--text-secondary)">{m.browse_session_sum_input()} </span><span class="font-mono text-(--text-primary)">{formatTokens(conversation.summary.total_input_tokens)}</span></div>
          <div><span class="text-(--text-secondary)">{m.browse_session_sum_output()} </span><span class="font-mono text-(--text-primary)">{formatTokens(conversation.summary.total_output_tokens)}</span></div>
        {/if}
        {#if (conversation.summary.total_cache_read_tokens ?? 0) > 0}
          <div><span class="text-(--text-secondary)">{m.browse_session_sum_cache_read()} </span><span class="font-mono text-(--text-primary)">{formatTokens(conversation.summary.total_cache_read_tokens)}</span></div>
        {/if}
        {#if (conversation.summary.total_cache_creation_tokens ?? 0) > 0}
          <div><span class="text-(--text-secondary)">{m.browse_session_sum_cache_write()} </span><span class="font-mono text-(--text-primary)">{formatTokens(conversation.summary.total_cache_creation_tokens)}</span></div>
        {/if}
        {#if (conversation.summary.total_reasoning_tokens ?? 0) > 0}
          <div><span class="text-(--text-secondary)">{m.browse_session_sum_reasoning()} </span><span class="font-mono text-(--text-primary)">{formatTokens(conversation.summary.total_reasoning_tokens)}</span></div>
        {/if}
        <div><span class="text-(--text-secondary)">{m.browse_session_sum_cost()} </span><span class="font-mono text-(--text-primary)">{formatSpend(conversation.summary.spend)}</span></div>
        <div><span class="text-(--text-secondary)">{m.browse_session_sum_duration()} </span><span class="font-mono text-(--text-primary)">{formatDuration(conversation.summary.duration_ms)}</span></div>
      </div>
    </div>

    <!-- Children not placed inline (no rendered spawn anchor or turn
         boundary), so each child appears once. -->
    {#if unplacedChildren.length > 0}
      <div class="max-w-full mt-6 bg-(--bg-card) rounded-xl border border-(--border) overflow-hidden">
        <div class="px-6 py-4 border-b border-(--border)">
          <h3 class="text-sm font-semibold text-(--text-primary)">{m.browse_session_children()}</h3>
        </div>
        <div class="divide-y divide-(--border)">
          {#each unplacedChildren as child (child.session_id)}
            <a href={sessionHref(slug, page.url.pathname, child.session_id, viewedWorkspace())} class="px-6 py-3 flex items-center gap-4 hover:bg-(--bg-elevated) transition-colors block">
              <div class="flex-1 min-w-0">
                <div class="flex items-center gap-2">
                  <p class="text-sm text-(--text-primary) line-clamp-1 leading-snug flex-1 min-w-0">
                    {child.first_user_prompt || child.model_used || '--'}
                  </p>
                  {#if !child.spend || child.spend.amount > 0}
                    <span class="text-xs text-(--text-primary) font-mono shrink-0 tabular-nums" title={child.spend ? undefined : m.spend_not_stated_hint()}>{formatSpend(child.spend, m.spend_not_stated_short)}</span>
                  {/if}
                  <span class="text-xs text-(--text-secondary) shrink-0 tabular-nums font-mono">{formatTimeAgo(child.last_timestamp)}</span>
                </div>
                <div class="flex items-center gap-2 mt-1 flex-wrap">
                  {#if child.app_id}
                    <span class="text-[10px] text-(--accent)">{child.app_id}</span>
                    <span class="text-[10px] text-(--text-secondary)">&middot;</span>
                  {/if}
                  <span class="text-xs text-(--text-secondary) font-mono">{child.model_used || '--'}</span>
                  <span class="text-[10px] text-(--text-secondary)">&middot;</span>
                  <span class="text-[10px] text-(--text-secondary)">{m.browse_session_child_turns({ count: child.turn_count })}</span>
                  {#if child.total_tokens}
                    <span class="text-[10px] text-(--text-secondary)">&middot;</span>
                    <span class="text-[10px] text-(--text-secondary) font-mono">{formatTokens(child.total_tokens)}</span>
                  {/if}
                  {#if child.linkage_confidence}
                    <span class="px-1.5 py-0.5 text-[9px] font-semibold rounded-full border border-current/30 {tagClasses(linkageTag(child.linkage_confidence))}">
                      {child.linkage_confidence}
                    </span>
                  {/if}
                </div>
              </div>
            </a>
          {/each}
        </div>
      </div>
    {/if}
  {/if}
</div>

<DiffPanel {diff} onclose={() => (diff = null)} />
