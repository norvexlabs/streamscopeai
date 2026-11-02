<script lang="ts">
  import type { TransformProgram, TransformSuggestion } from '#lib/api-types.js';
  import { adminApi } from '#lib/api-client.js';
  import { extractError, extractErrorCode, fetchAllPages } from '#lib/api-helpers.js';
  import { thref } from '#lib/tenant.js';
  import type { PageProps } from './$types';

  let { params }: PageProps = $props();

  let slug = $derived(params.slug);
  import { getTabFromUrl } from '#lib/tabs.js';
  import Tabs from '#lib/components/Tabs.svelte';
  import Skeleton from '#lib/components/Skeleton.svelte';
  import TagBadge from '#lib/components/TagBadge.svelte';
  import ProfilesManager from '#lib/components/policy/ProfilesManager.svelte';
  import { profileLists } from '#lib/scope.svelte.js';
  import { scopeColor, filterChipColor } from '#lib/colormaps/transforms.js';
  import { usePeriodicLoad } from '#lib/hooks.svelte.js';
  import { toast } from '#lib/toast.svelte.js';
  import { useLoadView } from '#lib/loadView.svelte.js';
  import SuggestionRevisedNotice from '#lib/components/policy/SuggestionRevisedNotice.svelte';
  import { acceptNewer, mergeSuggestions } from '#lib/suggestion-merge.js';

  let activeTab = $state<'profiles' | 'request' | 'response' | 'suggestions'>(
    getTabFromUrl(['profiles', 'request', 'response', 'suggestions'], 'profiles')
  );
  // The Request/Response pipeline view shows every program (scope tagged per
  // row); per-profile editing lives in the `/transforms/profiles/[id]` drill-down.
  const profileName = $derived((id: string | null | undefined) =>
    id ? (profileLists.transform.find((p) => p.id === id)?.name ?? 'Unknown profile') : 'Shared'
  );
  let programs = $state<TransformProgram[]>([]);
  let suggestions = $state<TransformSuggestion[]>([]);
  /** Newer copies of pending rows still shown as the admin is reading them. */
  let suggestionsNewer = $state<Record<string, TransformSuggestion>>({});
  function showNewer(id: string) {
    const m = acceptNewer({ rows: suggestions, newer: suggestionsNewer }, id);
    suggestions = m.rows;
    suggestionsNewer = m.newer;
  }
  let reviewingId = $state<string | null>(null);
  let showSuggestionHistory = $state(false);
  let pendingSuggestions = $derived(suggestions.filter((s: TransformSuggestion) => s.status === 'pending'));
  let historySuggestions = $derived(suggestions.filter((s: TransformSuggestion) => s.status !== 'pending'));
  let loading = $state(true);
  // The skeleton on a first load or a new scope only: a refresh keeps what
  // is shown (`#lib/loadView.js`), so an auto-refresh tick never blanks it.
  const view = useLoadView(() => loading);
  let error = $state<string | null>(null);

  // Only the latest read lands: a refresh read before a save must not put the
  // old state back after the save's own re-read.
  let loadGen = 0;
  async function loadData() {
    const gen = ++loadGen;
    loading = true;
    error = null;
    try {
      const [programsList, suggestionsList] = await Promise.all([
        fetchAllPages((offset, limit) =>
          adminApi.GET('/api/v1/admin/transforms/programs', { params: { query: { offset, limit } } })),
        fetchAllPages((offset, limit) =>
          adminApi.GET('/api/v1/admin/transforms/suggestions', { params: { query: { offset, limit } } })),
      ]);
      if (gen !== loadGen) return;
      programs = programsList;
      // A refresh never rewrites a pending row the admin may be reading.
      const merged = mergeSuggestions(suggestions, suggestionsList);
      suggestions = merged.rows;
      suggestionsNewer = merged.newer;
    } catch (e: unknown) {
      if (gen === loadGen) error = e instanceof Error ? e.message : String(e);
    } finally {
      if (gen === loadGen) loading = false;
    }
  }

  usePeriodicLoad(loadData);

  // Approval sends the content hash of the suggestion as shown, so an agent
  // re-proposal that rewrote it meanwhile is refused instead of installed.
  async function handleSuggestion(suggestion: { id: string; content_hash: string }, status: 'approved' | 'rejected') {
    if (reviewingId) return;
    const id = suggestion.id;
    reviewingId = id;
    try {
      const { error: err } = status === 'approved'
        ? await adminApi.POST('/api/v1/admin/transforms/suggestions/{id}/actions/approve', {
            params: { path: { id } },
            body: { content_hash: suggestion.content_hash },
          })
        : await adminApi.POST('/api/v1/admin/transforms/suggestions/{id}/actions/reject', { params: { path: { id } } });
      const changed = !!err && extractErrorCode(err) === 'suggestion_changed';
      if (changed) {
        toast.error('Suggestion changed since it was loaded', { body: 'Review the new version before approving it.' });
      } else if (err) {
        toast.error(`Failed to ${status === 'approved' ? 'approve' : 'reject'} suggestion`, { body: extractError(err) });
      } else {
        toast.success(status === 'approved' ? 'Suggestion approved' : 'Suggestion rejected');
      }
      await loadData();
      if (changed) showNewer(id);
    } finally {
      reviewingId = null;
    }
  }

  function scopeLabel(scope: string) {
    switch (scope) {
      case 'system_prompt': return 'system_prompt';
      default: return scope;
    }
  }

  // Pipeline visualization constants
  const BUILTIN_SCRIPT_NAMES = new Set(['compression', 'server_tool_filter']);
  const REQUEST_SCOPE_ORDER = ['global', 'system_prompt', 'messages', 'tools'] as const;
  const RESPONSE_SCOPE_ORDER = ['global', 'text', 'tool', 'thinking'] as const;

  const currentPhase = $derived(activeTab === 'response' ? 'response' : 'request');
  const SCOPE_ORDER = $derived(currentPhase === 'response' ? RESPONSE_SCOPE_ORDER : REQUEST_SCOPE_ORDER);

  let scriptsByScope = $derived((() => {
    const phase = currentPhase;
    const scopes = phase === 'response' ? RESPONSE_SCOPE_ORDER : REQUEST_SCOPE_ORDER;
    const groups: Record<string, TransformProgram[]> = {};
    for (const scope of scopes) {
      groups[scope] = programs
        .filter((p: TransformProgram) => (p.phase || 'request') === phase && p.scope === scope)
        .sort((a: TransformProgram, b: TransformProgram) => (a.priority ?? 100) - (b.priority ?? 100));
    }
    return groups;
  })());
</script>

<div class="space-y-6">
  <div class="flex items-center justify-between">
    <h1 class="text-2xl font-semibold text-(--text-primary)">Transforms</h1>
  </div>

  {#if error}
    <div class="p-3 rounded-lg bg-(--error-bg) text-(--error) text-sm">{error}</div>
  {/if}

  <!-- Tabs -->
  <Tabs tabs={[{id: 'profiles', label: 'Profiles'}, {id: 'request', label: 'Request'}, {id: 'response', label: 'Response'}, {id: 'suggestions', label: 'Suggestions'}]} active={activeTab} onchange={(t) => activeTab = t as typeof activeTab}>
    {#snippet badge(id)}
      {#if id === 'suggestions'}
        {#if pendingSuggestions.length > 0}
          <span class="ml-1 px-1.5 py-0.5 text-xs rounded-full bg-(--accent) text-(--accent-fg)">{pendingSuggestions.length}</span>
        {/if}
      {/if}
    {/snippet}
  </Tabs>

  {#snippet scriptChain()}
    <div class="w-full rounded-xl border border-(--border) bg-(--bg-card) p-5">
      <div class="flex items-center justify-between mb-4">
        <div class="flex items-center gap-3">
          <span class="w-7 h-7 flex items-center justify-center rounded-full bg-(--accent)/20 text-sm font-mono text-(--accent)">{currentPhase === 'response' ? '2' : '4'}</span>
          <span class="font-semibold text-(--text-primary)">Script Chain</span>
          <span class="text-xs text-(--text-secondary)">Rhai scripts by scope then priority — all profiles</span>
        </div>
        <a href={thref(slug, '/transforms')} onclick={(e) => { e.preventDefault(); activeTab = 'profiles'; }} class="text-xs text-(--accent) hover:underline">Edit in Profiles →</a>
      </div>
      <div class="space-y-3">
        {#each SCOPE_ORDER as scope}
          {@const scopePrograms = scriptsByScope[scope] || []}
          <div class="rounded-lg border border-(--border) overflow-hidden">
            <div class="flex items-center gap-2 px-4 py-2 bg-(--bg-primary)/50">
              <TagBadge color={scopeColor(scope)} class="text-xs">{scopeLabel(scope)}</TagBadge>
              {#if scopePrograms.length === 0}
                <span class="text-xs text-(--text-secondary) italic">No scripts</span>
              {/if}
            </div>
            {#each scopePrograms as p}
              <div class="flex items-center justify-between px-4 py-3 border-t border-(--border) hover:bg-(--bg-elevated)">
                <div class="flex-1 min-w-0">
                  <div class="flex items-center gap-2.5">
                    <a href={thref(slug, `/transforms/${p.id}`)} class="font-medium text-(--text-primary) hover:text-(--accent) truncate">{p.name}</a>
                    <span class="text-xs text-(--text-secondary) font-mono shrink-0">p:{p.priority}</span>
                    {#if BUILTIN_SCRIPT_NAMES.has(p.name)}
                      <TagBadge color="blue" class="text-xs shrink-0">Built-in</TagBadge>
                    {/if}
                    {#if p.profile_id}
                      <TagBadge color="indigo" class="text-xs shrink-0">{profileName(p.profile_id)}</TagBadge>
                    {:else}
                      <TagBadge color="neutral" class="text-xs shrink-0">Shared</TagBadge>
                    {/if}
                  </div>
                  {#if p.description}
                    <div class="text-xs text-(--text-secondary) mt-1 line-clamp-2">{p.description}</div>
                  {/if}
                  {#if p.model_filter || p.app_filter || p.match_mode === 'span'}
                    <div class="flex gap-2 mt-1">
                      {#if p.match_mode === 'span'}
                        <TagBadge color={scopeColor(p.scope)} class="text-xs">per-match</TagBadge>
                      {/if}
                      {#if p.model_filter}
                        <TagBadge color={filterChipColor.models} class="text-xs">models: {p.model_filter}</TagBadge>
                      {/if}
                      {#if p.app_filter}
                        <TagBadge color={filterChipColor.apps} class="text-xs">apps: {p.app_filter}</TagBadge>
                      {/if}
                    </div>
                  {/if}
                </div>
                <div class="flex items-center gap-3 shrink-0 ml-4">
                  <span class="text-xs {p.enabled ? 'text-(--success)' : 'text-(--text-secondary)'}">{p.enabled ? 'Enabled' : 'Disabled'}</span>
                  <a href={thref(slug, `/transforms/${p.id}`)} class="text-(--accent) hover:underline text-sm">Open →</a>
                </div>
              </div>
            {/each}
          </div>
        {/each}
      </div>
    </div>
  {/snippet}

  {#if view.skeleton}
    <!-- Match the pipeline's actual shape: ~9 numbered step cards stacked
         vertically (see step components below), each ~5rem tall. Under-sizing
         here causes a big layout jump when data lands. -->
    <Skeleton variant="card" count={9} height="5rem" />
  {:else if activeTab === 'request'}
    <!-- REQUEST Pipeline Visualization -->
    <div class="flex flex-col items-center gap-0">
      <div class="w-full text-center py-3 px-6 rounded-lg bg-(--bg-secondary) border border-(--border) text-sm text-(--text-secondary) font-mono tracking-widest uppercase">Client Request</div>
      <div class="w-0 h-7 border-l-2 border-dashed border-(--border)"></div>

      <!-- ① Resolve Upstream -->
      <div class="w-full rounded-xl border border-(--border) bg-(--bg-card) p-5">
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-3">
            <span class="w-7 h-7 flex items-center justify-center rounded-full bg-(--bg-elevated) text-sm font-mono text-(--text-secondary)">1</span>
            <span class="font-semibold text-(--text-primary)">Resolve Upstream</span>
            <span class="px-2 py-0.5 text-xs rounded-sm bg-(--bg-elevated) text-(--text-secondary)">System</span>
          </div>
          <span class="text-xs text-(--success)">Always</span>
        </div>
        <p class="text-sm text-(--text-secondary) mt-2 ml-10">Routes the model alias to an upstream target: resolves URL, API key, provider, context window, and protocol format.</p>
      </div>
      <div class="w-0 h-7 border-l-2 border-dashed border-(--border)"></div>

      <!-- ② Normalize -->
      <div class="w-full rounded-xl border border-(--border) bg-(--bg-card) p-5">
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-3">
            <span class="w-7 h-7 flex items-center justify-center rounded-full bg-(--bg-elevated) text-sm font-mono text-(--text-secondary)">2</span>
            <span class="font-semibold text-(--text-primary)">Normalize</span>
            <span class="px-2 py-0.5 text-xs rounded-sm bg-(--bg-elevated) text-(--text-secondary)">System</span>
          </div>
          <span class="text-xs text-(--success)">Always</span>
        </div>
        <p class="text-sm text-(--text-secondary) mt-2 ml-10">Converts native request into a protocol-agnostic text-only view. Non-text content preserved unchanged.</p>
      </div>
      <div class="w-0 h-7 border-l-2 border-dashed border-(--border)"></div>

      <!-- ③ Tool Policy -->
      <div class="w-full rounded-xl border border-(--border) bg-(--bg-card) p-5">
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-3">
            <span class="w-7 h-7 flex items-center justify-center rounded-full bg-(--bg-elevated) text-sm font-mono text-(--text-secondary)">3</span>
            <span class="font-semibold text-(--text-primary)">Tool Policy</span>
            <span class="px-2 py-0.5 text-xs rounded-sm bg-(--bg-elevated) text-(--text-secondary)">System</span>
          </div>
          <span class="text-xs text-(--text-secondary)">Conditional</span>
        </div>
        <p class="text-sm text-(--text-secondary) mt-2 ml-10">
          Removes blocked tools from request (name-only rules). Active when block rules exist in <a href={thref(slug, '/policy')} class="text-(--accent) hover:underline">risk rules</a>.
        </p>
      </div>
      <div class="w-0 h-7 border-l-2 border-dashed border-(--border)"></div>

      <!-- ④ Script Chain -->
      {@render scriptChain()}
      <div class="w-0 h-7 border-l-2 border-dashed border-(--border)"></div>

      <!-- ⑤ Stream Options -->
      <div class="w-full rounded-xl border border-(--border) bg-(--bg-card) p-5">
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-3">
            <span class="w-7 h-7 flex items-center justify-center rounded-full bg-(--bg-elevated) text-sm font-mono text-(--text-secondary)">5</span>
            <span class="font-semibold text-(--text-primary)">Stream Options</span>
            <span class="px-2 py-0.5 text-xs rounded-sm bg-(--bg-elevated) text-(--text-secondary)">System</span>
          </div>
          <span class="text-xs text-(--success)">Always</span>
        </div>
        <p class="text-sm text-(--text-secondary) mt-2 ml-10">Injects stream_options.include_usage for streaming ChatCompletions to capture token usage from upstream.</p>
      </div>
      <div class="w-0 h-7 border-l-2 border-dashed border-(--border)"></div>

      <!-- ⑥ Convert to Upstream Protocol -->
      <div class="w-full rounded-xl border border-(--border) bg-(--bg-card) p-5">
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-3">
            <span class="w-7 h-7 flex items-center justify-center rounded-full bg-(--bg-elevated) text-sm font-mono text-(--text-secondary)">6</span>
            <span class="font-semibold text-(--text-primary)">Convert to Upstream Protocol</span>
            <span class="px-2 py-0.5 text-xs rounded-sm bg-(--bg-elevated) text-(--text-secondary)">System</span>
          </div>
          <span class="text-xs text-(--warning)">Auto</span>
        </div>
        <p class="text-sm text-(--text-secondary) mt-2 ml-10">Serializes the transformed request into the upstream's protocol format via DomainRequest hub. Passthrough when client and upstream use the same protocol.</p>
      </div>
      <div class="w-0 h-7 border-l-2 border-dashed border-(--border)"></div>

      <div class="w-full text-center py-3 px-6 rounded-lg bg-(--bg-secondary) border border-(--border) text-sm text-(--text-secondary) font-mono tracking-widest uppercase">Upstream</div>
    </div>

  {:else if activeTab === 'response'}
    <!-- RESPONSE Pipeline Visualization -->
    <div class="flex flex-col items-center gap-0">
      <div class="w-full text-center py-3 px-6 rounded-lg bg-(--bg-secondary) border border-(--border) text-sm text-(--text-secondary) font-mono tracking-widest uppercase">Upstream Response</div>
      <div class="w-0 h-7 border-l-2 border-dashed border-(--border)"></div>

      <!-- ① Block Accumulator (SSE only) -->
      <div class="w-full rounded-xl bg-(--tag-cyan-bg)/40 p-5">
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-3">
            <span class="w-7 h-7 flex items-center justify-center rounded-full bg-(--tag-cyan-bg) text-sm font-mono text-(--tag-cyan-text)">1</span>
            <span class="font-semibold text-(--text-primary)">Block Accumulator</span>
            <TagBadge color="cyan" class="text-xs">SSE only</TagBadge>
          </div>
          <span class="text-xs text-(--warning)">Auto</span>
        </div>
        <p class="text-sm text-(--text-secondary) mt-2 ml-10">
          <strong class="text-(--text-primary)">Streaming responses:</strong> buffers SSE events into complete content blocks (text, tool_use, thinking) so they can be inspected before reaching the client.
          Activated when response scripts or argument-based <a href={thref(slug, '/policy')} class="text-(--accent) hover:underline">tool block rules</a> exist.
          When inactive, events pass through with zero overhead (fast path).
        </p>
        <p class="text-sm text-(--text-secondary) mt-2 ml-10">
          <strong class="text-(--text-primary)">Non-streaming responses:</strong> the full JSON body is already buffered — no accumulation needed, policy is applied directly on the complete response.
        </p>
      </div>
      <div class="w-0 h-7 border-l-2 border-dashed border-(--border)"></div>

      <!-- ② Tool Policy (arg-based) -->
      <div class="w-full rounded-xl border border-(--error)/30 bg-(--error-bg) p-5">
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-3">
            <span class="w-7 h-7 flex items-center justify-center rounded-full bg-(--error)/20 text-sm font-mono text-(--error)">!</span>
            <span class="font-semibold text-(--text-primary)">Tool Policy (Arguments)</span>
            <span class="px-2 py-0.5 text-xs rounded-sm bg-(--error-bg) text-(--error)">Block</span>
          </div>
          <span class="text-xs text-(--text-secondary)">Conditional</span>
        </div>
        <p class="text-sm text-(--text-secondary) mt-2 ml-10">
          Checks tool calls against argument-aware
          <a href={thref(slug, '/policy')} class="text-(--accent) hover:underline">risk rules</a>
          (`phase: response, scope: tool_calls`). Block actions suppress the call — the client sees a notice; replace actions rewrite args in place. Applies to both streaming and non-streaming responses.
        </p>
      </div>
      <div class="w-0 h-7 border-l-2 border-dashed border-(--border)"></div>

      <!-- ③ Script Chain (response phase) -->
      {@render scriptChain()}
      <div class="w-0 h-7 border-l-2 border-dashed border-(--border)"></div>

      <!-- ④ Protocol Translation -->
      <div class="w-full rounded-xl border border-(--border) bg-(--bg-card) p-5">
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-3">
            <span class="w-7 h-7 flex items-center justify-center rounded-full bg-(--bg-elevated) text-sm font-mono text-(--text-secondary)">4</span>
            <span class="font-semibold text-(--text-primary)">Protocol Translation</span>
            <span class="px-2 py-0.5 text-xs rounded-sm bg-(--bg-elevated) text-(--text-secondary)">System</span>
          </div>
          <span class="text-xs text-(--warning)">Auto</span>
        </div>
        <p class="text-sm text-(--text-secondary) mt-2 ml-10">Translates upstream response into the client's protocol format. Passthrough when same protocol. Handles token scaling, usage merge, and finish reason normalization.</p>
      </div>
      <div class="w-0 h-7 border-l-2 border-dashed border-(--border)"></div>

      <div class="w-full text-center py-3 px-6 rounded-lg bg-(--bg-secondary) border border-(--border) text-sm text-(--text-secondary) font-mono tracking-widest uppercase">Client</div>
    </div>

  {:else if activeTab === 'profiles'}
    <!-- Transform profiles: named program bundles a workspace can select. -->
    <div class="rounded-xl border border-(--border) bg-(--bg-card) p-5">
      <ProfilesManager kind="transform" activate={activeTab === 'profiles'} />
    </div>

  {:else if activeTab === 'suggestions'}
    <!-- Suggestions Tab -->
    <div>
      <h3 class="text-lg font-semibold text-(--text-primary) mb-3">Suggested Programs</h3>
      {#if pendingSuggestions.length === 0 && !showSuggestionHistory}
        <div class="text-center py-12 text-(--text-secondary)">
          <p>No pending transform suggestions. The LLM agent will propose programs based on session analysis.</p>
          {#if historySuggestions.length > 0}
            <button class="mt-2 text-xs text-(--accent) hover:underline" onclick={() => showSuggestionHistory = true}>
              Show {historySuggestions.length} reviewed suggestion{historySuggestions.length > 1 ? 's' : ''}
            </button>
          {/if}
        </div>
      {:else}
        <div class="space-y-4">
          {#each showSuggestionHistory ? suggestions : pendingSuggestions as s}
            <div class="border border-(--border) rounded-lg p-4">
              <div class="flex items-start justify-between">
                <div>
                  <div class="flex items-center gap-2">
                    <span class="px-2 py-0.5 text-xs rounded-sm bg-(--bg-primary) text-(--text-secondary)">{s.expert_axis}</span>
                    <h3 class="font-medium text-(--text-primary)">{s.title}</h3>
                    <span class="px-2 py-0.5 text-xs rounded-sm {s.status === 'pending' ? 'bg-(--warning-bg) text-(--warning)' : s.status === 'implemented' ? 'bg-(--success-bg) text-(--success)' : 'bg-(--bg-elevated) text-(--text-secondary)'}">{s.status}</span>
                  </div>
                  <p class="text-sm text-(--text-secondary) mt-1">{s.rationale}</p>
                  {#if s.proposed_phase || s.proposed_scope || s.proposed_model_filter || s.proposed_app_filter || s.proposed_match_mode === 'span'}
                    <div class="flex items-center gap-2 mt-1 flex-wrap">
                      {#if s.proposed_phase === 'response'}
                        <TagBadge color="cyan" class="text-xs">response</TagBadge>
                      {/if}
                      {#if s.proposed_scope}
                        <TagBadge color={scopeColor(s.proposed_scope)} class="text-xs">{s.proposed_scope}</TagBadge>
                      {/if}
                      {#if s.proposed_match_mode === 'span'}
                        <TagBadge color={s.proposed_scope ? scopeColor(s.proposed_scope) : 'indigo'} class="text-xs">per-match</TagBadge>
                      {/if}
                      {#if s.proposed_model_filter}
                        <TagBadge color={filterChipColor.models}>models: {s.proposed_model_filter}</TagBadge>
                      {/if}
                      {#if s.proposed_app_filter}
                        <TagBadge color={filterChipColor.apps}>apps: {s.proposed_app_filter}</TagBadge>
                      {/if}
                    </div>
                  {/if}
                  {#if s.proposed_trigger_regex}
                    <div class="mt-1 text-xs text-(--text-secondary) font-mono">
                      {s.proposed_match_mode === 'span' ? 'match' : 'trigger'}: {s.proposed_trigger_regex}
                    </div>
                  {/if}
                </div>
                {#if s.status === 'pending'}
                  <div class="flex gap-2 shrink-0 ml-4">
                    <button disabled={reviewingId !== null} onclick={() => handleSuggestion(s, 'approved')} class="px-3 py-1 text-xs rounded-sm bg-(--success) text-(--success-fg) hover:bg-(--success)/85 disabled:opacity-50 disabled:cursor-not-allowed">Approve</button>
                    <button disabled={reviewingId !== null} onclick={() => handleSuggestion(s, 'rejected')} class="px-3 py-1 text-xs rounded-sm border border-(--border) text-(--text-secondary) hover:bg-(--bg-elevated) hover:text-(--text-primary) disabled:opacity-50 disabled:cursor-not-allowed">Reject</button>
                  </div>
                {/if}
              </div>
              {#if s.status === 'pending' && suggestionsNewer[s.id]}
                <SuggestionRevisedNotice onshow={() => showNewer(s.id)} />
              {/if}
              <details class="mt-3">
                <summary class="text-xs text-(--text-secondary) cursor-pointer hover:text-(--text-primary)">View proposed source</summary>
                <pre class="mt-2 p-3 rounded-sm bg-(--bg-primary) text-xs text-(--text-secondary) overflow-x-auto font-mono">{s.proposed_source}</pre>
              </details>
            </div>
          {/each}
        </div>
        {#if !showSuggestionHistory && historySuggestions.length > 0}
          <button class="mt-4 text-xs text-(--text-secondary) hover:text-(--text-primary)" onclick={() => showSuggestionHistory = true}>
            Show {historySuggestions.length} reviewed suggestion{historySuggestions.length > 1 ? 's' : ''}
          </button>
        {:else if showSuggestionHistory && historySuggestions.length > 0}
          <button class="mt-4 text-xs text-(--text-secondary) hover:text-(--text-primary)" onclick={() => showSuggestionHistory = false}>
            Hide reviewed suggestions
          </button>
        {/if}
      {/if}

    </div>
  {/if}
</div>
