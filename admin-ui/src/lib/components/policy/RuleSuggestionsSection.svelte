<script lang="ts">
  import type { ToolRuleSuggestion } from '#lib/api-types.js';
  import type { components } from '#lib/generated/api-types.js';
  import { adminApi } from '#lib/api-client.js';
  import { extractError, extractErrorCode, fetchAllPages } from '#lib/api-helpers.js';
  import { toast } from '#lib/toast.svelte.js';
  import { profileLists } from '#lib/scope.svelte.js';
  import FrameworkChip from '#lib/components/FrameworkChip.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import Modal from '#lib/components/Modal.svelte';
  import SuggestionRevisedNotice from '#lib/components/policy/SuggestionRevisedNotice.svelte';
  import { acceptNewer, mergeSuggestions, type MergedSuggestions } from '#lib/suggestion-merge.js';

  type SecurityFramework = components['schemas']['SecurityFramework'];

  interface Props {
    activate?: boolean;
  }

  let { activate = true }: Props = $props();

  let toolRuleSuggestions = $state<ToolRuleSuggestion[]>([]);
  /** Newer copies of pending rows still shown as the admin is reading them. */
  let toolRuleNewer = $state<Record<string, ToolRuleSuggestion>>({});
  function showMerged(m: MergedSuggestions<ToolRuleSuggestion>) {
    toolRuleSuggestions = m.rows;
    toolRuleNewer = m.newer;
  }
  const showNewer = (id: string) => showMerged(acceptNewer({ rows: toolRuleSuggestions, newer: toolRuleNewer }, id));
  let toolRuleSuggestionsLoading = $state(false);
  /** Flips true after the first load attempt completes (success OR empty list).
   * Gates the activate-effect so an empty server response doesn't re-fire
   * the load every reactive tick — the dependency set otherwise stays in the
   * "needs loading" shape (length=0 && !loading) and loops forever. */
  let loaded = $state(false);
  /** Suggestion id currently being approved/rejected — disables that row's
   * buttons and shows an inline "Reviewing…" hint. Per-suggestion (not
   * section-wide) so the operator can see exactly which row is in-flight
   * and other rows stay actionable. */
  let reviewingId = $state<string | null>(null);
  /** Per-suggestion target tool profile for approval ('' → tenant default).
   * Only surfaced when the tenant has more than one profile. */
  let approveProfile = $state<Record<string, string>>({});
  let frameworks = $state<SecurityFramework[]>([]);
  let frameworkSource = $state<'all' | 'traffic' | 'framework'>('all');
  let selectedFramework = $state<SecurityFramework | null>(null);
  let showToolRuleHistory = $state(false);

  export async function loadToolRuleSuggestions() {
    toolRuleSuggestionsLoading = true;
    try {
      const fetched = await fetchAllPages<ToolRuleSuggestion>((offset, limit) =>
        adminApi.GET('/api/v1/admin/experts/tool-rule-suggestions', { params: { query: { offset, limit } } }));
      showMerged(mergeSuggestions(toolRuleSuggestions, fetched));
    } catch (e) {
      toolRuleSuggestions = [];
      toast.error('Failed to load tool rule suggestions', { body: (e as Error).message });
    } finally {
      toolRuleSuggestionsLoading = false;
      loaded = true;
    }
  }

  async function loadFrameworks() {
    if (frameworks.length > 0) return;
    try {
      const { data } = await adminApi.GET('/api/v1/admin/security-frameworks');
      if (data) frameworks = data.frameworks;
    } catch (e) {
      toast.error(extractError(e));
    }
  }

  // Silent refresh — don't flip the section-wide loading flag (which would
  // hide every other row behind a spinner). A reviewed row moves to history
  // on its own thanks to the status filter.
  async function refreshToolRuleSuggestions() {
    try {
      const fetched = await fetchAllPages<ToolRuleSuggestion>((offset, limit) =>
        adminApi.GET('/api/v1/admin/experts/tool-rule-suggestions', { params: { query: { offset, limit } } }));
      showMerged(mergeSuggestions(toolRuleSuggestions, fetched));
    } catch (e) {
      toast.error(extractError(e));
    }
  }

  // Approval sends the content hash of the suggestion as shown, so an agent
  // re-proposal that rewrote it meanwhile is refused instead of installed.
  async function handleToolRuleSuggestion(suggestion: ToolRuleSuggestion, status: 'approved' | 'rejected') {
    if (reviewingId) return;
    const id = suggestion.id;
    reviewingId = id;
    try {
      // On approval, land the rule in the chosen profile ('' → tenant default).
      const { error: err } = status === 'approved'
        ? await adminApi.POST('/api/v1/admin/experts/tool-rule-suggestions/{id}/actions/approve', {
            params: { path: { id } },
            body: { content_hash: suggestion.content_hash, profile_id: approveProfile[id] || null },
          })
        : await adminApi.POST('/api/v1/admin/experts/tool-rule-suggestions/{id}/actions/reject', { params: { path: { id } } });
      if (err) {
        const code = extractErrorCode(err);
        if (code === 'suggestion_changed') {
          toast.error('Suggestion changed since you reviewed it', {
            body: 'The agent re-proposed it. It has been reloaded — review it again.',
            code,
          });
          await refreshToolRuleSuggestions();
          showNewer(id);
          return;
        }
        toast.error(`Failed to ${status === 'approved' ? 'approve' : 'reject'} suggestion`, {
          body: extractError(err),
          code: code ?? undefined,
        });
        return;
      }
      toast.success(status === 'approved' ? 'Suggestion approved — rule active.' : 'Suggestion rejected.');
      await refreshToolRuleSuggestions();
    } finally {
      reviewingId = null;
    }
  }

  function toolRuleRiskColor(risk: string): string {
    switch (risk) {
      case 'danger': return 'bg-(--error-bg) text-(--error)';
      case 'caution': return 'bg-(--tag-amber-bg) text-(--tag-amber-text)';
      case 'safe': return 'bg-(--tag-teal-bg) text-(--tag-teal-text)';
      default: return 'bg-(--bg-elevated) text-(--text-secondary)';
    }
  }

  function frameworkById(id: string): SecurityFramework | undefined {
    return frameworks.find((f) => f.id === id);
  }

  function openFrameworkDrawer(id: string) {
    const hit = frameworkById(id);
    if (hit) {
      selectedFramework = hit;
      return;
    }
    selectedFramework = {
      id,
      framework: 'unknown',
      version: '',
      title: id,
      summary: 'No details available for this framework id.',
      tool_risk_hints: [],
    };
  }

  // Tool profiles for the approve-target picker, default first. The picker also
  // offers "Shared (all profiles)" (the default choice). Hidden when no named
  // profile exists — then everything is shared anyway (zero ceremony).
  let profileOptions = $derived(
    [...profileLists.tools].sort(
      (a, b) => Number(b.is_default) - Number(a.is_default) || a.name.localeCompare(b.name)
    )
  );

  let pendingToolRuleSuggestions = $derived(toolRuleSuggestions.filter((s) => s.status === 'pending'));
  let historyToolRuleSuggestions = $derived(toolRuleSuggestions.filter((s) => s.status !== 'pending'));

  let filteredSuggestions = $derived.by(() => {
    const base = showToolRuleHistory ? toolRuleSuggestions : pendingToolRuleSuggestions;
    if (frameworkSource === 'all') return base;
    return base.filter((s) => {
      const hasRefs = (s.framework_refs ?? []).length > 0;
      return frameworkSource === 'framework' ? hasRefs : !hasRefs;
    });
  });

  $effect(() => {
    if (activate && !loaded && !toolRuleSuggestionsLoading) {
      void loadToolRuleSuggestions();
      void loadFrameworks();
    }
  });
</script>

{#if toolRuleSuggestionsLoading}
  <div class="flex items-center gap-3 py-12 justify-center text-(--text-secondary)">
    <div class="w-5 h-5 border-2 border-(--accent) border-t-transparent rounded-full animate-spin"></div>
    Loading tool rule suggestions…
  </div>
{:else if pendingToolRuleSuggestions.length === 0 && !showToolRuleHistory}
  <div class="text-center py-12 text-(--text-secondary)">
    <p>No pending tool rule suggestions. The LLM agent will propose rules based on session analysis.</p>
    {#if historyToolRuleSuggestions.length > 0}
      <button class="mt-2 text-xs text-(--accent) hover:underline" onclick={() => showToolRuleHistory = true}>
        Show {historyToolRuleSuggestions.length} reviewed suggestion{historyToolRuleSuggestions.length > 1 ? 's' : ''}
      </button>
    {/if}
  </div>
{:else}
  <div class="flex items-center justify-between mb-4 gap-3 flex-wrap">
    <p class="text-sm text-(--text-secondary)">Tool risk rules proposed by the LLM agent based on observed tool usage patterns.</p>
    <div class="flex items-center gap-1 bg-(--bg-primary) border border-(--border) rounded-lg p-0.5">
      {#each [['all', 'All'], ['traffic', 'Traffic-based'], ['framework', 'Framework-aligned']] as [key, label]}
        <button onclick={() => frameworkSource = key as typeof frameworkSource}
          class="px-3 py-1 text-xs rounded-sm {frameworkSource === key ? 'bg-(--accent)/20 text-(--accent)' : 'text-(--text-secondary) hover:text-(--text-primary)'} transition-colors">
          {label}
        </button>
      {/each}
    </div>
  </div>
  <div class="space-y-3">
    {#each filteredSuggestions as suggestion}
      {@const condList = (Array.isArray(suggestion.match_conditions) ? suggestion.match_conditions : []) as Array<{target?: string, op?: string, value?: unknown}>}
      {@const condSummary = condList
        .map((c) => {
          const v = c.value;
          const valStr = Array.isArray(v) ? v.join(',') : String(v ?? '');
          return `${c.target ?? '?'} ${c.op ?? '?'} ${valStr}`;
        })
        .join(' AND ')}
      {@const actionKind = (suggestion.action as { kind?: string } | null | undefined)?.kind ?? 'classify'}
      <div class="border border-(--border) rounded-lg p-4">
        <div class="flex items-center gap-2 mb-2">
          <span class="text-xs px-2 py-0.5 rounded-sm bg-(--tag-rose-bg) text-(--tag-rose-text)">Rule</span>
          <span class="text-xs px-2 py-0.5 rounded-sm bg-(--bg-elevated) text-(--text-secondary)">{suggestion.expert_axis}</span>
          <span class="font-medium text-sm text-(--text-primary)">{suggestion.title}</span>
          <span class="ml-auto text-xs px-2 py-0.5 rounded-sm {suggestion.status === 'pending' ? 'bg-(--warning-bg) text-(--warning)' : suggestion.status === 'implemented' ? 'bg-(--success-bg) text-(--tag-teal-text)' : 'bg-(--bg-elevated) text-(--text-secondary)'}">{suggestion.status}</span>
        </div>
        <div class="text-xs text-(--text-secondary) mb-2">
          <code class="bg-(--bg-secondary) px-1.5 py-0.5 rounded-sm">{condSummary || '(catch-all)'}</code>
          <span class="ml-2 px-1.5 py-0.5 rounded-sm {toolRuleRiskColor(suggestion.risk)}">{suggestion.risk}</span>
          <span class="ml-1 px-1.5 py-0.5 rounded-sm bg-(--bg-elevated) text-(--text-secondary)">{actionKind}</span>
          <span class="ml-1 px-1.5 py-0.5 rounded-sm bg-(--bg-elevated) text-(--text-secondary)">{suggestion.phase}/{suggestion.scope}</span>
          {#if suggestion.model_filter}
            <span class="ml-1 px-1.5 py-0.5 rounded-sm bg-(--bg-elevated) text-(--text-secondary)">model:{suggestion.model_filter}</span>
          {/if}
          {#if suggestion.app_filter}
            <span class="ml-1 px-1.5 py-0.5 rounded-sm bg-(--bg-elevated) text-(--text-secondary)">app:{suggestion.app_filter}</span>
          {/if}
          {#if suggestion.mcp_server_filter}
            <span class="ml-1 px-1.5 py-0.5 rounded-sm bg-(--bg-elevated) text-(--text-secondary)">mcp:{suggestion.mcp_server_filter}</span>
          {/if}
          <span class="ml-2 px-1.5 py-0.5 rounded-sm font-mono bg-(--bg-secondary) text-(--text-secondary) border border-(--border)">{suggestion.proposed_rule_id}</span>
        </div>
        {#if suggestion.rationale}
          <div class="mb-3">
            <div class="text-[10px] uppercase tracking-wider text-(--text-secondary) font-medium mb-1">Why</div>
            <p class="text-xs text-(--text-secondary) leading-relaxed">{suggestion.rationale}</p>
          </div>
        {/if}
        {#if suggestion.framework_refs && suggestion.framework_refs.length > 0}
          <div class="mb-3 flex flex-wrap gap-1">
            {#each suggestion.framework_refs as ref}
              <FrameworkChip id={ref} title={frameworkById(ref)?.title} onselect={openFrameworkDrawer} />
            {/each}
          </div>
        {/if}
        {#if suggestion.status === 'pending' && toolRuleNewer[suggestion.id]}
          <SuggestionRevisedNotice onshow={() => showNewer(suggestion.id)} />
        {/if}
        {#if suggestion.status === 'pending'}
          {@const inFlight = reviewingId === suggestion.id}
          {@const otherInFlight = !!reviewingId && !inFlight}
          <div class="flex items-center gap-2">
            {#if profileOptions.length > 1}
              <SelectInput value={approveProfile[suggestion.id] ?? ''}
                onchange={(e) => (approveProfile[suggestion.id] = (e.currentTarget as HTMLSelectElement).value)}
                disabled={inFlight || otherInFlight}
                fluid={false}
                aria-label="Apply to">
                <option value="">Shared (all profiles)</option>
                {#each profileOptions as p (p.id)}
                  <option value={p.id}>{p.name}{p.is_default ? ' (default)' : ''}</option>
                {/each}
              </SelectInput>
            {/if}
            <button class="text-xs px-3 py-1 bg-(--success) text-(--success-fg) rounded-sm hover:bg-(--success)/85 disabled:opacity-50 disabled:cursor-not-allowed"
              disabled={inFlight || otherInFlight}
              onclick={() => handleToolRuleSuggestion(suggestion, 'approved')}>Approve</button>
            <button class="text-xs px-3 py-1 bg-(--bg-elevated) text-(--text-secondary) rounded-sm hover:bg-(--bg-elevated)/85 disabled:opacity-50 disabled:cursor-not-allowed"
              disabled={inFlight || otherInFlight}
              onclick={() => handleToolRuleSuggestion(suggestion, 'rejected')}>Reject</button>
            {#if inFlight}
              <span class="flex items-center gap-1.5 text-xs text-(--text-secondary)">
                <span class="w-3 h-3 border-2 border-(--accent) border-t-transparent rounded-full animate-spin"></span>
                Reviewing…
              </span>
            {/if}
          </div>
        {/if}
      </div>
    {/each}
  </div>
  {#if !showToolRuleHistory && historyToolRuleSuggestions.length > 0}
    <button class="mt-4 text-xs text-(--text-secondary) hover:text-(--text-primary)" onclick={() => showToolRuleHistory = true}>
      Show {historyToolRuleSuggestions.length} reviewed suggestion{historyToolRuleSuggestions.length > 1 ? 's' : ''}
    </button>
  {:else if showToolRuleHistory && historyToolRuleSuggestions.length > 0}
    <button class="mt-4 text-xs text-(--text-secondary) hover:text-(--text-primary)" onclick={() => showToolRuleHistory = false}>
      Hide reviewed suggestions
    </button>
  {/if}
{/if}

<Modal open={!!selectedFramework} title={selectedFramework ? `${selectedFramework.id}: ${selectedFramework.title}` : ''} onclose={() => selectedFramework = null}>
  <div class="py-2 space-y-3 text-sm">
    {#if selectedFramework}
      <div class="flex flex-wrap items-center gap-2">
        <span class="text-xs px-2 py-0.5 rounded-sm bg-(--bg-elevated) text-(--text-secondary) font-mono">{selectedFramework.framework}</span>
        {#if selectedFramework.version}
          <span class="text-[10px] px-1.5 py-0.5 rounded-sm bg-(--bg-secondary) text-(--text-secondary)">v{selectedFramework.version}</span>
        {/if}
      </div>
      <p class="text-(--text-secondary) leading-relaxed">{selectedFramework.summary}</p>
      {#if selectedFramework.tool_risk_hints && selectedFramework.tool_risk_hints.length > 0}
        <div>
          <div class="text-[10px] uppercase tracking-wider text-(--text-secondary) font-medium mb-1">Tool-risk hints</div>
          <ul class="list-disc pl-5 text-xs text-(--text-secondary) space-y-1">
            {#each selectedFramework.tool_risk_hints as hint}
              <li>{hint}</li>
            {/each}
          </ul>
        </div>
      {/if}
    {/if}
  </div>
</Modal>
