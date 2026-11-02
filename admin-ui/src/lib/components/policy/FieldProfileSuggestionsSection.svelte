<script lang="ts">
  import type { FieldProfileSuggestion } from '#lib/api-types.js';
  import { adminApi } from '#lib/api-client.js';
  import { extractError, extractErrorCode, fetchAllPages } from '#lib/api-helpers.js';
  import { toast } from '#lib/toast.svelte.js';
  import SuggestionRevisedNotice from '#lib/components/policy/SuggestionRevisedNotice.svelte';
  import { acceptNewer, mergeSuggestions, type MergedSuggestions } from '#lib/suggestion-merge.js';

  interface Props {
    activate?: boolean;
  }

  let { activate = true }: Props = $props();

  let suggestions = $state<FieldProfileSuggestion[]>([]);
  /** Newer copies of pending rows still shown as the admin is reading them. */
  let newer = $state<Record<string, FieldProfileSuggestion>>({});
  function showMerged(m: MergedSuggestions<FieldProfileSuggestion>) {
    suggestions = m.rows;
    newer = m.newer;
  }
  const showNewer = (id: string) => showMerged(acceptNewer({ rows: suggestions, newer }, id));
  let loading = $state(false);
  // Flips true after the first load attempt so an empty response doesn't
  // re-fire the activate-effect every reactive tick.
  let loaded = $state(false);
  let reviewingId = $state<string | null>(null);
  let showHistory = $state(false);

  export async function loadSuggestions() {
    loading = true;
    try {
      const fetched = await fetchAllPages<FieldProfileSuggestion>((offset, limit) =>
        adminApi.GET('/api/v1/admin/experts/field-profile-suggestions', { params: { query: { offset, limit } } }));
      showMerged(mergeSuggestions(suggestions, fetched));
    } catch (e) {
      suggestions = [];
      toast.error('Failed to load field profile suggestions', { body: (e as Error).message });
    } finally {
      loading = false;
      loaded = true;
    }
  }

  async function refreshSuggestions() {
    try {
      const fetched = await fetchAllPages<FieldProfileSuggestion>((offset, limit) =>
        adminApi.GET('/api/v1/admin/experts/field-profile-suggestions', { params: { query: { offset, limit } } }));
      showMerged(mergeSuggestions(suggestions, fetched));
    } catch (e) {
      toast.error(extractError(e));
    }
  }

  // Approval sends the content hash of the suggestion as shown, so an agent
  // re-proposal that rewrote it meanwhile is refused instead of installed.
  async function handleSuggestion(suggestion: FieldProfileSuggestion, status: 'approved' | 'rejected') {
    if (reviewingId) return;
    const id = suggestion.id;
    reviewingId = id;
    try {
      const { error: err } = status === 'approved'
        ? await adminApi.POST('/api/v1/admin/experts/field-profile-suggestions/{id}/actions/approve', {
            params: { path: { id } },
            body: { content_hash: suggestion.content_hash },
          })
        : await adminApi.POST('/api/v1/admin/experts/field-profile-suggestions/{id}/actions/reject', { params: { path: { id } } });
      if (err) {
        const code = extractErrorCode(err);
        if (code === 'suggestion_changed') {
          toast.error('Suggestion changed since you reviewed it', {
            body: 'The agent re-proposed it. It has been reloaded — review it again.',
            code,
          });
          await refreshSuggestions();
          showNewer(id);
          return;
        }
        toast.error(`Failed to ${status === 'approved' ? 'approve' : 'reject'} suggestion`, {
          body: extractError(err),
          code: code ?? undefined,
        });
        return;
      }
      toast.success(status === 'approved' ? 'Suggestion approved — field profile registered.' : 'Suggestion rejected.');
      await refreshSuggestions();
    } finally {
      reviewingId = null;
    }
  }

  let pending = $derived(suggestions.filter((s) => s.status === 'pending'));
  let history = $derived(suggestions.filter((s) => s.status !== 'pending'));
  let visible = $derived(showHistory ? suggestions : pending);

  $effect(() => {
    if (activate && !loaded && !loading) {
      void loadSuggestions();
    }
  });
</script>

{#if loading}
  <div class="flex items-center gap-3 py-12 justify-center text-(--text-secondary)">
    <div class="w-5 h-5 border-2 border-(--accent) border-t-transparent rounded-full animate-spin"></div>
    Loading field profile suggestions…
  </div>
{:else if pending.length === 0 && !showHistory}
  <div class="text-center py-12 text-(--text-secondary)">
    <p>No pending field profile suggestions. The LLM agent proposes profiles for uncovered tool fields it observes in traffic.</p>
    {#if history.length > 0}
      <button class="mt-2 text-xs text-(--accent) hover:underline" onclick={() => showHistory = true}>
        Show {history.length} reviewed suggestion{history.length > 1 ? 's' : ''}
      </button>
    {/if}
  </div>
{:else}
  <p class="text-sm text-(--text-secondary) mb-4">Tool field profiles proposed by the LLM agent for tool arguments not yet canonicalised — approving one lets policy rules target that argument by canonical <code class="bg-(--bg-secondary) px-1 py-0.5 rounded-sm">arg.&lt;field&gt;</code>.</p>
  <div class="space-y-3">
    {#each visible as suggestion}
      <div class="border border-(--border) rounded-lg p-4">
        <div class="flex items-center gap-2 mb-2 flex-wrap">
          <span class="text-xs px-2 py-0.5 rounded-sm bg-(--tag-teal-bg) text-(--tag-teal-text)">Field Profile</span>
          <span class="text-xs px-2 py-0.5 rounded-sm bg-(--bg-elevated) text-(--text-secondary)">{suggestion.expert_axis}</span>
          <span class="font-medium text-sm text-(--text-primary)">{suggestion.tool_id} · {suggestion.field}</span>
          <span class="ml-auto text-xs px-2 py-0.5 rounded-sm {suggestion.status === 'pending' ? 'bg-(--warning-bg) text-(--warning)' : suggestion.status === 'approved' ? 'bg-(--success-bg) text-(--tag-teal-text)' : 'bg-(--bg-elevated) text-(--text-secondary)'}">{suggestion.status}</span>
        </div>
        <div class="text-xs text-(--text-secondary) mb-2 flex flex-wrap gap-1 items-center">
          <span class="px-1.5 py-0.5 rounded-sm bg-(--bg-elevated)">tool: <code>{suggestion.tool_pattern}</code></span>
          <span class="px-1.5 py-0.5 rounded-sm bg-(--bg-elevated)">field: <code>{suggestion.field}</code></span>
          {#if suggestion.wire_field}
            <span class="px-1.5 py-0.5 rounded-sm bg-(--bg-elevated)">wire: <code>{suggestion.wire_field}</code></span>
          {/if}
          <span class="px-1.5 py-0.5 rounded-sm bg-(--tag-indigo-bg) text-(--tag-indigo-text)">norm: {suggestion.normalizer}</span>
          {#if suggestion.app_filter}
            <span class="px-1.5 py-0.5 rounded-sm bg-(--bg-elevated)">app:{suggestion.app_filter}</span>
          {/if}
          {#if suggestion.mcp_server}
            <span class="px-1.5 py-0.5 rounded-sm bg-(--bg-elevated)">mcp:{suggestion.mcp_server}</span>
          {/if}
          {#if suggestion.server_type}
            <span class="px-1.5 py-0.5 rounded-sm bg-(--bg-elevated)">server:{suggestion.server_type}</span>
          {/if}
        </div>
        {#if suggestion.rationale}
          <div class="mb-3">
            <div class="text-[10px] uppercase tracking-wider text-(--text-secondary) font-medium mb-1">Why</div>
            <p class="text-xs text-(--text-secondary) leading-relaxed">{suggestion.rationale}</p>
          </div>
        {/if}
        {#if suggestion.status === 'pending' && newer[suggestion.id]}
          <SuggestionRevisedNotice onshow={() => showNewer(suggestion.id)} />
        {/if}
        {#if suggestion.status === 'pending'}
          {@const inFlight = reviewingId === suggestion.id}
          {@const otherInFlight = !!reviewingId && !inFlight}
          <div class="flex items-center gap-2">
            <button class="text-xs px-3 py-1 bg-(--success) text-(--success-fg) rounded-sm hover:bg-(--success)/85 disabled:opacity-50 disabled:cursor-not-allowed"
              disabled={inFlight || otherInFlight}
              onclick={() => handleSuggestion(suggestion, 'approved')}>Approve</button>
            <button class="text-xs px-3 py-1 bg-(--bg-elevated) text-(--text-secondary) rounded-sm hover:bg-(--bg-elevated)/85 disabled:opacity-50 disabled:cursor-not-allowed"
              disabled={inFlight || otherInFlight}
              onclick={() => handleSuggestion(suggestion, 'rejected')}>Reject</button>
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
  {#if !showHistory && history.length > 0}
    <button class="mt-4 text-xs text-(--text-secondary) hover:text-(--text-primary)" onclick={() => showHistory = true}>
      Show {history.length} reviewed suggestion{history.length > 1 ? 's' : ''}
    </button>
  {:else if showHistory && history.length > 0}
    <button class="mt-4 text-xs text-(--text-secondary) hover:text-(--text-primary)" onclick={() => showHistory = false}>
      Hide reviewed suggestions
    </button>
  {/if}
{/if}
