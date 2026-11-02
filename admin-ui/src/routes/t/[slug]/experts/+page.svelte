<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import { extractError, fetchAllPages } from '#lib/api-helpers.js';
  import type { AgentModelOption, AgentExpert, PromptSnippet } from '#lib/api-types.js';
  import { getTabFromUrl } from '#lib/tabs.js';
  import { EXPERT_COLORS } from '#lib/constants.js';
  import Tabs from '#lib/components/Tabs.svelte';
  import Modal from '#lib/components/Modal.svelte';
  import ExpertCard from '#lib/components/experts/ExpertCard.svelte';
  import JudgeModelSelect from '#lib/components/experts/JudgeModelSelect.svelte';
  import { EXPERT_INPUT_TYPES, EXPERT_OUTPUT_TYPES, inputTypeInfo, outputTypeInfo } from '#lib/colormaps/experts.js';
  import { usePeriodicLoad } from '#lib/hooks.svelte.js';
  import ProfilesManager from '#lib/components/policy/ProfilesManager.svelte';

  // Tab state — Profiles first, the uniform entry point for every policy kind.
  let activeTab = $state<'profiles' | 'experts' | 'prompts'>(
    getTabFromUrl(['profiles', 'experts', 'prompts'], 'profiles')
  );

  let experts = $state<AgentExpert[]>([]);

  let loading = $state(true);
  let error = $state<string | null>(null);

  // Expert form
  let showExpertForm = $state(false);
  let editingExpertId = $state<string | null>(null);
  let expertAxis = $state('');
  let expertPrompt = $state('');
  let expertEnabled = $state(true);
  let expertInputType = $state<string[]>(['session']);
  let expertOutputType = $state<string[]>(['transform_suggestion']);
  let expertModelOverride = $state('');
  let expertDescription = $state('');
  let expertColor = $state('');
  let expertMergeEnabled = $state(true);
  let savingExpert = $state(false);

  // Prompt snippets tab
  let snippets = $state<PromptSnippet[]>([]);
  let snippetsLoading = $state(false);
  let expandedSnippets = $state<Set<string>>(new Set());
  let snippetEdits = $state<Map<string, string>>(new Map());
  let savingSnippet = $state<string | null>(null);

  // Memory modal
  let showMemoryModal = $state(false);
  let memoryExpertId = $state<string | null>(null);
  let memoryExpertAxis = $state('');
  let memoryText = $state('');
  let savingMemory = $state(false);
  let memoryLoading = $state(false);

  // The expert edit modal uses this for its per-expert "Model Override"
  // picker (the per-profile judge model is edited on the profile page).
  let agentModels = $state<AgentModelOption[]>([]);
  // Until the list loads, the override picker shows a stored value as is
  // rather than calling it unserved.
  let agentModelsLoaded = $state(false);
  let agentModelsError = $state('');

  async function loadAgentModels() {
    const { data: res, error: err } = await adminApi.GET('/api/v1/admin/experts/agent-models');
    if (err || !res) {
      agentModelsLoaded = false;
      agentModelsError = extractError(err, 'Failed to load the model list');
      return;
    }
    agentModels = res.models;
    agentModelsLoaded = true;
    agentModelsError = '';
  }

  async function loadData() {
    loading = true;
    error = null;
    try {
      experts = await fetchAllPages((offset, limit) =>
        adminApi.GET('/api/v1/admin/experts', { params: { query: { offset, limit } } }));
    } catch (e: unknown) {
      // Surfaced by the inline `{#if error}` banner, matching this page's
      // mutation paths — no toast (would double-notify).
      error = e instanceof Error ? e.message : String(e);
    } finally {
      loading = false;
    }
  }

  async function loadSnippets() {
    snippetsLoading = true;
    try {
      snippets = await fetchAllPages((offset, limit) =>
        adminApi.GET('/api/v1/admin/experts/prompt-snippets', { params: { query: { offset, limit } } }));
    } catch (e: unknown) {
      console.warn('Failed to load snippets:', e);
    } finally {
      snippetsLoading = false;
    }
  }

  usePeriodicLoad(() => {
    loadData();
    loadAgentModels();
    loadSnippets();
  }, loadData);

  // Expert management functions
  const EXAMPLE_EXPERT_PROMPT = `You are an expert analyzing LLM sessions for user frustration and unresolved-question patterns that indicate a human support handoff or a documentation gap.

Focus areas:
- Frustration language: "this doesn't work", "still broken", "that's not what I asked", "forget it", profanity, all-caps emphasis
- Question-restating: user paraphrases the same intent 3+ times in one session, or returns next session with the same question
- Dead-end loops: assistant suggests step A, user reports failure, assistant suggests A again or a near-variant
- Escalation tells: "can I talk to a human", "is there support", "who do I contact", "this is urgent"
- Cross-session repetition: same user, same topic, multiple sessions without resolution — a documentation gap, not a model problem

IMPORTANT RULES:
- You analyze ONE session at a time. Use your memory to track patterns across sessions.
- When you spot a frustration or handoff signal, record the category in memory under the user's email with session count.
- When a single user has hit 3+ distinct frustration signals across separate sessions on the same topic, propose a transform (e.g. a system-prompt that offers an escalation path after N retries) and raise a minor alert.
- If a session contains an explicit human-handoff request that the assistant did not surface, raise a major alert immediately.
- Only propose transforms when memory shows a confirmed cross-session pattern. Never from a single session alone.
- Check "Previously Rejected Suggestions" before proposing.

Memory structure example:
## Tracked Users
- alice@example.com: "doesn't work" repetition (2 sessions), explicit handoff request (1), dead-end loop (1) → 3 signals, READY for transform
- bob@example.com: paraphrased restate (1 session) → watching

For each proposed program you MUST explain:
1. **description**: What the script does in plain language.
2. **rationale**: Why this is safe to apply to all traffic.`;

  function openCreateExpert() {
    editingExpertId = null;
    expertAxis = '';
    expertDescription = '';
    expertPrompt = EXAMPLE_EXPERT_PROMPT;
    expertEnabled = true;
    expertInputType = ['session'];
    expertOutputType = ['transform_suggestion'];
    expertModelOverride = '';
    expertColor = '';
    expertMergeEnabled = true;
    showExpertForm = true;
  }

  function openEditExpert(e: AgentExpert) {
    editingExpertId = e.id;
    expertAxis = e.axis;
    expertDescription = e.description || '';
    expertPrompt = e.prompt;
    expertEnabled = e.enabled;
    expertInputType = e.input_types || ['session'];
    expertOutputType = e.output_types || ['transform_suggestion'];
    expertModelOverride = e.model_override || '';
    expertColor = e.color || '';
    expertMergeEnabled = e.merge_enabled ?? true;
    showExpertForm = true;
  }

  async function saveExpert() {
    savingExpert = true;
    try {
      if (editingExpertId) {
        const { error: err } = await adminApi.PATCH('/api/v1/admin/experts/{id}', {
          params: { path: { id: editingExpertId } },
          body: {
            description: expertDescription || null,
            prompt: expertPrompt,
            enabled: expertEnabled,
            input_types: expertInputType,
            output_types: expertOutputType,
            model_override: expertModelOverride || null,
            color: expertColor || undefined,
            merge_enabled: expertMergeEnabled,
          },
        });
        if (err) { error = extractError(err, 'Unknown error'); savingExpert = false; return; }
      } else {
        const { error: err } = await adminApi.POST('/api/v1/admin/experts', {
          body: {
            axis: expertAxis,
            description: expertDescription || undefined,
            prompt: expertPrompt,
            enabled: expertEnabled,
            input_types: expertInputType,
            output_types: expertOutputType,
            model_override: expertModelOverride || undefined,
            merge_enabled: expertMergeEnabled,
          },
        });
        if (err) { error = extractError(err, 'Unknown error'); savingExpert = false; return; }
      }
      showExpertForm = false;
      await loadData();
    } catch (e: unknown) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      savingExpert = false;
    }
  }

  async function removeExpert(id: string, isBuiltin: boolean) {
    const msg = isBuiltin
      ? 'Delete this built-in expert? It stays deleted — restarts and upgrades do not bring it back.'
      : 'Delete this expert?';
    if (!confirm(msg)) return;
    try {
      const { error: err } = await adminApi.DELETE('/api/v1/admin/experts/{id}', { params: { path: { id } } });
      if (err) { error = extractError(err, 'Unknown error'); return; }
      await loadData();
    } catch (e: unknown) {
      error = e instanceof Error ? e.message : String(e);
    }
  }

  async function toggleExpert(e: AgentExpert) {
    try {
      const { error: err } = await adminApi.PATCH('/api/v1/admin/experts/{id}', {
        params: { path: { id: e.id } },
        body: { enabled: !e.enabled },
      });
      if (err) { error = extractError(err, 'Unknown error'); return; }
      await loadData();
    } catch (err: unknown) {
      error = err instanceof Error ? err.message : String(err);
    }
  }

  async function resetExpert(id: string) {
    try {
      const { error: err } = await adminApi.POST('/api/v1/admin/experts/{id}/actions/reset', { params: { path: { id } } });
      if (err) { error = extractError(err, 'Unknown error'); return; }
      await loadData();
    } catch (err: unknown) {
      error = err instanceof Error ? err.message : String(err);
    }
  }

  async function openMemory(e: AgentExpert) {
    memoryExpertId = e.id;
    memoryExpertAxis = e.axis;
    memoryLoading = true;
    showMemoryModal = true;
    try {
      const { data: res } = await adminApi.GET('/api/v1/admin/experts/{id}/memory', { params: { path: { id: e.id } } });
      memoryText = (res as { memory: string })?.memory ?? '';
    } catch {
      memoryText = '';
    } finally {
      memoryLoading = false;
    }
  }

  async function saveMemory() {
    if (!memoryExpertId) return;
    savingMemory = true;
    try {
      const { error: err } = await adminApi.PUT('/api/v1/admin/experts/{id}/memory', {
        params: { path: { id: memoryExpertId } },
        body: { memory: memoryText },
      });
      if (err) { error = extractError(err, 'Unknown error'); savingMemory = false; return; }
      showMemoryModal = false;
      await loadData();
    } catch (e: unknown) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      savingMemory = false;
    }
  }
</script>

<div>
  <div class="flex items-center justify-between mb-6">
    <div>
      <h1 class="text-2xl font-semibold text-(--text-primary)">Experts</h1>
      <p class="text-sm text-(--text-secondary) mt-1">LLM agent insights, session alerts, and transform suggestions</p>
    </div>
  </div>

  {#if error}
    <div class="p-3 rounded-lg bg-(--error-bg) text-(--error) text-sm mb-6">{error}</div>
  {/if}

  <!-- Tabs -->
  <Tabs tabs={[{id: 'profiles', label: 'Profiles'}, {id: 'experts', label: 'Definitions'}, {id: 'prompts', label: 'Prompts'}]} active={activeTab} onchange={(t) => { activeTab = t as typeof activeTab; if (t === 'prompts') loadSnippets(); }} class="mb-8" />

  <!-- ===== Experts Tab ===== -->
  {#if activeTab === 'experts'}

  <div class="bg-(--bg-card) rounded-xl border border-(--border)">
    <div class="flex items-center justify-between px-6 py-4 border-b border-(--border)">
      <div>
        <h3 class="text-sm font-semibold text-(--text-primary)">Expert definitions</h3>
        <p class="text-xs text-(--text-secondary) mt-0.5">Each expert is one angle the analysis agent reviews conversations from: what it reads, what it looks for, and what it may propose. Switching one off stops it in every profile; the Profiles tab chooses which run on which workspaces.</p>
      </div>
      <button onclick={openCreateExpert} class="px-4 py-2 bg-(--accent) text-(--accent-fg) rounded-lg hover:bg-(--accent-hover) text-sm font-medium">
        Create Expert
      </button>
    </div>

    {#if loading && experts.length === 0}
      <div class="px-6 py-8 text-center text-(--text-secondary) text-sm">Loading…</div>
    {:else if experts.length === 0}
      <div class="px-6 py-12 text-center">
        <p class="text-sm text-(--text-secondary)">No experts configured</p>
        <p class="text-xs text-(--text-secondary) mt-1">Create an expert to define how the agent analyzes sessions.</p>
      </div>
    {:else}
      <div class="grid gap-3 p-4 sm:grid-cols-2 xl:grid-cols-3">
        {#each experts as e (e.id)}
          <ExpertCard expert={e}>
            {#snippet control()}
              <button
                onclick={() => toggleExpert(e)}
                role="switch"
                aria-checked={e.enabled}
                aria-label="Enable {e.axis}"
                title={e.enabled ? 'On: runs in every profile that includes it' : 'Off: runs nowhere'}
                class="w-10 h-5 rounded-full transition-colors {e.enabled ? 'bg-(--success)' : 'bg-(--bg-elevated)'} relative"
              >
                <span class="absolute top-0.5 {e.enabled ? 'right-0.5' : 'left-0.5'} w-4 h-4 rounded-full bg-white ring-1 ring-(--bg-primary)/60 transition-all"></span>
              </button>
            {/snippet}
            {#snippet actions()}
              <button onclick={() => openEditExpert(e)} class="text-(--accent) hover:underline">Edit</button>
              <button onclick={() => openMemory(e)} class="text-(--tag-violet-text) hover:underline">Memory</button>
              <button onclick={() => resetExpert(e.id)} class="text-(--warning) hover:underline" title="Reset the watermark and rescan every session">Reset</button>
              <button onclick={() => removeExpert(e.id, !!e.is_builtin)} class="ml-auto text-(--error) hover:underline">Delete</button>
            {/snippet}
          </ExpertCard>
        {/each}
      </div>
    {/if}
  </div>

  {/if}

  <!-- ===== Prompts Tab ===== -->
  {#if activeTab === 'prompts'}

  <div class="bg-(--bg-card) rounded-xl border border-(--border)">
    <div class="px-6 py-4 border-b border-(--border)">
      <h3 class="text-sm font-semibold text-(--text-primary)">Feature Prompts</h3>
      <p class="text-xs text-(--text-secondary) mt-0.5">Each input and output feature has a prompt snippet automatically included for experts that use it. Edit the content to customize expert behavior.</p>
    </div>

    {#if snippetsLoading && snippets.length === 0}
      <div class="px-6 py-8 text-center text-(--text-secondary) text-sm">Loading snippets…</div>
    {:else if snippets.length === 0}
      <div class="px-6 py-12 text-center">
        <p class="text-sm text-(--text-secondary)">No prompt snippets found</p>
      </div>
    {:else}
      {@const inputSnippets = snippets.filter(s => EXPERT_INPUT_TYPES.includes(s.key))}
      {@const outputSnippets = snippets.filter(s => EXPERT_OUTPUT_TYPES.includes(s.key))}
      <!-- Every snippet is listed: one no type names (the pooled-analysis
           panel preamble) goes under Other rather than out of sight. -->
      {@const otherSnippets = snippets.filter(s => !EXPERT_INPUT_TYPES.includes(s.key) && !EXPERT_OUTPUT_TYPES.includes(s.key))}
      {@const expertUsage = (key: string) => {
        const count = (experts || []).filter((e: AgentExpert) => (e.input_types || []).includes(key) || (e.output_types || []).includes(key)).length;
        return count;
      }}

      {#snippet snippetRow(snippet: PromptSnippet)}
        {@const isExpanded = expandedSnippets.has(snippet.key)}
        {@const editedContent = snippetEdits.get(snippet.key) ?? snippet.content}
        {@const previewLines = snippet.content.split('\n').slice(0, 2).join('\n')}
        {@const usedBy = expertUsage(snippet.key)}
        <div class="px-6 py-4">
          <div class="flex items-center justify-between mb-1">
            <div class="flex items-center gap-2">
              <span class="font-medium text-sm text-(--text-primary)">{snippet.label}</span>
              <span class="text-xs text-(--text-secondary) font-mono">{snippet.key}</span>
              {#if usedBy > 0}
                <span class="px-1.5 py-0.5 text-[10px] rounded-sm bg-(--bg-primary) text-(--text-secondary)">Used by {usedBy} expert{usedBy !== 1 ? 's' : ''}</span>
              {/if}
              {#if !snippet.is_builtin}
                <span class="px-1.5 py-0.5 text-[10px] rounded-sm bg-(--warning-bg) text-(--warning)" title="Edited here: new releases leave it as it is">Edited</span>
              {/if}
            </div>
            <button
              onclick={() => {
                const next = new Set(expandedSnippets);
                if (isExpanded) { next.delete(snippet.key); } else { next.add(snippet.key); }
                expandedSnippets = next;
              }}
              class="text-(--accent) hover:underline text-xs"
            >{isExpanded ? 'Collapse' : 'Expand'}</button>
          </div>

          {#if !isExpanded}
            <pre class="text-xs text-(--text-secondary) font-mono whitespace-pre-wrap line-clamp-2 mt-1">{previewLines}</pre>
          {:else}
            <textarea
              value={editedContent}
              oninput={(ev) => { const m = new Map(snippetEdits); m.set(snippet.key, (ev.target as HTMLTextAreaElement).value); snippetEdits = m; }}
              class="w-full h-48 px-3 py-2 rounded-lg bg-(--bg-primary) border border-(--border) text-(--text-primary) text-sm font-mono resize-y mt-2"
              spellcheck="false"
            ></textarea>
            <div class="flex justify-end gap-2 mt-2">
              {#if !snippet.is_builtin}
                <button
                  onclick={async () => {
                    savingSnippet = snippet.key;
                    const { error: err } = await adminApi.POST('/api/v1/admin/experts/prompt-snippets/{key}/actions/restore-default', { params: { path: { key: snippet.key } } });
                    savingSnippet = null;
                    if (err) { error = extractError(err, 'Failed to restore the snippet'); return; }
                    const m = new Map(snippetEdits); m.delete(snippet.key); snippetEdits = m;
                    await loadSnippets();
                  }}
                  disabled={savingSnippet === snippet.key}
                  title="Replace this text with the shipped one; new releases then update it again"
                  class="px-4 py-1.5 text-sm border border-(--border) text-(--text-primary) rounded-lg hover:bg-(--bg-elevated) disabled:opacity-50"
                >Restore default</button>
              {/if}
              <button
                onclick={async () => {
                  savingSnippet = snippet.key;
                  const { error: err } = await adminApi.PUT('/api/v1/admin/experts/prompt-snippets/{key}', { params: { path: { key: snippet.key } }, body: { content: editedContent } });
                  savingSnippet = null;
                  if (err) { error = extractError(err, 'Failed to save the snippet'); return; }
                  const m = new Map(snippetEdits); m.delete(snippet.key); snippetEdits = m;
                  await loadSnippets();
                }}
                disabled={savingSnippet === snippet.key}
                class="px-4 py-1.5 text-sm bg-(--accent) text-(--accent-fg) rounded-lg hover:bg-(--accent-hover) disabled:opacity-50"
              >
                {savingSnippet === snippet.key ? 'Saving…' : 'Save'}
              </button>
            </div>
          {/if}
        </div>
      {/snippet}

      {#if inputSnippets.length > 0}
        <div class="px-6 pt-4 pb-2">
          <h4 class="text-xs font-semibold text-(--text-secondary) uppercase tracking-wider">Input Features</h4>
        </div>
        <div class="divide-y divide-(--border)">
          {#each inputSnippets as snippet (snippet.key)}
            {@render snippetRow(snippet)}
          {/each}
        </div>
      {/if}

      {#if outputSnippets.length > 0}
        <div class="px-6 pt-4 pb-2 {inputSnippets.length > 0 ? 'border-t border-(--border)' : ''}">
          <h4 class="text-xs font-semibold text-(--text-secondary) uppercase tracking-wider">Output Features</h4>
        </div>
        <div class="divide-y divide-(--border)">
          {#each outputSnippets as snippet (snippet.key)}
            {@render snippetRow(snippet)}
          {/each}
        </div>
      {/if}

      {#if otherSnippets.length > 0}
        <div class="px-6 pt-4 pb-2 border-t border-(--border)">
          <h4 class="text-xs font-semibold text-(--text-secondary) uppercase tracking-wider">Other</h4>
        </div>
        <div class="divide-y divide-(--border)">
          {#each otherSnippets as snippet (snippet.key)}
            {@render snippetRow(snippet)}
          {/each}
        </div>
      {/if}
    {/if}
  </div>

  {/if}

  <!-- ===== Profiles Tab ===== -->
  {#if activeTab === 'profiles'}
    <section>
      <div class="mb-4">
        <h3 class="text-sm font-semibold text-(--text-primary)">Expert profiles</h3>
        <p class="text-xs text-(--text-secondary) mt-0.5">
          Bundle experts into a profile, then assign the profile to a workspace (Workspaces →
          Access) to control which experts analyze that workspace's conversations.
        </p>
      </div>
      <ProfilesManager kind="expert" activate={activeTab === 'profiles'} />
    </section>
  {/if}
</div>

<!-- Memory Modal -->
<Modal open={showMemoryModal} title="Expert Memory: {memoryExpertAxis}" onclose={() => showMemoryModal = false}>
  <p class="text-xs text-(--text-secondary) mb-4">
    The agent builds this memory over time from analysis cycles. You can view, edit, or add instructions that the agent will see in future cycles.
  </p>

  {#if memoryLoading}
    <div class="text-sm text-(--text-secondary) py-8 text-center">Loading memory…</div>
  {:else}
    <textarea
      bind:value={memoryText}
      class="w-full h-80 px-3 py-2 rounded-lg bg-(--bg-primary) border border-(--border) text-(--text-primary) text-sm font-mono resize-y"
      spellcheck="false"
      placeholder="No memory yet. The agent will populate this after analysis cycles, or you can add instructions here."
    ></textarea>
  {/if}

  <div class="flex justify-end gap-3 mt-4">
    <button onclick={() => showMemoryModal = false} class="px-4 py-2 text-sm text-(--text-secondary) hover:text-(--text-primary)">Cancel</button>
    <button
      onclick={saveMemory}
      disabled={savingMemory || memoryLoading}
      class="px-4 py-2 text-sm bg-(--accent) text-(--accent-fg) rounded-lg hover:bg-(--accent-hover) disabled:opacity-50"
    >
      {savingMemory ? 'Saving…' : 'Save'}
    </button>
  </div>
</Modal>

<!-- Expert Form Modal -->
<Modal open={showExpertForm} title="{editingExpertId ? 'Edit' : 'Create'} Expert" onclose={() => showExpertForm = false} maxWidth="max-w-3xl">
  <div class="space-y-4">
    <div>
      <label class="block text-sm text-(--text-secondary) mb-1">Axis Name
        <input
          bind:value={expertAxis}
          disabled={!!editingExpertId}
          class="w-full px-3 py-2 rounded-lg bg-(--bg-primary) border border-(--border) text-(--text-primary) text-sm disabled:opacity-50"
          placeholder="e.g. compliance, cost_optimization"
        />
      </label>
      {#if !editingExpertId}
        <p class="text-xs text-(--text-secondary) mt-1">Snake_case identifier. Cannot be changed after creation.</p>
      {/if}
    </div>

    <div>
      <label class="block text-sm text-(--text-secondary) mb-1">Description
        <input
          bind:value={expertDescription}
          class="w-full px-3 py-2 rounded-lg bg-(--bg-primary) border border-(--border) text-(--text-primary) text-sm"
          placeholder="Short description of what this expert does"
        />
      </label>
    </div>

    <div class="flex items-center gap-2">
      <label class="flex items-center gap-2 text-sm text-(--text-secondary)">
        <input type="checkbox" bind:checked={expertEnabled} class="rounded-sm" />
        Enabled
      </label>
    </div>

    <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
      <div>
        <span class="block text-sm text-(--text-secondary) mb-1">Reads</span>
        <div class="space-y-1 px-3 py-2 rounded-lg bg-(--bg-primary) border border-(--border)">
          {#each EXPERT_INPUT_TYPES as t (t)}
            <label class="flex items-center gap-2 text-sm text-(--text-primary)" title={inputTypeInfo(t).hint}>
              <input type="checkbox" checked={expertInputType.includes(t)}
                onchange={(e) => { expertInputType = (e.target as HTMLInputElement).checked ? [...expertInputType, t] : expertInputType.filter((x) => x !== t); }} />
              {inputTypeInfo(t).label}
            </label>
          {/each}
        </div>
      </div>
      <div>
        <span class="block text-sm text-(--text-secondary) mb-1">Can propose</span>
        <div class="space-y-1 px-3 py-2 rounded-lg bg-(--bg-primary) border border-(--border)">
          {#each EXPERT_OUTPUT_TYPES as t (t)}
            <label class="flex items-center gap-2 text-sm text-(--text-primary)" title={outputTypeInfo(t).hint}>
              <input type="checkbox" checked={expertOutputType.includes(t)}
                onchange={(e) => { expertOutputType = (e.target as HTMLInputElement).checked ? [...expertOutputType, t] : expertOutputType.filter((x) => x !== t); }} />
              {outputTypeInfo(t).label}
            </label>
          {/each}
        </div>
      </div>
      <div>
        <label for="expert-model-override" class="block text-sm text-(--text-secondary) mb-1">Model Override</label>
        <JudgeModelSelect id="expert-model-override" bind:value={expertModelOverride} models={agentModels} loaded={agentModelsLoaded} emptyLabel="None: use the profile's judge model" />
        {#if agentModelsError}
          <p class="text-xs text-(--error-text) mt-1.5">{agentModelsError}: the list cannot be checked right now.</p>
        {/if}
      </div>
    </div>

    <div>
      <label class="flex items-center gap-2 text-sm text-(--text-primary)">
        <input type="checkbox" bind:checked={expertMergeEnabled} />
        Pooled analysis
      </label>
      <p class="text-xs text-(--text-secondary) mt-1">When on, this expert shares one analysis call per session/cluster with compatible experts (same input path, model, and workspace scope) — each axis still answers separately. Turn off to always analyze with a dedicated call.</p>
    </div>

    <!-- Color picker -->
    <div>
      <span class="block text-sm text-(--text-secondary) mb-1">Color</span>
      <div class="flex items-center gap-2 flex-wrap">
        <button
          onclick={() => expertColor = ''}
          class="w-7 h-7 rounded-full border-2 flex items-center justify-center {!expertColor ? 'border-(--accent)' : 'border-(--border)'} bg-(--bg-primary)"
          title="No color"
        >
          <span class="text-xs text-(--text-secondary)">--</span>
        </button>
        {#each EXPERT_COLORS as c}
          <button
            onclick={() => expertColor = c.value}
            class="w-7 h-7 rounded-full border-2 {expertColor === c.value ? 'border-white ring-1 ring-(--accent)' : 'border-transparent'}"
            style="background-color: {c.value}"
            title={c.label}
          ></button>
        {/each}
      </div>
    </div>

    <!-- Input/output type info box -->
    {#if !expertInputType.every(t => t === 'session') || !expertOutputType.every(t => t === 'transform_suggestion')}
      <div class="rounded-lg bg-(--bg-primary) border border-(--border) px-4 py-3 text-xs text-(--text-secondary) space-y-1">
        {#if expertInputType.includes('session_cluster')}
          <p><span class="text-(--text-primary) font-medium">Session Clusters:</span> The expert receives groups of related sessions (same user/app) for cross-session pattern analysis. Memory is especially important for tracking patterns over time.</p>
        {/if}
        {#if expertInputType.includes('tool_inventory')}
          <p><span class="text-(--text-primary) font-medium">Tool Inventory:</span> The expert receives aggregated tool usage data (tool names, call counts, risk levels) instead of individual session conversations.</p>
        {/if}
        {#if expertOutputType.includes('session_label')}
          <p><span class="text-(--text-primary) font-medium">Session Labels:</span> Instead of proposing transforms, the expert applies labels/tags to sessions for categorization and filtering.</p>
        {/if}
        {#if expertOutputType.includes('tool_rules')}
          <p><span class="text-(--text-primary) font-medium">Tool Rules:</span> The expert proposes tool risk classification rules (patterns, risk levels, block actions) instead of Rhai transforms.</p>
        {/if}
      </div>
    {/if}

    <div>
      <label class="block text-sm text-(--text-secondary) mb-1">System Prompt
        <p class="text-xs text-(--text-secondary) mb-2">Your prompt defines what the expert looks for. Prompt snippets are assembled dynamically based on the input/output types selected above. Edit snippets in the Prompts tab.</p>
        <textarea
          bind:value={expertPrompt}
          class="w-full h-96 px-3 py-2 rounded-lg bg-(--bg-primary) border border-(--border) text-(--text-primary) text-sm font-mono resize-y"
          spellcheck="false"
        ></textarea>
      </label>

      <details class="mt-2 text-xs text-(--text-secondary)">
        <summary class="cursor-pointer hover:text-(--text-primary) select-none">What your expert receives and must output</summary>
        <div class="mt-2 space-y-2 pl-2 border-l-2 border-(--border)">
          <div>
            <span class="font-semibold text-(--text-primary)">Input (varies by input_types):</span>
            <strong>session</strong> — metadata (model, user, app, tokens, cost, duration, errors), conversation (system prompt, messages, tool calls, compaction, time gaps), active transforms, rejected suggestions.
            <strong>session_cluster</strong> — grouped sessions by (key_id, app_id) with timeline.
            <strong>tool_inventory</strong> — aggregated tool usage with per-call risk classification and rule stats.
            <strong>memory</strong> — expert's persistent memory (4K cap, full replacement).
          </div>
          <div>
            <span class="font-semibold text-(--text-primary)">Output (varies by output_types):</span>
            <code class="text-[10px] bg-(--bg-primary) px-1 rounded-sm">findings[]</code>,
            <code class="text-[10px] bg-(--bg-primary) px-1 rounded-sm">proposed_programs[]</code> (transform_suggestion),
            <code class="text-[10px] bg-(--bg-primary) px-1 rounded-sm">proposed_tool_rules[]</code> (tool_rules),
            <code class="text-[10px] bg-(--bg-primary) px-1 rounded-sm">session_labels[]</code> (session_label),
            <code class="text-[10px] bg-(--bg-primary) px-1 rounded-sm">alert_level/alert_note</code> (alert),
            <code class="text-[10px] bg-(--bg-primary) px-1 rounded-sm">memory_update</code> (memory).
            Only fields matching the expert's output_types appear in the tool schema.
          </div>
          <div>
            <span class="font-semibold text-(--text-primary)">System-provided context:</span>
            <strong>Prompt snippets</strong> — assembled per input/output type (editable in Prompts tab).
            <strong>Output</strong> — enforced via dynamic tool calling schema (submit_analysis), no JSON in prompt needed.
          </div>
        </div>
      </details>
    </div>

    <div class="flex justify-end gap-3">
      <button onclick={() => showExpertForm = false} class="px-4 py-2 text-sm text-(--text-secondary) hover:text-(--text-primary)">Cancel</button>
      <button
        onclick={saveExpert}
        disabled={savingExpert || !expertAxis || !expertPrompt}
        class="px-4 py-2 text-sm bg-(--accent) text-(--accent-fg) rounded-lg hover:bg-(--accent-hover) disabled:opacity-50"
      >
        {savingExpert ? 'Saving…' : (editingExpertId ? 'Update' : 'Create')}
      </button>
    </div>
  </div>
</Modal>
