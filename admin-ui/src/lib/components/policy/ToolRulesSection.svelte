<script lang="ts">
  import { toast } from '#lib/toast.svelte.js';
  import type { components } from '#lib/generated/api-types.js';
  import { adminApi } from '#lib/api-client.js';
  import { extractError, fetchAllPages } from '#lib/api-helpers.js';
  import { formatTimeAgo } from '#lib/formatters.js';
  import { CONFIG_USAGE_WINDOW_DAYS } from '#lib/constants.js';
  import { page } from '$app/state';
  import { goto } from '$app/navigation';
  import { thref } from '#lib/tenant.js';
  import RuleEditModal from '#lib/components/RuleEditModal.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import Modal from '#lib/components/Modal.svelte';
  import FrameworkChip from '#lib/components/FrameworkChip.svelte';
  import Icon from '#lib/components/Icon.svelte';

  type ToolRule = components['schemas']['Rule'];
  type ToolRuleListRow = components['schemas']['ToolRuleListItem'];
  type SecurityFramework = components['schemas']['SecurityFramework'];

  interface Props {
    inventoryToolNames?: string[];
    /** The profile whose effective rule set to edit (Default-as-base): for a
     *  Layered profile that is the Default's rules ⊕ its own; for the Default or a
     *  Standalone, its own rules. */
    profileId?: string;
    /** The tenant's Default tool profile id (the shared base). Rules tagged with
     *  it are *inherited* in a Layered profile view (read-only + "Customize here"). */
    baselineProfileId?: string;
    /** True when `profileId` is a Layered profile — its inherited Default rules
     *  render read-only. The Default and Standalone profiles own all their rules. */
    layered?: boolean;
    activate?: boolean;
  }

  let { inventoryToolNames = [], profileId, baselineProfileId, layered = false, activate = true }: Props = $props();

  let slug = $derived(page.params.slug ?? '');

  let toolRules = $state<ToolRuleListRow[]>([]);
  let rulesLoading = $state(false);
  let rulesError = $state<string | null>(null);
  let rulesSuccess = $state<string | null>(null);

  let filterQ = $state('');
  let filterRiskLevel = $state('');
  let filterAction = $state('');
  let filterSource = $state<'all' | 'builtin' | 'custom'>('all');
  let filterEnabled = $state<'all' | 'enabled' | 'disabled'>('all');

  let editModalOpen = $state(false);
  let editingRule = $state<ToolRule | null>(null);
  let resetModalOpen = $state(false);
  let resetRunning = $state(false);
  let deletingRule = $state<ToolRule | null>(null);

  let frameworks = $state<SecurityFramework[]>([]);
  let selectedFramework = $state<SecurityFramework | null>(null);

  export async function loadToolRules() {
    rulesLoading = true;
    rulesError = null;
    try {
      const shared = isSharedView;
      const pid = viewSel;
      toolRules = await fetchAllPages<ToolRuleListRow>((offset, limit) =>
        adminApi.GET('/api/v1/admin/tool-rules', {
          params: { query: {
            offset,
            limit,
            view: shared ? 'shared' : undefined,
            profile_id: shared ? undefined : pid,
            // /policy is a config page (no header period lens) — per-rule usage
            // stats render over a fixed recent window.
            days: CONFIG_USAGE_WINDOW_DAYS,
          } },
        }));
      const deepId = page.url.searchParams.get('rule_id');
      if (deepId && !editModalOpen) {
        const hit = toolRules.find((r) => r.id === deepId);
        if (hit) openEditRule(hit);
      }
    } catch (e) {
      rulesError = (e as Error).message;
    } finally {
      rulesLoading = false;
    }
  }

  export async function loadFrameworks() {
    if (frameworks.length > 0) return;
    try {
      const { data } = await adminApi.GET('/api/v1/admin/security-frameworks');
      if (data) frameworks = data.frameworks;
    } catch (e) {
      toast.error(extractError(e));
    }
  }

  function openCreateRule() {
    editingRule = null;
    editModalOpen = true;
  }

  function openEditRule(rule: ToolRule) {
    editingRule = rule;
    editModalOpen = true;
  }

  function handleRuleSaved(_saved: ToolRule) {
    flash(editingRule ? 'Rule updated.' : 'Rule created.');
    void loadToolRules();
  }

  // Copy-on-write: fork a shared rule into the current profile so it can diverge
  // here without affecting other profiles. POSTs a profile-specific copy linked
  // to the shared origin, then opens it for editing.
  async function customizeHere(shared: ToolRuleListRow) {
    if (isSharedView) return;
    const { error: err } = await adminApi.POST('/api/v1/admin/tool-rules', {
      body: {
        title: shared.title,
        description: shared.description,
        risk: shared.risk,
        phase: shared.phase,
        scope: shared.scope,
        match: shared.match,
        action: shared.action,
        priority: shared.priority,
        model_filter: shared.model_filter,
        app_filter: shared.app_filter,
        mcp_server_filter: shared.mcp_server_filter,
        a2a_agent_filter: shared.a2a_agent_filter,
        enabled: shared.enabled,
        framework_refs: shared.framework_refs,
        profile_id: viewSel,
        forked_from: shared.id,
      },
    });
    if (err) {
      rulesError = extractError(err, 'Failed to customize rule');
      return;
    }
    flash('Customized for this profile.');
    await loadToolRules();
    const fork = toolRules.find((r) => r.forked_from === shared.id && r.profile_id === viewSel);
    if (fork) openEditRule(fork);
  }

  async function toggleEnabled(rule: ToolRule) {
    const next = !(rule.enabled ?? true);
    const { error: err } = await adminApi.PATCH('/api/v1/admin/tool-rules/{id}', {
      params: { path: { id: rule.id } },
      body: { enabled: next },
    });
    if (err) {
      rulesError = extractError(err, 'Failed to toggle rule');
      return;
    }
    await loadToolRules();
  }

  async function moveRule(rule: ToolRule, direction: -1 | 1) {
    const current = toolRules.findIndex((r) => r.id === rule.id);
    if (current < 0) return;
    const target = current + direction;
    if (target < 0 || target >= toolRules.length) return;
    const { error: err } = await adminApi.PATCH('/api/v1/admin/tool-rules/{id}', {
      params: { path: { id: rule.id } },
      body: { position: target },
    });
    if (err) {
      rulesError = extractError(err, 'Failed to reorder');
      return;
    }
    await loadToolRules();
  }

  async function confirmDelete() {
    if (!deletingRule) return;
    const { error: err } = await adminApi.DELETE('/api/v1/admin/tool-rules/{id}', {
      params: { path: { id: deletingRule.id } },
    });
    if (err) {
      rulesError = extractError(err, 'Failed to delete');
      deletingRule = null;
      return;
    }
    deletingRule = null;
    flash('Rule deleted.');
    await loadToolRules();
  }

  async function runReset() {
    resetRunning = true;
    const { data, error: err } = await adminApi.POST('/api/v1/admin/tool-rules/actions/reset', {});
    resetRunning = false;
    resetModalOpen = false;
    if (err) {
      rulesError = extractError(err, 'Reset failed');
      return;
    }
    flash(data?.message ?? 'Builtins restored.');
    await loadToolRules();
  }

  function flash(msg: string) {
    rulesSuccess = msg;
    setTimeout(() => { if (rulesSuccess === msg) rulesSuccess = null; }, 3000);
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

  // The list shows exactly one scope, fixed by the drill-down route: the SHARED
  // baseline (applies to every profile) or one profile's effective set (its
  // specific rules + the shared baseline minus shared rules it has forked).
  // `viewSel` is the profile_id used in queries (SHARED in the baseline view).
  const SHARED = 'shared';
  const viewSel = $derived(profileId ?? SHARED);
  const isSharedView = $derived(viewSel === SHARED);

  let filteredRules: ToolRuleListRow[] = $derived.by(() => {
    return toolRules.filter((r) => {
      if (filterRiskLevel && r.risk !== filterRiskLevel) return false;
      if (filterAction) {
        const kind = r.action?.kind ?? 'classify';
        if (kind !== filterAction) return false;
      }
      if (filterSource === 'builtin' && !r.is_builtin) return false;
      if (filterSource === 'custom' && r.is_builtin) return false;
      if (filterEnabled === 'enabled' && !(r.enabled ?? true)) return false;
      if (filterEnabled === 'disabled' && (r.enabled ?? true)) return false;
      if (filterQ) {
        const needle = filterQ.toLowerCase();
        const condMatch = (r.match ?? []).some((c) => {
          if (c.target?.toLowerCase().includes(needle)) return true;
          const v = c.value as unknown;
          if (typeof v === 'string') return v.toLowerCase().includes(needle);
          if (Array.isArray(v)) return v.some((s) => typeof s === 'string' && s.toLowerCase().includes(needle));
          return false;
        });
        const hit =
          [r.id, r.title, r.description].some((v) => v?.toLowerCase().includes(needle)) ||
          condMatch;
        if (!hit) return false;
      }
      return true;
    });
  });

  function riskColor(risk: string): string {
    switch (risk) {
      case 'danger': return 'var(--error)';
      case 'caution': return 'var(--warning)';
      case 'unknown': return 'var(--text-secondary)';
      default: return 'var(--success)';
    }
  }

  function riskBg(risk: string): string {
    switch (risk) {
      case 'danger': return 'var(--error-bg)';
      case 'caution': return 'var(--warning-bg)';
      case 'unknown': return 'var(--bg-elevated)';
      default: return 'var(--success-bg)';
    }
  }

  // Load (and reload) whenever the tab is active and the selected view changes
  // — the initial view and any combo switch. Reads only viewSel/activate,
  // neither written by loadToolRules, so it can't loop.
  $effect(() => {
    void viewSel;
    if (activate) {
      void loadToolRules();
      void loadFrameworks();
    }
  });

  // A `?rule_id=` deep-link (from a blocked-tool banner) lands on the shared
  // drill-down without knowing which profile owns the rule. One unfiltered lookup
  // finds the owner: a shared rule opens here (the load effect handles it); a
  // profile-specific rule redirects to that profile's drill-down, where its own
  // load effect opens it.
  let deepResolved = $state(false);
  $effect(() => {
    if (!activate || deepResolved) return;
    const deepId = page.url.searchParams.get('rule_id');
    if (!deepId || !isSharedView) return;
    deepResolved = true;
    void (async () => {
      const all = await fetchAllPages<ToolRuleListRow>((offset, limit) =>
        adminApi.GET('/api/v1/admin/tool-rules', { params: { query: { offset, limit } } }));
      const hit = all.find((r) => r.id === deepId);
      if (hit && hit.profile_id) {
        void goto(thref(slug, `/policy/profiles/${hit.profile_id}?rule_id=${encodeURIComponent(deepId)}`));
      }
    })();
  });
</script>

{#if rulesLoading && toolRules.length === 0}
  <div class="flex items-center gap-3 py-12 justify-center text-(--text-secondary)">
    <div class="w-5 h-5 border-2 border-(--accent) border-t-transparent rounded-full animate-spin"></div>
    Loading tool rules…
  </div>
{:else}
  <div class="bg-(--bg-card) rounded-xl p-3 border border-(--border) mb-4">
    <div class="flex flex-wrap items-center gap-2">
      <button onclick={openCreateRule}
        class="px-3 py-1.5 bg-(--accent) text-(--accent-fg) rounded-lg text-sm font-medium hover:bg-(--accent-hover) transition-colors flex items-center gap-1">
        <Icon name="plus" size="sm" color="var(--accent-fg)" />
        Add Rule
      </button>
      <input type="search" bind:value={filterQ} placeholder="Search id, title, conditions…"
        class="flex-1 min-w-50 max-w-md px-3 py-1.5 bg-(--bg-primary) border border-(--border) rounded-lg text-sm focus:outline-hidden focus:border-(--accent)" />
      <SelectInput bind:value={filterRiskLevel} fluid={false}>
        <option value="">All risks</option>
        <option value="safe">Safe</option>
        <option value="caution">Caution</option>
        <option value="danger">Danger</option>
        <option value="unknown">Unknown</option>
      </SelectInput>
      <SelectInput bind:value={filterAction} fluid={false}>
        <option value="">All actions</option>
        <option value="classify">Classify only</option>
        <option value="block">Block</option>
        <option value="replace">Replace</option>
        <option value="substitute">Substitute</option>
        <option value="intercept_only">Intercept only</option>
      </SelectInput>
      <SelectInput bind:value={filterSource} fluid={false}>
        <option value="all">All sources</option>
        <option value="builtin">Builtin</option>
        <option value="custom">Custom</option>
      </SelectInput>
      <SelectInput bind:value={filterEnabled} fluid={false}>
        <option value="all">All states</option>
        <option value="enabled">Enabled</option>
        <option value="disabled">Disabled</option>
      </SelectInput>
      <button onclick={() => resetModalOpen = true}
        class="ml-auto px-3 py-1.5 text-xs border border-(--border) text-(--text-secondary) hover:text-(--text-primary) hover:border-(--error)/40 rounded-lg transition-colors">
        Reset builtins…
      </button>
    </div>
    <p class="text-[10px] text-(--text-secondary) mt-2">
      {#if layered}
        This profile builds on the Default — inherited rows are read-only; use <strong>Customize here</strong> to override one for this profile. First match wins — order matters.
      {:else}
        This profile's own rules. First match wins — order matters.
      {/if}
      {#if filteredRules.length !== toolRules.length}
        Showing <strong>{filteredRules.length}</strong> of <strong>{toolRules.length}</strong>.
      {:else}
        <strong>{toolRules.length}</strong> rule{toolRules.length === 1 ? '' : 's'}.
      {/if}
    </p>
  </div>

  {#if rulesError}
    <div class="p-3 rounded-lg bg-(--error-bg) text-(--error) text-sm mb-3">{rulesError}</div>
  {/if}
  {#if rulesSuccess}
    <div class="p-3 rounded-lg bg-(--success-bg) text-(--success) text-sm mb-3">{rulesSuccess}</div>
  {/if}

  <div class="space-y-2">
    {#if filteredRules.length === 0}
      <div class="bg-(--bg-card) rounded-xl border border-(--border) py-12 text-center">
        <p class="text-(--text-secondary)">No rules match your filters.</p>
        {#if toolRules.length === 0}
          <p class="text-sm text-(--text-secondary) mt-1">Click "Add Rule" to create one, or "Reset builtins…" to restore the shipped rule library.</p>
        {/if}
      </div>
    {:else}
      {#each filteredRules as rule (rule.id)}
        {@const rulePos = toolRules.findIndex((r) => r.id === rule.id)}
        {@const isEnabled = rule.enabled ?? true}
        {@const isInherited = layered && baselineProfileId != null && rule.profile_id === baselineProfileId}
        {@const isFork = !!rule.forked_from}
        {@const readOnly = isInherited}
        {@const matchSummary = (rule.match ?? [])
          .map((c) => {
            const v = c.value as unknown;
            const valStr = Array.isArray(v) ? v.join(',') : String(v ?? '');
            return `${c.target} ${c.op} ${valStr}`;
          })
          .join(' AND ')}
        <div id="rule-{rule.id}"
          class="bg-(--bg-card) rounded-xl border border-(--border) p-3 scroll-mt-24 {isEnabled ? '' : 'opacity-60'}">
          <div class="flex items-center gap-3">
            <span class="text-xs text-(--text-secondary) w-6 text-right shrink-0 font-mono">{rulePos + 1}</span>
            <div class="flex-1 min-w-0">
              <div class="flex items-center gap-2 flex-wrap">
                <span class="font-medium text-sm text-(--text-primary)">{rule.title || '(untitled)'}</span>
                <span class="text-[10px] font-mono px-1.5 py-0.5 rounded-sm bg-(--bg-primary) text-(--text-secondary) border border-(--border)">{rule.id}</span>
                <span class="inline-flex items-center px-1.5 py-0.5 rounded-full text-[10px] font-semibold uppercase border"
                  style="color: {riskColor(rule.risk)}; border-color: color-mix(in srgb, {riskColor(rule.risk)} 19%, transparent); background: {riskBg(rule.risk)}">{rule.risk}</span>
                {#if rule.action?.kind === 'block'}
                  <span class="inline-flex items-center px-1.5 py-0.5 rounded-sm text-[10px] font-semibold uppercase text-(--error) bg-(--error-bg) border border-(--error)/30">block</span>
                {:else if rule.action?.kind === 'replace'}
                  <span class="inline-flex items-center px-1.5 py-0.5 rounded-sm text-[10px] font-semibold uppercase text-(--tag-violet-text) bg-(--tag-violet-bg)">replace</span>
                {:else if rule.action?.kind === 'substitute'}
                  <span class="inline-flex items-center px-1.5 py-0.5 rounded-sm text-[10px] font-semibold uppercase text-(--tag-teal-text) bg-(--tag-teal-bg)">substitute</span>
                {:else if rule.action?.kind === 'intercept_only'}
                  <span class="inline-flex items-center px-1.5 py-0.5 rounded-sm text-[10px] font-semibold uppercase text-(--tag-blue-text) bg-(--tag-blue-bg)">intercept</span>
                {/if}
                <span class="inline-flex items-center px-1.5 py-0.5 rounded-sm text-[10px] font-medium uppercase text-(--text-secondary) bg-(--bg-elevated) border border-(--border)">{rule.phase}/{rule.scope}</span>
                {#if rule.model_filter}
                  <span class="inline-flex items-center px-1.5 py-0.5 rounded-sm text-[10px] font-medium text-(--text-secondary) bg-(--bg-elevated) border border-(--border)">model:{rule.model_filter}</span>
                {/if}
                {#if rule.app_filter}
                  <span class="inline-flex items-center px-1.5 py-0.5 rounded-sm text-[10px] font-medium text-(--text-secondary) bg-(--bg-elevated) border border-(--border)">app:{rule.app_filter}</span>
                {/if}
                {#if rule.mcp_server_filter}
                  <span class="inline-flex items-center px-1.5 py-0.5 rounded-sm text-[10px] font-medium text-(--text-secondary) bg-(--bg-elevated) border border-(--border)">mcp:{rule.mcp_server_filter}</span>
                {/if}
                {#if rule.a2a_agent_filter}
                  <span class="inline-flex items-center px-1.5 py-0.5 rounded-sm text-[10px] font-medium text-(--text-secondary) bg-(--bg-elevated) border border-(--border)">a2a:{rule.a2a_agent_filter}</span>
                {/if}
                {#if rule.is_builtin}
                  <span class="inline-flex items-center px-1.5 py-0.5 rounded-sm text-[10px] font-medium text-(--tag-blue-text) bg-(--tag-blue-bg)">builtin</span>
                {/if}
                {#if isFork}
                  <span class="inline-flex items-center px-1.5 py-0.5 rounded-sm text-[10px] font-medium text-(--tag-amber-text) bg-(--tag-amber-bg)">customized here</span>
                {:else if isInherited}
                  <span class="inline-flex items-center px-1.5 py-0.5 rounded-sm text-[10px] font-medium text-(--tag-teal-text) bg-(--tag-teal-bg)">inherited</span>
                {:else}
                  <span class="inline-flex items-center px-1.5 py-0.5 rounded-sm text-[10px] font-medium text-(--tag-indigo-text) bg-(--tag-indigo-bg)">this profile</span>
                {/if}
                {#if !isEnabled}
                  <span class="inline-flex items-center px-1.5 py-0.5 rounded-sm text-[10px] font-medium text-(--text-secondary) bg-(--bg-elevated) border border-(--border)">disabled</span>
                {/if}
                {#if rule.framework_refs && rule.framework_refs.length > 0}
                  {#each rule.framework_refs as ref}
                    <FrameworkChip id={ref} title={frameworkById(ref)?.title} compact onselect={openFrameworkDrawer} />
                  {/each}
                {/if}
              </div>
              <div class="text-[11px] font-mono text-(--text-secondary) mt-0.5 truncate">{matchSummary || '(catch-all)'}</div>
              {#if rule.description}
                <div class="text-[11px] text-(--text-secondary) mt-0.5 line-clamp-2">{rule.description}</div>
              {/if}
              <div class="text-[10px] text-(--text-secondary) mt-0.5">
                {#if rule.call_count_window > 0}
                  · {rule.call_count_window.toLocaleString()} call{rule.call_count_window !== 1 ? 's' : ''}
                  · {rule.tool_count_window.toLocaleString()} tool{rule.tool_count_window !== 1 ? 's' : ''}
                  {#if rule.last_seen}· {formatTimeAgo(rule.last_seen)}{/if}
                {:else}
                  · no activity ·
                {/if}
              </div>
            </div>
            <div class="flex items-center gap-1 shrink-0">
              {#if readOnly}
                <!-- A shared rule seen inside a profile: read-only here. Fork it
                     to diverge for this profile only. -->
                <button onclick={() => customizeHere(rule)}
                  class="px-2 py-1 text-[11px] rounded-sm border border-(--border) text-(--accent) hover:bg-(--bg-elevated) hover:border-(--accent) transition-colors">
                  Customize here →
                </button>
              {:else}
                <button onclick={() => toggleEnabled(rule)} aria-label={isEnabled ? 'Disable' : 'Enable'}
                  class="px-2 py-1 text-[10px] uppercase tracking-wider rounded-sm border border-(--border) hover:border-(--accent) text-(--text-secondary) hover:text-(--text-primary) transition-colors">
                  {isEnabled ? 'On' : 'Off'}
                </button>
                <button onclick={() => moveRule(rule, -1)} disabled={rulePos === 0} aria-label="Move up"
                  class="p-1 rounded-sm hover:bg-(--bg-elevated) text-(--text-secondary) hover:text-(--text-primary) disabled:opacity-30 disabled:cursor-not-allowed transition-colors">
                  <Icon name="chevronUp" size="sm" tone="neutral" />
                </button>
                <button onclick={() => moveRule(rule, 1)} disabled={rulePos === toolRules.length - 1} aria-label="Move down"
                  class="p-1 rounded-sm hover:bg-(--bg-elevated) text-(--text-secondary) hover:text-(--text-primary) disabled:opacity-30 disabled:cursor-not-allowed transition-colors">
                  <Icon name="chevronDown" size="sm" tone="neutral" />
                </button>
                <button onclick={() => openEditRule(rule)} aria-label="Edit"
                  title="Edit"
                  class="p-1 rounded-sm hover:bg-(--bg-elevated) text-(--text-secondary) hover:text-(--accent) transition-colors">
                  <Icon name="pencil" size="sm" tone="neutral" />
                </button>
                <button onclick={() => deletingRule = rule} aria-label={isFork ? 'Revert to shared' : 'Delete'}
                  title={isFork ? 'Revert to shared' : 'Delete'}
                  class="p-1 rounded-sm hover:bg-(--error-bg) text-(--text-secondary) hover:text-(--error) transition-colors">
                  <Icon name="trash" size="sm" tone="error" />
                </button>
              {/if}
            </div>
          </div>
        </div>
      {/each}
    {/if}
  </div>
{/if}

<RuleEditModal
  open={editModalOpen}
  initial={editingRule}
  inventory={inventoryToolNames}
  defaultProfileId={isSharedView ? undefined : viewSel}
  onclose={() => editModalOpen = false}
  onsaved={handleRuleSaved}
/>

<Modal open={resetModalOpen} title="Reset builtins" onclose={() => resetModalOpen = false}>
  <div class="py-2 space-y-3 text-sm">
    <p>Restore every builtin rule from the shipped seed and clear the <em>deleted builtins</em> list for this tenant.</p>
    <ul class="list-disc pl-5 text-(--text-secondary) space-y-1 text-xs">
      <li>Custom rules (created by you or approved from suggestions) are preserved.</li>
      <li>Any edits you've made to a builtin rule will be overwritten with the shipped version.</li>
      <li>Any builtin rules you previously deleted will reappear.</li>
    </ul>
  </div>
  {#snippet footer()}
    <div class="flex items-center justify-end gap-2">
      <button type="button" onclick={() => resetModalOpen = false}
        class="px-4 py-2 text-sm border border-(--border) rounded-lg hover:bg-(--bg-elevated) transition-colors">Cancel</button>
      <button type="button" onclick={runReset} disabled={resetRunning}
        class="px-4 py-2 bg-(--error)/90 text-(--error-fg) text-sm rounded-lg hover:bg-(--error) disabled:opacity-50 transition-colors">
        {resetRunning ? 'Resetting…' : 'Reset builtins'}
      </button>
    </div>
  {/snippet}
</Modal>

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

<Modal open={!!deletingRule} title="Delete rule" onclose={() => deletingRule = null}>
  <div class="py-2 space-y-3 text-sm">
    <p>Delete <strong>{deletingRule?.title || deletingRule?.id || '(untitled)'}</strong>?</p>
    {#if deletingRule?.is_builtin}
      <div class="p-3 rounded-lg bg-(--warning-bg) text-(--warning) text-xs">
        This is a builtin rule. Deleting it marks it as removed so startup sync won't resurrect it — you can always restore via "Reset builtins".
      </div>
    {/if}
  </div>
  {#snippet footer()}
    <div class="flex items-center justify-end gap-2">
      <button type="button" onclick={() => deletingRule = null}
        class="px-4 py-2 text-sm border border-(--border) rounded-lg hover:bg-(--bg-elevated) transition-colors">Cancel</button>
      <button type="button" onclick={confirmDelete}
        class="px-4 py-2 bg-(--error)/90 text-(--error-fg) text-sm rounded-lg hover:bg-(--error) transition-colors">Delete</button>
    </div>
  {/snippet}
</Modal>
