<script lang="ts">
  // Inline, self-contained, MULTI-SELECT workspace filter for the row-level
  // investigative pages (audit / sessions / tool-calls / admin-audit). The
  // value is a comma-separated set of workspace ids, URL-bound by the page's
  // `UrlFilters`, so a workspace-scoped view is shareable. Self-hides when the
  // tenant has a single workspace (nothing to narrow).
  //
  // The Agent workspace is just another entry — there is no separate "hide
  // agent" toggle. The DEFAULT (empty value) selects every workspace EXCEPT the
  // Agent one; tick it to include agent traffic, or narrow to any subset. An
  // empty value is the canonical "default" — committing a selection that equals
  // "all non-agent" stores `''` to keep the URL clean.
  import { consoleScope } from '#lib/scope.svelte.js';
  import FilterField from '#lib/components/filter/FilterField.svelte';

  let {
    value = $bindable(''),
    onchange,
  }: {
    value?: string;
    onchange?: () => void;
  } = $props();

  // Default workspace first, Agent workspace last, others by name in between.
  const sorted = $derived(
    [...consoleScope.workspaces].sort((a, b) => {
      const aAgent = a.role === 'agent';
      const bAgent = b.role === 'agent';
      if (aAgent !== bAgent) return aAgent ? 1 : -1;
      const aDefault = a.role === 'default';
      const bDefault = b.role === 'default';
      if (aDefault !== bDefault) return aDefault ? -1 : 1;
      return a.name.localeCompare(b.name);
    })
  );
  const allIds = $derived(sorted.map((w) => w.id));
  const nonAgentIds = $derived(sorted.filter((w) => w.role !== 'agent').map((w) => w.id));

  // Selected set — an empty value resolves to the default (all non-agent).
  const selected = $derived.by(() => {
    const sel = value
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    return new Set(sel.length > 0 ? sel : nonAgentIds);
  });

  function commit(next: Set<string>): void {
    const arr = allIds.filter((id) => next.has(id));
    const isDefault =
      arr.length === nonAgentIds.length && nonAgentIds.every((id) => next.has(id));
    value = isDefault ? '' : arr.join(',');
    onchange?.();
  }

  function toggle(id: string): void {
    const next = new Set(selected);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    commit(next);
  }

  const allSelected = $derived(allIds.length > 0 && allIds.every((id) => selected.has(id)));

  const label = $derived.by(() => {
    const arr = allIds.filter((id) => selected.has(id));
    if (arr.length === 0) return 'No workspaces';
    if (allSelected) return 'All workspaces';
    if (value === '') return 'All except agent';
    if (arr.length === 1) return sorted.find((w) => w.id === arr[0])?.name ?? '1 workspace';
    return `${arr.length} workspaces`;
  });

  const visible = $derived(consoleScope.workspaceCount >= 2);
</script>

{#if visible}
  <FilterField label="Workspace" class="min-w-40" for="ws-filter-summary">
    <details class="ws-filter">
      <summary id="ws-filter-summary">
        <span class="truncate">{label}</span>
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" aria-hidden="true">
          <path d="M6 9l6 6 6-6" />
        </svg>
      </summary>
      <div class="ws-panel">
        <div class="ws-actions">
          <button type="button" onclick={() => commit(new Set(allIds))} disabled={allSelected}>All</button>
          <button type="button" onclick={() => commit(new Set(nonAgentIds))} disabled={value === ''}>Default</button>
        </div>
        {#each sorted as w (w.id)}
          <label class="ws-row">
            <input type="checkbox" checked={selected.has(w.id)} onchange={() => toggle(w.id)} />
            <span class="truncate">{w.name}</span>
            {#if w.role === 'agent'}<span class="ws-tag">Agent</span>{/if}
            {#if w.role === 'default' && w.name.toLowerCase() !== 'default'}<span class="ws-tag">Default</span>{/if}
          </label>
        {/each}
      </div>
    </details>
  </FilterField>
{/if}

<style>
  .ws-filter {
    position: relative;
  }
  .ws-filter > summary {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.5rem;
    height: 2.25rem;
    padding: 0 0.625rem;
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 0.5rem;
    color: var(--text-primary);
    font-size: 0.875rem;
    font-weight: 500;
    cursor: pointer;
    list-style: none;
    white-space: nowrap;
  }
  .ws-filter > summary::-webkit-details-marker {
    display: none;
  }
  .ws-filter > summary:hover {
    border-color: var(--accent);
  }
  .ws-panel {
    position: absolute;
    z-index: 30;
    top: calc(100% + 0.25rem);
    left: 0;
    min-width: 100%;
    max-height: 18rem;
    overflow-y: auto;
    padding: 0.375rem;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 0.5rem;
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.35);
  }
  .ws-actions {
    display: flex;
    gap: 0.25rem;
    padding: 0.125rem 0.25rem 0.375rem;
    border-bottom: 1px solid var(--border);
    margin-bottom: 0.25rem;
  }
  .ws-actions > button {
    flex: 1;
    padding: 0.25rem 0.5rem;
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 0.375rem;
    color: var(--text-secondary);
    font-size: 0.75rem;
    font-weight: 600;
    cursor: pointer;
  }
  .ws-actions > button:hover:not(:disabled) {
    border-color: var(--accent);
    color: var(--text-primary);
  }
  .ws-actions > button:disabled {
    opacity: 0.45;
    cursor: default;
  }
  .ws-row {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.375rem 0.5rem;
    border-radius: 0.375rem;
    cursor: pointer;
    font-size: 0.875rem;
    color: var(--text-primary);
  }
  .ws-row:hover {
    background: var(--bg-hover);
  }
  .ws-row > input {
    accent-color: var(--accent);
  }
  .ws-tag {
    margin-left: auto;
    padding: 0.0625rem 0.375rem;
    background: var(--tag-neutral-bg);
    color: var(--tag-neutral-text);
    border-radius: 0.25rem;
    font-size: 0.625rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.03em;
  }
</style>
