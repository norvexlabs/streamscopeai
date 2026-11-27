<script lang="ts">
  // The badge filter of the browse views (Audit, Sessions), on both planes: a
  // multi-select of badge codes, URL-bound by the page's `UrlFilters` as a
  // comma-separated value. A row matches when it carries ANY picked badge.
  // The choices are the codes the listed kinds can carry (`surfaces`), grouped
  // by family; each says what it means. A value naming a code not offered
  // here (unknown, an alert, one the listed kinds cannot carry) reads as the
  // codes that are — the list sends the same (`offeredBadgeFilter`).
  import FilterField from '#lib/components/filter/FilterField.svelte';
  import {
    BADGE_REGISTRY,
    badgeFilterGroups,
    offeredBadgeFilter,
    type BadgeCode,
    type BadgeFamily,
    type BadgeSurface,
  } from '#lib/badges.js';
  import { m } from '#lib/paraglide/messages.js';

  let {
    value = $bindable(''),
    surfaces,
    onchange,
  }: {
    value?: string;
    /** The row kinds being listed: what the choices are narrowed to. */
    surfaces: readonly BadgeSurface[];
    onchange?: () => void;
  } = $props();

  const uid = $props.id();
  let query = $state('');
  let details = $state<HTMLDetailsElement | null>(null);

  // A click outside the panel, or Escape, closes it: two dropdowns of the bar
  // are never open over each other.
  function closeOutside(e: MouseEvent): void {
    if (details?.open && e.target instanceof Node && !details.contains(e.target)) details.open = false;
  }
  function closeOnEscape(e: KeyboardEvent): void {
    if (e.key === 'Escape' && details?.open) details.open = false;
  }

  const FAMILY_LABEL: Record<Exclude<BadgeFamily, 'alert'>, () => string> = {
    policy: m.browse_badge_family_policy,
    guardrail: m.browse_badge_family_guardrail,
    translation: m.browse_badge_family_translation,
    cache: m.browse_badge_family_cache,
    capacity: m.browse_badge_family_capacity,
    web: m.browse_badge_family_web,
    mcp: m.browse_badge_family_mcp,
    record: m.browse_badge_family_record,
  };

  const selected = $derived(new Set(offeredBadgeFilter(value, surfaces)));
  const groups = $derived.by(() => {
    const q = query.trim().toLowerCase();
    return badgeFilterGroups(surfaces)
      .map((g) => ({
        ...g,
        codes: q
          ? g.codes.filter((c) => BADGE_REGISTRY[c].label.toLowerCase().includes(q) || c.includes(q))
          : g.codes,
      }))
      .filter((g) => g.codes.length > 0);
  });

  const label = $derived.by(() => {
    const picked = [...selected];
    if (picked.length === 0) return m.browse_filter_badges_any();
    if (picked.length === 1) return BADGE_REGISTRY[picked[0]].label;
    return m.browse_filter_badges_count({ count: picked.length });
  });

  function commit(next: Set<BadgeCode>): void {
    value = [...next].sort().join(',');
    onchange?.();
  }

  function toggle(code: BadgeCode): void {
    const next = new Set(selected);
    if (next.has(code)) next.delete(code);
    else next.add(code);
    commit(next);
  }
</script>

<svelte:window onclick={closeOutside} onkeydown={closeOnEscape} />

<FilterField label={m.browse_filter_badges()} class="min-w-36" for="{uid}-summary">
  <details class="bp" bind:this={details}>
    <summary id="{uid}-summary">
      <span class="truncate">{label}</span>
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" aria-hidden="true">
        <path d="M6 9l6 6 6-6" />
      </svg>
    </summary>
    <div class="bp-panel">
      <div class="bp-actions">
        <input class="bp-search" type="search" bind:value={query} placeholder={m.browse_filter_badges_search()} aria-label={m.browse_filter_badges_search()} />
        <button type="button" onclick={() => commit(new Set())} disabled={selected.size === 0}>{m.browse_filter_badges_clear()}</button>
      </div>
      {#each groups as g (g.family)}
        <div class="bp-family">{FAMILY_LABEL[g.family]()}</div>
        {#each g.codes as code (code)}
          <label class="bp-row">
            <input type="checkbox" checked={selected.has(code)} onchange={() => toggle(code)} />
            <span class="bp-text">
              <span class="bp-label">{BADGE_REGISTRY[code].label}</span>
              <span class="bp-help">{BADGE_REGISTRY[code].help()}</span>
            </span>
          </label>
        {/each}
      {:else}
        <div class="bp-empty">{m.browse_filter_badges_none()}</div>
      {/each}
    </div>
  </details>
</FilterField>

<style>
  .bp {
    position: relative;
  }
  .bp > summary {
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
  .bp > summary::-webkit-details-marker {
    display: none;
  }
  .bp > summary:hover {
    border-color: var(--accent);
  }
  .bp-panel {
    position: absolute;
    z-index: 30;
    top: calc(100% + 0.25rem);
    left: 0;
    width: 24rem;
    max-width: calc(100vw - 2rem);
    max-height: 24rem;
    overflow-y: auto;
    padding: 0.375rem;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 0.5rem;
    box-shadow: var(--shadow-pop);
  }
  .bp-actions {
    display: flex;
    gap: 0.25rem;
    padding: 0.125rem 0.25rem 0.375rem;
    border-bottom: 1px solid var(--border);
    margin-bottom: 0.25rem;
  }
  .bp-search {
    flex: 1;
    min-width: 0;
    height: 1.75rem;
    padding: 0 0.5rem;
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 0.375rem;
    color: var(--text-primary);
    font-size: 0.75rem;
  }
  .bp-actions > button {
    padding: 0.25rem 0.5rem;
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 0.375rem;
    color: var(--text-secondary);
    font-size: 0.75rem;
    font-weight: 600;
    cursor: pointer;
  }
  .bp-actions > button:hover:not(:disabled) {
    border-color: var(--accent);
    color: var(--text-primary);
  }
  .bp-actions > button:disabled {
    opacity: 0.45;
    cursor: default;
  }
  .bp-family {
    padding: 0.5rem 0.5rem 0.25rem;
    color: var(--text-secondary);
    font-size: 0.625rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  .bp-row {
    display: flex;
    align-items: flex-start;
    gap: 0.5rem;
    padding: 0.375rem 0.5rem;
    border-radius: 0.375rem;
    cursor: pointer;
  }
  .bp-row:hover {
    background: var(--bg-hover);
  }
  .bp-row > input {
    margin-top: 0.1875rem;
    accent-color: var(--accent);
  }
  .bp-text {
    display: flex;
    flex-direction: column;
    gap: 0.125rem;
    min-width: 0;
  }
  .bp-label {
    color: var(--text-primary);
    font-size: 0.8125rem;
    font-weight: 500;
  }
  .bp-help {
    color: var(--text-secondary);
    font-size: 0.6875rem;
    line-height: 1.35;
    white-space: normal;
  }
  .bp-empty {
    padding: 0.5rem;
    color: var(--text-secondary);
    font-size: 0.75rem;
  }
</style>
