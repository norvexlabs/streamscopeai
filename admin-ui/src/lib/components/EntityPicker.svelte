<!--
  Reusable searchable single-select picker.

  An accessible combobox: type to search a (typically server-backed) list,
  arrow/enter to choose, escape/click-away to dismiss. Generic over the entity —
  pass a `search(query)` that returns `PickerItem`s. Used for the workspace
  member picker today; reuse it anywhere a list is too long for a native
  `<select>` (users, providers, …). The codebase has no other combobox, so this
  is the single home for typeahead selection.
-->
<script lang="ts" module>
  export interface PickerItem {
    id: string;
    label: string;
    sublabel?: string;
  }
</script>

<script lang="ts">
  import Icon from '#lib/components/Icon.svelte';

  let {
    search,
    value = $bindable(null),
    placeholder = 'Search…',
    disabled = false,
    emptyText = 'No matches',
    onselect,
  }: {
    /** Async search — returns matching items for the typed query. */
    search: (query: string) => Promise<PickerItem[]>;
    /** Currently-selected item (bindable). */
    value?: PickerItem | null;
    placeholder?: string;
    disabled?: boolean;
    emptyText?: string;
    onselect?: (item: PickerItem | null) => void;
  } = $props();

  let query = $state('');
  let results = $state<PickerItem[]>([]);
  let open = $state(false);
  let loading = $state(false);
  let activeIndex = $state(-1);
  let rootEl = $state<HTMLDivElement | undefined>();
  let inputEl = $state<HTMLInputElement | undefined>();
  let debounceTimer: ReturnType<typeof setTimeout> | undefined;
  // Monotonic token so a slow earlier search can't overwrite a newer one.
  let searchSeq = 0;

  function runSearch(q: string) {
    const seq = ++searchSeq;
    loading = true;
    search(q)
      .then((items) => {
        if (seq !== searchSeq) return; // a newer search superseded this one
        results = items;
        activeIndex = items.length > 0 ? 0 : -1;
      })
      .catch(() => {
        if (seq !== searchSeq) return;
        results = [];
        activeIndex = -1;
      })
      .finally(() => {
        if (seq === searchSeq) loading = false;
      });
  }

  function onInput() {
    open = true;
    value = null; // typing invalidates a prior selection
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => runSearch(query), 200);
  }

  function choose(item: PickerItem) {
    value = item;
    query = item.label;
    open = false;
    onselect?.(item);
  }

  function clear() {
    value = null;
    query = '';
    results = [];
    activeIndex = -1;
    onselect?.(null);
    inputEl?.focus();
  }

  function onFocus() {
    if (!disabled) {
      open = true;
      if (results.length === 0 && !value) runSearch(query);
    }
  }

  function onKeydown(e: KeyboardEvent) {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      open = true;
      if (results.length) activeIndex = (activeIndex + 1) % results.length;
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (results.length) activeIndex = (activeIndex - 1 + results.length) % results.length;
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (open && activeIndex >= 0 && results[activeIndex]) choose(results[activeIndex]);
    } else if (e.key === 'Escape') {
      open = false;
      inputEl?.blur();
    }
  }

  function onWindowClick(e: MouseEvent) {
    if (rootEl && !rootEl.contains(e.target as Node)) open = false;
  }
</script>

<svelte:window onclick={onWindowClick} />

<div bind:this={rootEl} class="relative">
  <div class="relative">
    <div class="absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none">
      <Icon name="search" size="sm" tone="neutral" />
    </div>
    <input
      bind:this={inputEl}
      bind:value={query}
      type="text"
      role="combobox"
      aria-expanded={open}
      aria-controls="entity-picker-list"
      autocomplete="off"
      {placeholder}
      {disabled}
      oninput={onInput}
      onfocus={onFocus}
      onkeydown={onKeydown}
      class="w-full pl-9 pr-8 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm placeholder:text-(--text-secondary) focus:outline-hidden focus:border-(--accent) transition-colors disabled:opacity-50"
    />
    {#if query}
      <button
        type="button"
        onclick={clear}
        class="absolute right-2.5 top-1/2 -translate-y-1/2 text-(--text-secondary) hover:text-(--text-primary) transition-colors"
        title="Clear"
      >
        <Icon name="close" size="sm" tone="neutral" />
      </button>
    {/if}
  </div>

  {#if open}
    <ul
      id="entity-picker-list"
      role="listbox"
      class="absolute z-30 mt-1 w-full max-h-64 overflow-auto rounded-lg border border-(--border) bg-(--bg-card) shadow-(--shadow-pop) py-1"
    >
      {#if loading}
        <li class="px-3 py-2 text-xs text-(--text-secondary)">Searching…</li>
      {:else if results.length === 0}
        <li class="px-3 py-2 text-xs text-(--text-secondary)">{emptyText}</li>
      {:else}
        {#each results as item, i (item.id)}
          <li role="option" aria-selected={activeIndex === i}>
            <button
              type="button"
              onclick={() => choose(item)}
              onmouseenter={() => (activeIndex = i)}
              class="w-full text-left px-3 py-2 flex flex-col gap-0.5 {activeIndex === i
                ? 'bg-(--bg-elevated)'
                : ''}"
            >
              <span class="text-sm text-(--text-primary) truncate">{item.label}</span>
              {#if item.sublabel}
                <span class="text-[10px] font-mono text-(--text-tertiary) truncate">{item.sublabel}</span>
              {/if}
            </button>
          </li>
        {/each}
      {/if}
    </ul>
  {/if}
</div>
