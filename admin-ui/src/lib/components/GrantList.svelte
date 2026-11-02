<!--
  What a workspace is granted of one kind (LLM providers, MCP servers, A2A
  agents): the granted entries with a Remove each, and "+ Add" over the
  candidates through the shared `EntityPicker`. The caller decides what is a
  candidate (never what is already granted, never what cannot be granted) and
  says in `unavailableNote` what it left out and why. `confirmRemove` returns
  the question to ask before a removal, or null to remove at once.
-->
<script lang="ts" module>
  export interface GrantEntry {
    id: string;
    label: string;
    sublabel?: string;
    /** A BYOK pass-through. */
    byok?: boolean;
    /** Granted but reaching nothing: its server is off. */
    off?: boolean;
    /** Why a granted entry does not work yet, shown under it. */
    warning?: string;
  }
</script>

<script lang="ts">
  import EntityPicker, { type PickerItem } from '#lib/components/EntityPicker.svelte';
  import ConfirmDialog from '#lib/components/ConfirmDialog.svelte';
  import EmptyState from '#lib/components/EmptyState.svelte';
  import ByokBadge from '#lib/components/ByokBadge.svelte';

  let {
    title,
    granted,
    candidates,
    unavailableNote = '',
    emptyTitle,
    emptyText,
    addPlaceholder,
    testid,
    onadd,
    onremove,
    confirmRemove,
  }: {
    title: string;
    granted: GrantEntry[];
    candidates: GrantEntry[];
    unavailableNote?: string;
    emptyTitle: string;
    emptyText: string;
    addPlaceholder: string;
    testid: string;
    /** Resolves `true` once the grant changed; on `false` the pick is kept. */
    onadd: (id: string) => Promise<boolean>;
    onremove: (id: string) => Promise<boolean>;
    confirmRemove?: (entry: GrantEntry) => string | null;
  } = $props();

  let picked = $state<PickerItem | null>(null);
  // Bumped after every grant change: the picker remounts with an empty query,
  // so it never offers what was just granted, and offers what was just removed.
  let pickerGen = $state(0);
  let busy = $state(false);
  let pendingRemove = $state<{ entry: GrantEntry; message: string } | null>(null);

  function search(query: string): Promise<PickerItem[]> {
    const q = query.trim().toLowerCase();
    return Promise.resolve(
      candidates
        .filter((c) => !q || c.label.toLowerCase().includes(q) || (c.sublabel ?? '').toLowerCase().includes(q))
        .map((c) => ({ id: c.id, label: c.label, sublabel: c.sublabel })),
    );
  }

  async function add() {
    if (!picked) return;
    busy = true;
    try {
      if (await onadd(picked.id)) {
        picked = null;
        pickerGen += 1;
      }
    } finally {
      busy = false;
    }
  }

  async function remove(entry: GrantEntry) {
    const message = confirmRemove?.(entry) ?? null;
    if (message) {
      pendingRemove = { entry, message };
      return;
    }
    await runRemove(entry.id);
  }

  async function runRemove(id: string) {
    busy = true;
    try {
      if (await onremove(id)) pickerGen += 1;
    } finally {
      busy = false;
    }
  }
</script>

<section class="space-y-3" data-testid={testid}>
  <h3 class="text-sm font-semibold text-(--text-primary)">
    {title}
    <span class="ml-1 text-xs font-normal text-(--text-secondary)">{granted.length}</span>
  </h3>
  {#if granted.length === 0}
    <EmptyState compact title={emptyTitle} body={emptyText} />
  {:else}
    <ul class="bg-(--bg-card) rounded-xl border border-(--border) divide-y divide-(--border)">
      {#each granted as entry (entry.id)}
        <li class="flex items-center justify-between gap-3 px-4 py-2.5" data-testid="grant-row">
          <div class="min-w-0">
          <div class="flex items-center gap-2">
            <span class="text-sm text-(--text-primary) truncate">{entry.label}</span>
            {#if entry.sublabel}<span class="text-xs text-(--text-secondary) truncate">{entry.sublabel}</span>{/if}
            {#if entry.byok}<ByokBadge title="BYOK pass-through — keyless; the client forwards its own credential." />{/if}
            {#if entry.off}
              <span
                class="px-1.5 py-0.5 rounded-sm text-xs font-medium bg-(--text-secondary)/15 text-(--text-secondary)"
                title="Its server is turned off in the LLM gateway, so this grant reaches nothing until it is turned on"
              >Off</span>
            {/if}
          </div>
          {#if entry.warning}<p class="mt-0.5 text-xs text-(--warning)">{entry.warning}</p>{/if}
          </div>
          <button
            onclick={() => remove(entry)}
            disabled={busy}
            class="shrink-0 text-xs text-(--error) hover:underline font-medium disabled:opacity-50"
          >Remove</button>
        </li>
      {/each}
    </ul>
  {/if}
  <div class="flex flex-col sm:flex-row gap-2 sm:items-start max-w-2xl">
    <div class="flex-1">
      {#key pickerGen}
        <EntityPicker {search} bind:value={picked} placeholder={addPlaceholder} emptyText="Nothing left to grant" disabled={busy} />
      {/key}
    </div>
    <button
      onclick={add}
      disabled={!picked || busy}
      class="px-4 py-2 text-sm rounded-lg bg-(--accent) text-(--accent-fg) hover:bg-(--accent-hover) disabled:opacity-50"
    >+ Add</button>
  </div>
  {#if unavailableNote}
    <p class="text-xs text-(--text-secondary)">{unavailableNote}</p>
  {/if}
</section>

<ConfirmDialog
  open={pendingRemove !== null}
  title="Remove grant"
  message={pendingRemove?.message ?? ''}
  confirmLabel="Remove"
  destructive
  onconfirm={() => {
    const id = pendingRemove?.entry.id;
    pendingRemove = null;
    if (id) void runRemove(id);
  }}
  oncancel={() => (pendingRemove = null)}
/>
