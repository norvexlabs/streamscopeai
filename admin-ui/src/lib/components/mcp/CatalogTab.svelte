<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import { extractError, fetchAllPages } from '#lib/api-helpers.js';
  import type { components } from '#lib/generated/api-types.js';
  import Icon from '#lib/components/Icon.svelte';
  import TagBadge, { type TagColor } from '#lib/components/TagBadge.svelte';
  import FilterInput from '#lib/components/FilterInput.svelte';
  import EmptyState from '#lib/components/EmptyState.svelte';
  import Spinner from '#lib/components/Spinner.svelte';
  import Modal from '#lib/components/Modal.svelte';
  import ConfirmDialog from '#lib/components/ConfirmDialog.svelte';
  import CatalogAdoptModal from '#lib/components/mcp/CatalogAdoptModal.svelte';
  import CatalogEntryEditModal from '#lib/components/mcp/CatalogEntryEditModal.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import { toast } from '#lib/toast.svelte.js';
  import { onMount } from 'svelte';

  type CatalogEntry = components['schemas']['McpCatalogEntry'];

  // Lets the parent page send the operator to a just-adopted upstream's OAuth
  // form when a per_user_oauth server was adopted without its client.
  let { onConfigureOauth }: { onConfigureOauth?: (upstreamId: string) => void } = $props();

  let entries = $state<CatalogEntry[]>([]);
  let loading = $state(true);
  let error = $state('');

  let query = $state('');
  let category = $state('');
  let authMode = $state('');

  let selected = $state<CatalogEntry | null>(null);
  let adopting = $state<CatalogEntry | null>(null);
  let pendingDelete = $state<CatalogEntry | null>(null);
  let pendingReset = $state(false);
  // Edit/create: `editorOpen` gates the modal; `editing` null → create.
  let editorOpen = $state(false);
  let editing = $state<CatalogEntry | null>(null);

  const AUTH_LABELS: Record<string, { label: string; color: TagColor }> = {
    no_auth: { label: 'No auth', color: 'teal' },
    service_account: { label: 'API key', color: 'blue' },
    per_user_oauth: { label: 'OAuth', color: 'violet' },
    byot: { label: 'Client token', color: 'neutral' },
  };

  function authBadge(mode: string): { label: string; color: TagColor } {
    return AUTH_LABELS[mode] ?? { label: mode, color: 'neutral' };
  }

  // Endpoint URLs of upstream servers that already exist — an entry whose URL
  // matches is shown as already adopted.
  let adoptedUrls = $state<Set<string>>(new Set());

  async function load() {
    loading = true;
    error = '';
    try {
      entries = await fetchAllPages((offset, limit) =>
        adminApi.GET('/api/v1/admin/mcp/catalog', { params: { query: { offset, limit } } }));
    } catch (e) {
      error = extractError(e, 'Failed to load catalog');
    } finally {
      loading = false;
    }
  }

  async function loadAdopted() {
    try {
      const rows = await fetchAllPages<{ upstream_url: string }>((offset, limit) =>
        adminApi.GET('/api/v1/admin/mcp/upstream-servers', { params: { query: { offset, limit } } }));
      adoptedUrls = new Set(rows.map((r) => r.upstream_url));
    } catch {
      adoptedUrls = new Set();
    }
  }

  onMount(() => {
    void load();
    void loadAdopted();
  });

  function openAdopt(entry: CatalogEntry) {
    selected = null;
    adopting = entry;
  }

  function openCreate() {
    editing = null;
    editorOpen = true;
  }

  function openEdit(entry: CatalogEntry) {
    selected = null;
    editing = entry;
    editorOpen = true;
  }

  async function onEntrySaved() {
    editorOpen = false;
    editing = null;
    toast.success('Catalog entry saved');
    await load();
  }

  async function confirmDelete() {
    const entry = pendingDelete;
    if (!entry) return;
    pendingDelete = null;
    selected = null;
    const { error: err } = await adminApi.DELETE('/api/v1/admin/mcp/catalog/{id}', {
      params: { path: { id: entry.id } },
    });
    if (err) {
      toast.error('Failed to remove entry', { body: extractError(err) });
      return;
    }
    toast.success('Removed from catalog', entry.name);
    await load();
  }

  async function confirmReset() {
    pendingReset = false;
    const { data, error: err } = await adminApi.POST('/api/v1/admin/mcp/catalog/actions/reset', {});
    if (err) {
      toast.error('Failed to reset catalog', { body: extractError(err) });
      return;
    }
    toast.success('Catalog reset', data?.message ?? undefined);
    await load();
  }

  const categories = $derived.by(() => {
    const set = new Set<string>();
    for (const e of entries) if (e.category) set.add(e.category);
    return [...set].sort();
  });

  const filtered = $derived.by(() => {
    const q = query.trim().toLowerCase();
    return entries.filter((e) => {
      if (category && e.category !== category) return false;
      if (authMode && e.auth_mode !== authMode) return false;
      if (q) {
        const hay = `${e.name} ${e.description ?? ''} ${e.category ?? ''}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  });
</script>

<div class="bg-(--bg-card) rounded-xl border border-(--border)">
  <!-- Header -->
  <div class="flex items-center justify-between px-6 py-4 border-b border-(--border)">
    <div>
      <h3 class="text-lg font-semibold text-(--text-primary)">Server Catalog</h3>
      <p class="text-sm text-(--text-secondary) mt-1">
        Curated remote MCP servers. Browse, review tools and auth needs, then adopt one to wire it
        into your gateway in a single step.
      </p>
    </div>
    <div class="ml-4 flex shrink-0 items-center gap-2">
      <button
        type="button"
        class="px-4 py-2 border border-(--border) text-(--text-secondary) hover:bg-(--bg-primary) rounded-lg text-sm font-medium"
        onclick={() => (pendingReset = true)}
      >
        Reset catalog
      </button>
      <button
        type="button"
        class="px-4 py-2 bg-(--accent) text-(--accent-fg) hover:bg-(--accent-hover) rounded-lg text-sm font-medium"
        onclick={openCreate}
      >
        New entry
      </button>
    </div>
  </div>

  <!-- Toolbar -->
  <div class="flex flex-wrap items-center gap-3 px-6 py-4 border-b border-(--border)">
    <div class="min-w-[16rem] flex-1">
      <FilterInput
        bind:value={query}
        placeholder="Search servers…"
        matchInfo={`${filtered.length} of ${entries.length}`}
      />
    </div>
    <SelectInput bind:value={category} fluid={false}>
      <option value="">All categories</option>
      {#each categories as c}
        <option value={c}>{c}</option>
      {/each}
    </SelectInput>
    <SelectInput bind:value={authMode} fluid={false}>
      <option value="">All auth modes</option>
      <option value="no_auth">No auth</option>
      <option value="service_account">API key</option>
      <option value="per_user_oauth">OAuth</option>
      <option value="byot">Client token</option>
    </SelectInput>
  </div>

  {#if loading}
    <div class="flex justify-center py-12"><Spinner /></div>
  {:else if error}
    <div class="m-4 bg-(--error-bg) border border-(--error-border) rounded-lg p-3 text-sm text-(--error-text)">
      {error}
    </div>
  {:else if filtered.length === 0}
    <EmptyState
      title={entries.length === 0 ? 'No catalog entries' : 'No servers match your filters'}
      body={entries.length === 0
        ? 'The MCP server catalog has not been seeded for this tenant.'
        : 'Try clearing the search or filters.'}
    >
      {#snippet icon()}
        <Icon name="globe" size="lg" tone="neutral" />
      {/snippet}
    </EmptyState>
  {:else}
    <div class="grid grid-cols-1 gap-3 p-6 sm:grid-cols-2 lg:grid-cols-3">
      {#each filtered as entry (entry.id)}
        {@const ab = authBadge(entry.auth_mode)}
        <button
          type="button"
          onclick={() => (selected = entry)}
          class="flex flex-col gap-2 rounded-xl border border-(--border) bg-(--bg-primary) p-4 text-left transition-colors hover:border-(--accent)"
        >
          <div class="flex items-start gap-3">
            <div class="flex h-9 w-9 shrink-0 items-center justify-center overflow-hidden rounded-lg bg-(--bg-card)">
              {#if entry.icon_url}
                <img src={entry.icon_url} alt="" class="h-6 w-6 object-contain" loading="lazy" />
              {:else}
                <Icon name="globe" size="sm" tone="neutral" />
              {/if}
            </div>
            <div class="min-w-0 flex-1">
              <div class="flex items-center gap-1.5">
                <span class="truncate font-medium text-(--text-primary)">
                  {entry.display_title || entry.name}
                </span>
                {#if entry.featured}
                  <Icon name="sparkles" size="xs" tone="warning" />
                {/if}
              </div>
              {#if entry.description}
                <p class="mt-0.5 line-clamp-2 text-xs text-(--text-secondary)">{entry.description}</p>
              {/if}
            </div>
          </div>
          <div class="mt-auto flex flex-wrap items-center gap-1.5">
            {#if adoptedUrls.has(entry.upstream_url)}
              <TagBadge color="indigo">Adopted</TagBadge>
            {/if}
            {#if entry.category}
              <TagBadge color="cyan">{entry.category}</TagBadge>
            {/if}
            <TagBadge color={ab.color}>{ab.label}</TagBadge>
            {#if entry.liveness}
              <TagBadge color={entry.liveness === 'alive' ? 'teal' : 'amber'}>{entry.liveness}</TagBadge>
            {/if}
            {#if entry.tool_count}
              <span class="inline-flex items-center gap-1 text-xs text-(--text-secondary)">
                <Icon name="wrench" size="xs" tone="neutral" />{entry.tool_count}
              </span>
            {/if}
          </div>
        </button>
      {/each}
    </div>
  {/if}
</div>

<Modal
  open={selected !== null}
  title={selected?.display_title || selected?.name || 'Server'}
  onclose={() => (selected = null)}
  autoFocus="close-button"
  maxWidth="max-w-2xl"
>
  {#if selected}
    {@const ab = authBadge(selected.auth_mode)}
    <div class="space-y-4 text-sm">
      <div class="flex flex-wrap items-center gap-1.5">
        {#if selected.category}<TagBadge color="cyan">{selected.category}</TagBadge>{/if}
        <TagBadge color={ab.color}>{ab.label}</TagBadge>
        <TagBadge color="neutral">{selected.transport === 'sse' ? 'HTTP+SSE' : 'Streamable HTTP'}</TagBadge>
        {#if selected.liveness}<TagBadge color={selected.liveness === 'alive' ? 'teal' : 'amber'}>{selected.liveness}</TagBadge>{/if}
      </div>

      {#if selected.description}
        <p class="text-(--text-secondary)">{selected.description}</p>
      {/if}

      <div class="space-y-1">
        <div class="text-xs uppercase tracking-wide text-(--text-secondary)">Endpoint</div>
        <code class="block break-all rounded-sm bg-(--bg-primary) px-2 py-1 text-xs text-(--text-primary)">{selected.upstream_url}</code>
      </div>

      {#if selected.oauth_default_scopes.length > 0}
        <div class="space-y-1">
          <div class="text-xs uppercase tracking-wide text-(--text-secondary)">Default OAuth scopes</div>
          <div class="flex flex-wrap gap-1">
            {#each selected.oauth_default_scopes as scope}
              <code class="rounded-sm bg-(--bg-primary) px-1.5 py-0.5 text-xs text-(--text-secondary)">{scope}</code>
            {/each}
          </div>
        </div>
      {/if}

      {#if selected.tools.length > 0}
        <div class="space-y-1">
          <div class="text-xs uppercase tracking-wide text-(--text-secondary)">
            Tools ({selected.tools.length})
          </div>
          <ul class="max-h-60 space-y-1 overflow-y-auto">
            {#each selected.tools as tool}
              <li class="rounded-sm border border-(--border) px-2 py-1">
                <span class="font-mono text-xs text-(--text-primary)">{tool.name}</span>
                {#if tool.description}
                  <span class="block text-xs text-(--text-secondary)">{tool.description}</span>
                {/if}
              </li>
            {/each}
          </ul>
        </div>
      {/if}

      {#if selected.website_url || selected.repository_url}
        <div class="flex flex-wrap gap-3 pt-1">
          {#if selected.website_url}
            <a href={selected.website_url} target="_blank" rel="noopener noreferrer"
               class="inline-flex items-center gap-1 text-(--accent) hover:underline">
              <Icon name="externalLink" size="xs" tone="info" />Website
            </a>
          {/if}
          {#if selected.repository_url}
            <a href={selected.repository_url} target="_blank" rel="noopener noreferrer"
               class="inline-flex items-center gap-1 text-(--accent) hover:underline">
              <Icon name="externalLink" size="xs" tone="info" />Repository
            </a>
          {/if}
        </div>
      {/if}
    </div>
  {/if}

  {#snippet footer()}
    <button
      type="button"
      class="rounded-lg border border-(--border) px-3 py-2 text-sm text-(--error-text) hover:bg-(--error-bg)"
      onclick={() => (pendingDelete = selected)}
    >
      Remove from catalog
    </button>
    <button
      type="button"
      class="rounded-lg border border-(--border) px-3 py-2 text-sm text-(--text-secondary) hover:bg-(--bg-primary)"
      onclick={() => selected && openEdit(selected)}
    >
      Edit
    </button>
    <button
      type="button"
      class="rounded-lg bg-(--accent) px-3 py-2 text-sm font-medium text-(--accent-fg) hover:bg-(--accent-hover)"
      onclick={() => selected && openAdopt(selected)}
    >
      Adopt
    </button>
  {/snippet}
</Modal>

<CatalogAdoptModal
  entry={adopting}
  onclose={() => (adopting = null)}
  onadopted={(result) => {
    adopting = null;
    void loadAdopted();
    if (result.needsOauthConfig && result.upstreamId) {
      onConfigureOauth?.(result.upstreamId);
    }
  }}
/>

<CatalogEntryEditModal
  open={editorOpen}
  {editing}
  onclose={() => {
    editorOpen = false;
    editing = null;
  }}
  onsaved={onEntrySaved}
/>

<ConfirmDialog
  open={pendingDelete !== null}
  title="Remove from catalog"
  message={pendingDelete
    ? `Remove "${pendingDelete.name}" from the catalog? This only removes the catalog listing — any servers you already adopted from it keep working. Built-in entries stay removed until you reset the catalog.`
    : ''}
  confirmLabel="Remove"
  destructive
  onconfirm={confirmDelete}
  oncancel={() => (pendingDelete = null)}
/>

<ConfirmDialog
  open={pendingReset}
  title="Reset catalog"
  message="Restore the built-in catalog to its shipped state? Removed built-in entries come back; your custom entries are deleted."
  confirmLabel="Reset"
  destructive
  onconfirm={confirmReset}
  oncancel={() => (pendingReset = false)}
/>
