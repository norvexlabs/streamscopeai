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
  import LocalServerEditModal from '#lib/components/mcp/LocalServerEditModal.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import { toast } from '#lib/toast.svelte.js';
  import { authKind, catalogMeta, displayName, type AuthKind } from '#lib/mcp/serverJson.js';
  import { declaredInputs } from '#lib/mcp/headerInputs.js';
  import { onMount } from 'svelte';

  type CatalogEntry = components['schemas']['McpCatalogEntry'];
  type CatalogPackage = components['schemas']['McpCatalogPackage'];

  // Lets the parent page send the operator to a just-adopted upstream's OAuth
  // form when a per_user_oauth server was adopted without its client.
  let { onConfigureOauth }: { onConfigureOauth?: (upstreamId: string) => void } = $props();

  let entries = $state<CatalogEntry[]>([]);
  let loading = $state(true);
  let error = $state('');

  let query = $state('');
  let category = $state('');
  let authMode = $state<AuthKind | ''>('');

  let selected = $state<CatalogEntry | null>(null);
  let adopting = $state<CatalogEntry | null>(null);
  /// The package being added as a local server, with its entry.
  let adoptingPackage = $state<{ entry: CatalogEntry; pkg: CatalogPackage } | null>(null);
  let pendingDelete = $state<CatalogEntry | null>(null);
  let pendingReset = $state(false);
  // Edit/create: `editorOpen` gates the modal; `editing` null → create.
  let editorOpen = $state(false);
  let editing = $state<CatalogEntry | null>(null);
  /// Open the editor on its server.json view (the paste-import).
  let editorJson = $state(false);

  const AUTH_LABELS: Record<AuthKind, { label: string; color: TagColor }> = {
    none: { label: 'No auth', color: 'teal' },
    key: { label: 'API key', color: 'blue' },
    headers: { label: 'Headers', color: 'neutral' },
    oauth: { label: 'OAuth', color: 'violet' },
  };

  function authBadge(entry: CatalogEntry): { label: string; color: TagColor } {
    return AUTH_LABELS[authKind(entry.server_json)];
  }

  /** The plain facts a card and the detail view show, read once per entry. */
  function view(entry: CatalogEntry) {
    const sj = entry.server_json;
    const meta = catalogMeta(sj);
    return {
      title: displayName(sj),
      description: sj.description,
      icon: sj.icons?.[0]?.src ?? null,
      category: meta.category ?? null,
      featured: meta.featured === true,
      liveness: meta.liveness ?? null,
      toolCount: meta.toolCount ?? meta.tools?.length ?? 0,
      tools: meta.tools ?? [],
      scopes: meta.oauth?.defaultScopes ?? [],
      website: sj.websiteUrl ?? null,
      repository: sj.repository?.url ?? null,
      remotes: sj.remotes ?? [],
    };
  }

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

  onMount(() => {
    void load();
  });

  function openAdopt(entry: CatalogEntry) {
    selected = null;
    adopting = entry;
  }

  function openAdoptPackage(entry: CatalogEntry, pkg: CatalogPackage) {
    selected = null;
    adoptingPackage = { entry, pkg };
  }

  function openCreate(asJson: boolean) {
    editing = null;
    editorJson = asJson;
    editorOpen = true;
  }

  function openEdit(entry: CatalogEntry) {
    selected = null;
    editing = entry;
    editorJson = false;
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
    toast.success('Removed from catalog', displayName(entry.server_json));
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
    for (const e of entries) {
      const c = catalogMeta(e.server_json).category;
      if (c) set.add(c);
    }
    return [...set].sort();
  });

  const filtered = $derived.by(() => {
    const q = query.trim().toLowerCase();
    return entries.filter((e) => {
      const v = view(e);
      if (category && v.category !== category) return false;
      // The auth filter is about remotes: an entry that declares only packages
      // has no auth mode, so no choice of the filter lists it.
      if (authMode && (v.remotes.length === 0 || authKind(e.server_json) !== authMode)) return false;
      if (q) {
        const hay = `${e.server_json.name} ${v.title} ${v.description} ${v.category ?? ''}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  });

  /** The upstreams adopted from an entry, by name — recorded on each upstream. */
  function adoptedNames(entry: CatalogEntry): string {
    return entry.adopted_upstreams.map((u) => u.name).join(', ');
  }

  /** The local servers added from an entry's packages, by name. */
  function adoptedLocalNames(entry: CatalogEntry): string {
    return entry.adopted_local_servers.map((s) => s.name).join(', ');
  }

  /** What the Adopted badge of a card says on hover. */
  function adoptedTitle(entry: CatalogEntry): string {
    const parts: string[] = [];
    if (entry.adopted_upstreams.length > 0) parts.push(`Adopted as ${adoptedNames(entry)}`);
    if (entry.adopted_local_servers.length > 0) parts.push(`Added as local server ${adoptedLocalNames(entry)}`);
    return parts.join(' · ');
  }
</script>

<div class="bg-(--bg-card) rounded-xl border border-(--border)">
  <!-- Header -->
  <div class="flex items-center justify-between px-6 py-4 border-b border-(--border)">
    <div>
      <h3 class="text-lg font-semibold text-(--text-primary)">Server Catalog</h3>
      <p class="text-sm text-(--text-secondary) mt-1">
        Curated MCP servers. Browse, review tools and auth needs, then adopt a remote server to wire it
        into your gateway in a single step, or add a packaged one as a local server that runs on each
        developer's machine.
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
        data-testid="catalog-import"
        class="px-4 py-2 border border-(--border) text-(--text-secondary) hover:bg-(--bg-primary) rounded-lg text-sm font-medium"
        onclick={() => openCreate(true)}
      >
        Import server.json
      </button>
      <button
        type="button"
        data-testid="catalog-new"
        class="px-4 py-2 bg-(--accent) text-(--accent-fg) hover:bg-(--accent-hover) rounded-lg text-sm font-medium"
        onclick={() => openCreate(false)}
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
      <option value="none">No auth</option>
      <option value="key">API key</option>
      <option value="headers">Headers</option>
      <option value="oauth">OAuth</option>
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
        {@const ab = authBadge(entry)}
        {@const v = view(entry)}
        <button
          type="button"
          data-testid="catalog-card"
          data-source-name={entry.source_name}
          onclick={() => (selected = entry)}
          class="flex flex-col gap-2 rounded-xl border border-(--border) bg-(--bg-primary) p-4 text-left transition-colors hover:border-(--accent)"
        >
          <div class="flex items-start gap-3">
            <div class="flex h-9 w-9 shrink-0 items-center justify-center overflow-hidden rounded-lg bg-(--bg-card)">
              {#if v.icon}
                <img src={v.icon} alt="" class="h-6 w-6 object-contain" loading="lazy" />
              {:else}
                <Icon name="globe" size="sm" tone="neutral" />
              {/if}
            </div>
            <div class="min-w-0 flex-1">
              <div class="flex items-center gap-1.5">
                <span class="truncate font-medium text-(--text-primary)">{v.title}</span>
                {#if v.featured}
                  <Icon name="sparkles" size="xs" tone="warning" />
                {/if}
              </div>
              {#if v.description}
                <p class="mt-0.5 line-clamp-2 text-xs text-(--text-secondary)">{v.description}</p>
              {/if}
            </div>
          </div>
          <div class="mt-auto flex flex-wrap items-center gap-1.5">
            {#if entry.adopted_upstreams.length > 0 || entry.adopted_local_servers.length > 0}
              <span data-testid="catalog-adopted" title={adoptedTitle(entry)}>
                <TagBadge color="indigo">Adopted</TagBadge>
              </span>
            {/if}
            {#if v.category}
              <TagBadge color="cyan">{v.category}</TagBadge>
            {/if}
            {#if v.remotes.length > 0}
              <TagBadge color={ab.color}>{ab.label}</TagBadge>
            {/if}
            {#if entry.packages.length > 0}
              <span data-testid="catalog-local" title="Declares a package: can be added as a local server that runs on each developer's machine">
                <TagBadge color="orange">Local</TagBadge>
              </span>
            {/if}
            {#if v.liveness}
              <TagBadge color={v.liveness === 'alive' ? 'teal' : 'amber'}>{v.liveness}</TagBadge>
            {/if}
            {#if v.toolCount}
              <span class="inline-flex items-center gap-1 text-xs text-(--text-secondary)">
                <Icon name="wrench" size="xs" tone="neutral" />{v.toolCount}
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
  title={selected ? displayName(selected.server_json) : 'Server'}
  onclose={() => (selected = null)}
  autoFocus="close-button"
  maxWidth="max-w-2xl"
>
  {#if selected}
    {@const ab = authBadge(selected)}
    {@const v = view(selected)}
    <div class="space-y-4 text-sm" data-testid="catalog-detail">
      <div class="flex flex-wrap items-center gap-1.5">
        {#if v.category}<TagBadge color="cyan">{v.category}</TagBadge>{/if}
        {#if v.remotes.length > 0}<TagBadge color={ab.color}>{ab.label}</TagBadge>{/if}
        {#if selected.packages.length > 0}<TagBadge color="orange">Local</TagBadge>{/if}
        {#if v.liveness}<TagBadge color={v.liveness === 'alive' ? 'teal' : 'amber'}>{v.liveness}</TagBadge>{/if}
        <code class="text-xs text-(--text-secondary)">{selected.server_json.name}@{selected.server_json.version}</code>
      </div>

      {#if selected.adopted_upstreams.length > 0}
        <p class="text-xs text-(--text-secondary)" data-testid="catalog-adopted-as">
          Adopted as
          <span class="font-mono text-(--text-primary)">{adoptedNames(selected)}</span>
          (Upstream Servers tab).
        </p>
      {/if}
      {#if selected.adopted_local_servers.length > 0}
        <p class="text-xs text-(--text-secondary)" data-testid="catalog-adopted-local-as">
          Added as local server
          <span class="font-mono text-(--text-primary)">{adoptedLocalNames(selected)}</span>
          (Local servers tab).
        </p>
      {/if}

      {#if v.description}
        <p class="text-(--text-secondary)">{v.description}</p>
      {/if}

      {#each v.remotes as r, ri (ri)}
        {@const inputs = declaredInputs(r)}
        <div class="space-y-1">
          <div class="text-xs uppercase tracking-wide text-(--text-secondary)">
            Endpoint{v.remotes.length > 1 ? ` ${ri + 1}` : ''} · {r.type === 'sse' ? 'HTTP+SSE' : 'Streamable HTTP'}
          </div>
          <code class="block break-all rounded-sm bg-(--bg-primary) px-2 py-1 text-xs text-(--text-primary)">{r.url}</code>
          {#if inputs.length > 0}
            <ul class="space-y-0.5 text-xs">
              {#each inputs as d (d.id)}
                <li>
                  <code class="font-mono text-(--text-primary)">{d.id}</code>
                  {#if d.isSecret}<span class="text-(--text-secondary)">· secret</span>{/if}
                  {#if d.isRequired}<span class="text-(--text-secondary)">· required</span>{/if}
                  {#if d.input.description}<span class="text-(--text-secondary)">— {d.input.description}</span>{/if}
                </li>
              {/each}
            </ul>
          {/if}
        </div>
      {/each}

      {#each selected.packages as pkg (pkg.index)}
        {@const entry = selected}
        <div class="space-y-1" data-testid="catalog-package">
          <div class="text-xs uppercase tracking-wide text-(--text-secondary)">
            Package{selected.packages.length > 1 ? ` ${pkg.index + 1}` : ''} · {pkg.registry_type} · {pkg.transport}
          </div>
          <div class="flex items-center justify-between gap-3">
            <code class="min-w-0 break-all rounded-sm bg-(--bg-primary) px-2 py-1 text-xs text-(--text-primary)">{pkg.identifier}{pkg.version ? `@${pkg.version}` : ''}</code>
            <button
              type="button"
              class="shrink-0 rounded-lg border border-(--border) px-3 py-1.5 text-xs font-medium text-(--accent) hover:bg-(--bg-primary)"
              data-testid="catalog-adopt-package"
              onclick={() => openAdoptPackage(entry, pkg)}
            >
              Add as local server
            </button>
          </div>
          {#if pkg.command_line}
            <code class="block break-all font-mono text-xs text-(--text-secondary)" data-testid="catalog-package-command-line">{pkg.command_line}</code>
          {/if}
          <p class="text-xs text-(--text-secondary)">
            Runs on each developer's machine; the gateway does not connect to it.
          </p>
          {#if pkg.underived_message}
            <p class="text-xs text-(--text-secondary)" data-testid="catalog-package-underived">{pkg.underived_message}</p>
          {/if}
        </div>
      {/each}

      {#if v.scopes.length > 0}
        <div class="space-y-1">
          <div class="text-xs uppercase tracking-wide text-(--text-secondary)">Default OAuth scopes</div>
          <div class="flex flex-wrap gap-1">
            {#each v.scopes as scope}
              <code class="rounded-sm bg-(--bg-primary) px-1.5 py-0.5 text-xs text-(--text-secondary)">{scope}</code>
            {/each}
          </div>
        </div>
      {/if}

      {#if v.tools.length > 0}
        <div class="space-y-1">
          <div class="text-xs uppercase tracking-wide text-(--text-secondary)">
            Tools ({v.tools.length})
          </div>
          <ul class="max-h-60 space-y-1 overflow-y-auto">
            {#each v.tools as tool}
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

      {#if v.website || v.repository}
        <div class="flex flex-wrap gap-3 pt-1">
          {#if v.website}
            <a href={v.website} target="_blank" rel="noopener noreferrer"
               class="inline-flex items-center gap-1 text-(--accent) hover:underline">
              <Icon name="externalLink" size="xs" tone="info" />Website
            </a>
          {/if}
          {#if v.repository}
            <a href={v.repository} target="_blank" rel="noopener noreferrer"
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
      data-testid="catalog-edit"
      onclick={() => selected && openEdit(selected)}
    >
      Edit
    </button>
    {#if (selected?.server_json.remotes ?? []).length > 0}
      <button
        type="button"
        class="rounded-lg bg-(--accent) px-3 py-2 text-sm font-medium text-(--accent-fg) hover:bg-(--accent-hover)"
        data-testid="catalog-adopt"
        onclick={() => selected && openAdopt(selected)}
      >
        Adopt
      </button>
    {/if}
  {/snippet}
</Modal>

<CatalogAdoptModal
  entry={adopting}
  onclose={() => (adopting = null)}
  onadopted={(result) => {
    adopting = null;
    void load();
    if (result.needsOauthConfig && result.upstreamId) {
      onConfigureOauth?.(result.upstreamId);
    }
  }}
/>

<LocalServerEditModal
  open={adoptingPackage !== null}
  editing={null}
  adopt={adoptingPackage}
  onclose={() => (adoptingPackage = null)}
  onsaved={() => {
    adoptingPackage = null;
    void load();
  }}
/>

<CatalogEntryEditModal
  open={editorOpen}
  {editing}
  startInJson={editorJson}
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
    ? `Remove "${displayName(pendingDelete.server_json)}" from the catalog? This only removes the catalog listing — any servers you already adopted from it keep working. Built-in entries stay removed until you reset the catalog.`
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
