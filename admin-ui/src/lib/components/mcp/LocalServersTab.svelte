<script lang="ts">
  /**
   * The tenant's local MCP servers: servers that run on each developer's own
   * machine. The list, with New / Edit / Delete and the enable switch. Each
   * row names the workspaces the server is granted to; a grant is made when
   * the server is created, or on a workspace's page.
   */
  import { adminApi } from '#lib/api-client.js';
  import { extractError, extractErrorCode, fetchAllPages } from '#lib/api-helpers.js';
  import { toast } from '#lib/toast.svelte.js';
  import type { components } from '#lib/generated/api-types.js';
  import TagBadge from '#lib/components/TagBadge.svelte';
  import ConfirmDialog from '#lib/components/ConfirmDialog.svelte';
  import LocalServerEditModal from '#lib/components/mcp/LocalServerEditModal.svelte';
  import { onMount } from 'svelte';

  type LocalServer = components['schemas']['McpLocalServer'];

  let servers = $state<LocalServer[]>([]);
  let loading = $state(true);
  let loadError = $state('');

  let showModal = $state(false);
  let editing = $state<LocalServer | null>(null);
  let pendingDelete = $state<LocalServer | null>(null);

  async function load() {
    loadError = '';
    try {
      servers = await fetchAllPages((offset, limit) =>
        adminApi.GET('/api/v1/admin/mcp/local-servers', { params: { query: { offset, limit } } }), 200);
    } catch (e: unknown) {
      loadError = extractError(e, 'Failed to load local servers');
    } finally {
      loading = false;
    }
  }

  onMount(() => {
    void load();
  });

  function reportError(title: string, err: unknown): void {
    toast.error(title, { body: extractError(err), code: extractErrorCode(err) ?? undefined });
  }

  function openNew() {
    editing = null;
    showModal = true;
  }
  function openEdit(row: LocalServer) {
    editing = row;
    showModal = true;
  }

  async function toggleEnabled(row: LocalServer, enabled: boolean) {
    const { error } = await adminApi.PATCH('/api/v1/admin/mcp/local-servers/{id}', {
      params: { path: { id: row.id } },
      body: { enabled },
    });
    if (error) {
      reportError(`Failed to ${enabled ? 'enable' : 'disable'} local server`, error);
      return;
    }
    void load();
  }

  async function confirmDelete() {
    const row = pendingDelete;
    if (!row) return;
    pendingDelete = null;
    const { error } = await adminApi.DELETE('/api/v1/admin/mcp/local-servers/{id}', {
      params: { path: { id: row.id } },
    });
    if (error) {
      reportError(`Failed to delete local server "${row.name}"`, error);
      return;
    }
    void load();
  }

  /** The variables each developer fills, by name. */
  function developerFilled(row: LocalServer): string[] {
    return (row.launch.env ?? []).filter((e) => e.secret === true || e.value === undefined || e.value === null).map((e) => e.name);
  }
</script>

<div class="bg-(--bg-card) rounded-xl border border-(--border)">
  <div class="flex items-center justify-between px-6 py-4 border-b border-(--border)">
    <div>
      <h3 class="text-lg font-semibold text-(--text-primary)">Local servers</h3>
      <p class="text-sm text-(--text-secondary) mt-1">
        These servers run on each developer's own machine; client provisioning writes their command line into
        the client configs of the workspaces they are granted to. The gateway does not connect to them, so
        their MCP traffic is not audited or policed on the MCP plane — tool rules still apply to the model's
        tool calls, by the <code class="font-mono">mcp__&lt;slug&gt;__</code> name.
      </p>
    </div>
    <button
      type="button"
      data-testid="local-server-new"
      class="px-4 py-2 bg-(--accent) hover:bg-(--accent-hover) text-(--accent-fg) rounded-lg text-sm font-medium ml-4 shrink-0"
      onclick={openNew}>+ New local server</button>
  </div>

  {#if loadError}
    <div class="m-4 bg-(--error-bg) border border-(--error-border) rounded-lg p-3 text-sm text-(--error-text)">
      {loadError}
    </div>
  {/if}

  {#if loading}
    <div class="px-6 py-8 text-sm text-(--text-secondary)">Loading…</div>
  {:else if servers.length === 0 && !loadError}
    <div class="px-6 py-12 text-center">
      <h4 class="text-base font-medium text-(--text-primary) mb-2">No local servers</h4>
      <p class="text-sm text-(--text-secondary) max-w-md mx-auto mb-4">
        Type a server's command line here, or add one from a Catalog entry that declares a package, then grant
        it to a workspace.
      </p>
      <button
        type="button"
        class="px-4 py-2 bg-(--accent) hover:bg-(--accent-hover) text-(--accent-fg) rounded-lg text-sm font-medium"
        onclick={openNew}>+ New local server</button>
    </div>
  {:else}
    <div class="divide-y divide-(--border)">
      {#each servers as s (s.id)}
        {@const filled = developerFilled(s)}
        <div class="px-6 py-4" data-testid="local-server-row" data-local-server-id={s.id}>
          <div class="flex items-center justify-between gap-3">
            <div class="min-w-0 flex-1">
              <p class="text-sm text-(--text-primary) font-medium flex items-center gap-2 flex-wrap">
                {s.name}
                <code class="font-mono text-xs font-normal text-(--text-secondary)">{s.slug}</code>
                {#if s.catalog_entry_id}
                  <span data-testid="local-server-from-catalog" title="Added from a Catalog entry">
                    <TagBadge color="indigo">From catalog</TagBadge>
                  </span>
                {/if}
                {#if !s.enabled}
                  <span class="px-1.5 py-0.5 rounded-sm text-xs font-medium bg-(--text-secondary)/15 text-(--text-secondary)">Off</span>
                {/if}
              </p>
              <code class="mt-1 block break-all font-mono text-xs text-(--text-secondary)" data-testid="local-server-command-line">{s.command_line}</code>
              {#if s.description}
                <p class="mt-1 text-xs text-(--text-secondary)">{s.description}</p>
              {/if}
              {#if filled.length > 0}
                <p class="mt-1 text-xs text-(--text-secondary)">
                  Each developer fills: <code class="font-mono">{filled.join(', ')}</code>
                </p>
              {/if}
              <p class="mt-1 text-xs text-(--text-secondary)" data-testid="local-server-workspaces">
                {#if s.workspaces.length > 0}
                  Granted to: {s.workspaces.map((w) => w.name).join(', ')}
                {:else}
                  Granted to no workspace
                {/if}
              </p>
            </div>
            <div class="flex items-center gap-3 shrink-0">
              <button
                type="button"
                class="w-7 h-3.5 rounded-full relative transition-colors {s.enabled ? 'bg-(--success)' : 'bg-(--toggle-off)'}"
                aria-label="Toggle enabled"
                title="{s.enabled ? 'Disable' : 'Enable'} local server"
                data-testid="local-server-toggle"
                onclick={() => toggleEnabled(s, !s.enabled)}>
                <span class="absolute top-0.5 w-2.5 h-2.5 rounded-full bg-white ring-1 ring-(--bg-primary)/60 transition-all {s.enabled ? 'left-3.5' : 'left-0.5'}"></span>
              </button>
              <button
                type="button"
                class="text-xs font-medium text-(--accent) hover:text-(--accent-hover)"
                data-testid="local-server-edit"
                onclick={() => openEdit(s)}>Edit</button>
              <button
                type="button"
                class="text-xs font-medium text-(--error) hover:bg-(--error-bg) px-1.5 rounded-sm"
                data-testid="local-server-delete"
                onclick={() => (pendingDelete = s)}>Delete</button>
            </div>
          </div>
        </div>
      {/each}
    </div>
  {/if}
</div>

<LocalServerEditModal
  open={showModal}
  {editing}
  onclose={() => (showModal = false)}
  onsaved={() => { showModal = false; void load(); }}
/>

<ConfirmDialog
  open={pendingDelete !== null}
  title="Delete local server"
  message={pendingDelete ? `Delete local server "${pendingDelete.name}" (${pendingDelete.slug})? Workspaces granted it lose the grant, and client provisioning stops writing it into members' client configs.` : ''}
  confirmLabel="Delete"
  destructive
  onconfirm={confirmDelete}
  oncancel={() => (pendingDelete = null)}
/>
