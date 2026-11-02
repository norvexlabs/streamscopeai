<script lang="ts">
  import type { EdgeNode } from '#lib/api-types.js';
  import { adminApi } from '#lib/api-client.js';
  import { extractSettings, extractError, extractErrorCode, updateSettings, fetchAllPages } from '#lib/api-helpers.js';
  import { toast } from '#lib/toast.svelte.js';
  import { formatTimeAgo, formatDateTime } from '#lib/formatters.js';
  import Page from '#lib/components/page/Page.svelte';
  import ConfirmDialog from '#lib/components/ConfirmDialog.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import Skeleton from '#lib/components/Skeleton.svelte';
  import EmptyState from '#lib/components/EmptyState.svelte';
  import CopyTextButton from '#lib/components/CopyTextButton.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import { usePeriodicLoad } from '#lib/hooks.svelte.js';
  import { useLoadView } from '#lib/loadView.svelte.js';

  // Edge nodes
  let edgeNodes = $state<EdgeNode[]>([]);
  let nodesLoading = $state(true);
  // The skeleton on a first load or a new scope only: a refresh keeps what
  // is shown (`#lib/loadView.js`), so an auto-refresh tick never blanks it.
  const nodesView = useLoadView(() => nodesLoading);
  let showAddNode = $state(false);
  let newNodeName = $state('');
  let newNodeEndpoint = $state('');
  let addingNode = $state(false);
  let createdNodeToken = $state<string | null>(null);
  let deleteNodeId = $state<string | null>(null);

  // Global proxy settings
  let logLevel = $state('info');

  async function reloadAll() {
    await Promise.all([loadNodes(), loadConfig()]);
  }

  usePeriodicLoad(reloadAll, reloadAll);

  // Only the latest read lands: a refresh read before a save must not put the
  // old state back after the save's own re-read.
  let configGen = 0;
  async function loadConfig() {
    const gen = ++configGen;
    const { data, error: err } = await adminApi.GET('/api/v1/admin/settings');
    if (gen !== configGen) return;
    if (err) {
      toast.error(extractError(err));
      return;
    }
    if (data) {
      const s = extractSettings(data);
      logLevel = (s.log_level as string) || 'info';
    }
  }

  async function handleLogLevelChange() {
    // A read in flight before or during this save is older than it: neither
    // may land after it.
    ++configGen;
    const { error: err } = await updateSettings({ log_level: logLevel });
    ++configGen;
    if (err) {
      await loadConfig();
      toast.error('Failed to save log level', { body: extractError(err), code: extractErrorCode(err) ?? undefined });
    } else {
      toast.success(`Log level set to ${logLevel}`);
    }
  }

  let nodesGen = 0;
  async function loadNodes() {
    const gen = ++nodesGen;
    nodesLoading = true;
    try {
      const nodes = await fetchAllPages<EdgeNode>((offset, limit) =>
        adminApi.GET('/api/v1/admin/edge-nodes', { params: { query: { offset, limit } } }));
      if (gen === nodesGen) edgeNodes = nodes;
    } catch (err) {
      if (gen === nodesGen) toast.error(extractError(err));
    } finally {
      if (gen === nodesGen) nodesLoading = false;
    }
  }

  async function handleAddNode() {
    if (!newNodeName.trim()) return;
    addingNode = true;
    const { data, error: err } = await adminApi.POST('/api/v1/admin/edge-nodes', {
      body: { name: newNodeName.trim(), endpoint: newNodeEndpoint.trim() || undefined },
    });
    if (err) {
      toast.error('Failed to add node', { body: extractError(err), code: extractErrorCode(err) ?? undefined });
    } else if (data) {
      createdNodeToken = data.token;
      newNodeName = '';
      newNodeEndpoint = '';
      await loadNodes();
      toast.success('Edge node created');
    }
    addingNode = false;
  }

  function dismissNodeToken() {
    createdNodeToken = null;
    showAddNode = false;
  }

  async function handleDeleteNode() {
    const id = deleteNodeId;
    deleteNodeId = null;
    if (!id) return;
    const { error: err } = await adminApi.DELETE('/api/v1/admin/edge-nodes/{id}', {
      params: { path: { id } },
    });
    if (err) {
      toast.error('Failed to delete node', { body: extractError(err), code: extractErrorCode(err) ?? undefined });
    } else {
      await loadNodes();
      toast.success('Edge node deleted');
    }
  }
</script>

<Page title="Edge Nodes" subtitle="Edge node infrastructure management">
  {#snippet actions()}
    <button
      onclick={() => showAddNode = !showAddNode}
      class="px-4 py-2 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-sm font-medium transition-colors"
    >
      {showAddNode ? 'Cancel' : '+ Add Node'}
    </button>
  {/snippet}

  <!-- Global log level control -->
  <div class="bg-(--bg-card) rounded-xl border border-(--border) p-4 flex items-center justify-between">
    <div>
      <p class="text-sm font-medium text-(--text-primary)">Log Level</p>
      <p class="text-xs text-(--text-secondary) mt-0.5">Global setting — applies to all edge nodes</p>
    </div>
    <SelectInput
      bind:value={logLevel}
      onchange={handleLogLevelChange}
      fluid={false}
    >
      <option value="error">Error</option>
      <option value="warn">Warn</option>
      <option value="info">Info</option>
      <option value="debug">Debug</option>
    </SelectInput>
  </div>

  {#if createdNodeToken}
    <div class="bg-(--bg-primary)/50 rounded-xl p-5 border border-dashed border-(--accent)">
      <div class="space-y-3">
        <div class="flex items-center gap-2 text-xs">
          <Icon name="errorCircle" size="sm" tone="warning" />
          <span class="font-medium text-(--warning)">Save this token now — you won't see it again</span>
        </div>
        <p class="text-xs text-(--text-secondary)">Set as <code class="text-(--accent)">EDGE_TOKEN</code> environment variable on the proxy instance.</p>
        <div class="flex items-center gap-2">
          <code class="flex-1 text-xs font-mono bg-(--bg-secondary) px-3 py-2 rounded-lg text-(--text-primary) break-all select-all">{createdNodeToken}</code>
          <CopyTextButton value={createdNodeToken ?? ''} />
        </div>
        <div class="flex justify-end">
          <button onclick={dismissNodeToken} class="px-4 py-1.5 text-sm rounded-lg bg-(--accent) text-(--accent-fg) hover:bg-(--accent-hover) transition-opacity">
            Done
          </button>
        </div>
      </div>
    </div>
  {:else if showAddNode}
    <div class="bg-(--bg-card) rounded-xl p-5 border border-(--border)">
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
        <div>
          <label class="block text-xs text-(--text-secondary) mb-1.5 uppercase tracking-wider">Node Name <span class="text-(--error)">*</span>
            <input bind:value={newNodeName} placeholder="e.g. edge-us-east" class="w-full px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm" />
          </label>
        </div>
        <div>
          <label class="block text-xs text-(--text-secondary) mb-1.5 uppercase tracking-wider">Endpoint
            <input bind:value={newNodeEndpoint} placeholder="e.g. https://proxy.example.com:8080" class="w-full px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm" />
          </label>
        </div>
      </div>
      <button onclick={handleAddNode} disabled={addingNode || !newNodeName.trim()} class="px-5 py-2 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-sm font-medium disabled:opacity-50">
        {addingNode ? 'Adding…' : 'Add Node'}
      </button>
    </div>
  {/if}

  <!-- Node List -->
  {#if nodesView.skeleton}
    <Skeleton variant="row" count={4} />
  {:else}
    <div class="bg-(--bg-card) rounded-xl border border-(--border) overflow-hidden">
      <table class="w-full text-sm">
        <thead>
          <tr class="border-b border-(--border) bg-(--bg-primary)/50">
            <th class="px-5 py-3 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Status</th>
            <th class="px-5 py-3 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Name</th>
            <th class="px-5 py-3 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Endpoint</th>
            <th class="px-5 py-3 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Config Sync</th>
            <th class="px-5 py-3 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Last Sync</th>
            <th class="px-5 py-3 text-right text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Actions</th>
          </tr>
        </thead>
        <tbody>
          {#each edgeNodes as node}
            <tr class="border-b border-(--border) hover:bg-(--bg-elevated) transition-colors">
              <td class="px-5 py-3.5">
                <span class="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium {node.is_connected ? 'bg-(--success)/10 text-(--success) border border-(--success)' : 'bg-(--error)/10 text-(--error) border border-(--error)'}">
                  <span class="w-1.5 h-1.5 rounded-full bg-current"></span>
                  {node.is_connected ? 'Online' : 'Offline'}
                </span>
                {#if node.is_connected && (node.connected_instances ?? 0) > 1}
                  <span
                    class="ml-1.5 inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-(--accent)/10 text-(--accent) border border-(--accent)"
                    title="Proxy replicas syncing"
                  >{node.connected_instances} replicas</span>
                {/if}
              </td>
              <td class="px-5 py-3.5 font-medium text-(--text-primary)">{node.name}</td>
              <td class="px-5 py-3.5 text-(--text-secondary) text-sm font-mono">{node.endpoint || '--'}</td>
              <td class="px-5 py-3.5">
                {#if !node.is_connected}
                  <span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium bg-(--text-secondary)/10 text-(--text-secondary) border border-(--text-secondary)">
                    <span class="w-1.5 h-1.5 rounded-full bg-current"></span>
                    Offline
                  </span>
                {:else if node.synced}
                  <span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium bg-(--success)/10 text-(--success) border border-(--success)">
                    <span class="w-1.5 h-1.5 rounded-full bg-current"></span>
                    Synced
                  </span>
                {:else}
                  <span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium bg-(--warning)/10 text-(--warning) border border-(--warning)">
                    <span class="w-1.5 h-1.5 rounded-full bg-current"></span>
                    Out of sync
                  </span>
                {/if}
              </td>
              <td
                class="px-5 py-3.5 text-(--text-secondary)"
                title={node.last_sync_at ? formatDateTime(node.last_sync_at) : ''}
              >{node.last_sync_at ? formatTimeAgo(node.last_sync_at) : 'Never'}</td>
              <td class="px-5 py-3.5 text-right">
                <div class="flex items-center justify-end gap-3">
                  <button onclick={() => (deleteNodeId = node.id)} class="text-xs text-(--error) hover:underline font-medium">Delete</button>
                </div>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
      {#if edgeNodes.length === 0}
        <EmptyState
          title="No edge nodes configured"
          body="Edge proxies register automatically via EDGE_TOKEN, or add one manually."
        />
      {/if}
    </div>
  {/if}

  <ConfirmDialog
    open={deleteNodeId !== null}
    title="Delete edge node"
    message="Delete this edge node? It will need to re-register to reconnect."
    confirmLabel="Delete"
    destructive
    onconfirm={handleDeleteNode}
    oncancel={() => (deleteNodeId = null)}
  />
</Page>
