<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import { extractError, extractErrorCode } from '#lib/api-helpers.js';
  import { toast } from '#lib/toast.svelte.js';
  import type { components } from '#lib/generated/api-types.js';
  import TabbedPage from '#lib/components/page/TabbedPage.svelte';
  import DownstreamEditModal from '#lib/components/mcp/DownstreamEditModal.svelte';
  import AttachedUpstreamModal from '#lib/components/mcp/AttachedUpstreamModal.svelte';
  import UpstreamEditModal from '#lib/components/mcp/UpstreamEditModal.svelte';
  import OAuthClientEditModal from '#lib/components/mcp/OAuthClientEditModal.svelte';
  import TokensView from '#lib/components/mcp/TokensView.svelte';
  import DownstreamTab from '#lib/components/mcp/DownstreamTab.svelte';
  import UpstreamTab from '#lib/components/mcp/UpstreamTab.svelte';
  import OAuthClientsCard from '#lib/components/mcp/OAuthClientsCard.svelte';
  import CimdClientsCard from '#lib/components/mcp/CimdClientsCard.svelte';
  import WebSettingsTab from '#lib/components/mcp/WebSettingsTab.svelte';
  import CatalogTab from '#lib/components/mcp/CatalogTab.svelte';
  import ConfirmDialog from '#lib/components/ConfirmDialog.svelte';
  import { useTabState } from '#lib/hooks.svelte.js';

  function reportError(title: string, err: unknown): void {
    toast.error(title, { body: extractError(err), code: extractErrorCode(err) ?? undefined });
  }

  type UpstreamRow = components['schemas']['McpUpstreamServerRow'];
  type VirtualServerRow = components['schemas']['McpVirtualServerRow'];
  type VirtualRouteRow = components['schemas']['McpVirtualRouteRow'];
  type OauthClientRow = components['schemas']['OauthClientRow'];
  type CimdClientRow = components['schemas']['CimdClientRow'];

  type Tab = 'endpoints' | 'oauth' | 'upstream-servers' | 'catalog' | 'tokens' | 'web';
  const TABS = ['endpoints', 'oauth', 'upstream-servers', 'catalog', 'tokens', 'web'] as const satisfies readonly Tab[];
  const tab = useTabState<Tab>(TABS, 'endpoints');

  let upstreams = $state<UpstreamRow[]>([]);
  let upstreamsLoading = $state(false);
  let upstreamsError = $state('');
  let showUpstreamModal = $state(false);
  let editingUpstream = $state<UpstreamRow | null>(null);

  let virtualServers = $state<VirtualServerRow[]>([]);
  let virtualServersLoading = $state(false);
  let virtualServersError = $state('');
  let showVsModal = $state(false);
  let editingVs = $state<VirtualServerRow | null>(null);

  let oauthClients = $state<OauthClientRow[]>([]);
  let oauthClientsLoading = $state(false);
  let oauthClientsError = $state('');
  let showOauthClientModal = $state(false);
  let editingOauthClient = $state<OauthClientRow | null>(null);

  // Clients that never registered — derived from their issued tokens, so this
  // reloads after a revoke to reflect the new live-token count.
  let cimdClients = $state<CimdClientRow[]>([]);
  let cimdClientsLoading = $state(false);
  let cimdClientsError = $state('');
  let pendingRevokeCimd = $state<CimdClientRow | null>(null);

  let routes = $state<VirtualRouteRow[]>([]);
  let routesLoading = $state(false);
  let showRouteModal = $state(false);
  let editingRoute = $state<VirtualRouteRow | null>(null);
  let routeDefaultVirtualServerId = $state<string | undefined>(undefined);
  let routeDefaultPosition = $state<number | undefined>(undefined);

  // Pending-confirmation rows for destructive ops. Single ConfirmDialog per
  // kind keeps the cancel/confirm wiring obvious; resetting the row to null
  // closes the dialog.
  let pendingDeleteUpstream = $state<UpstreamRow | null>(null);
  let pendingDeleteVs = $state<VirtualServerRow | null>(null);
  let pendingDeleteRoute = $state<VirtualRouteRow | null>(null);
  let pendingDeleteOauthClient = $state<OauthClientRow | null>(null);

  async function loadUpstreams() {
    upstreamsLoading = true;
    upstreamsError = '';
    const { data, error } = await adminApi.GET('/api/v1/admin/mcp/upstream-servers', {
      params: { query: { limit: 200 } },
    });
    if (error) {
      upstreamsError = extractError(error);
    } else if (data) {
      upstreams = data.items;
    }
    upstreamsLoading = false;
  }

  async function loadVirtualServers() {
    virtualServersLoading = true;
    virtualServersError = '';
    const { data, error } = await adminApi.GET('/api/v1/admin/mcp/virtual-servers', {
      params: { query: { limit: 200 } },
    });
    if (error) {
      virtualServersError = extractError(error);
    } else if (data) {
      virtualServers = data.items;
    }
    virtualServersLoading = false;
  }

  async function loadRoutes() {
    routesLoading = true;
    const { data, error } = await adminApi.GET('/api/v1/admin/mcp/virtual-routes', {
      params: { query: { limit: 500 } },
    });
    if (error) {
      toast.error(extractError(error));
    } else if (data) {
      routes = data.items;
    }
    routesLoading = false;
  }

  async function loadOauthClients() {
    oauthClientsLoading = true;
    oauthClientsError = '';
    const { data, error } = await adminApi.GET('/api/v1/admin/mcp/oauth-clients', {
      params: { query: { limit: 200 } },
    });
    if (error) {
      oauthClientsError = extractError(error);
    } else if (data) {
      oauthClients = data.items;
    }
    oauthClientsLoading = false;
  }

  async function loadCimdClients() {
    cimdClientsLoading = true;
    cimdClientsError = '';
    const { data, error } = await adminApi.GET('/api/v1/admin/mcp/cimd-clients', {
      params: { query: { limit: 200 } },
    });
    if (error) {
      cimdClientsError = extractError(error);
    } else if (data) {
      cimdClients = data.items;
    }
    cimdClientsLoading = false;
  }

  $effect(() => {
    void loadUpstreams();
    void loadVirtualServers();
    void loadRoutes();
    void loadOauthClients();
    void loadCimdClients();
  });

  async function toggleUpstreamEnabled(row: UpstreamRow, enabled: boolean) {
    const { error } = await adminApi.PATCH('/api/v1/admin/mcp/upstream-servers/{id}', {
      params: { path: { id: row.id } },
      body: { enabled },
    });
    if (error) {
      reportError(`Failed to ${enabled ? 'enable' : 'disable'} upstream`, error);
      return;
    }
    void loadUpstreams();
  }

  async function toggleVsEnabled(row: VirtualServerRow, enabled: boolean) {
    const { error } = await adminApi.PATCH('/api/v1/admin/mcp/virtual-servers/{id}', {
      params: { path: { id: row.id } },
      body: { enabled },
    });
    if (error) {
      reportError(`Failed to ${enabled ? 'enable' : 'disable'} endpoint`, error);
      return;
    }
    void loadVirtualServers();
  }

  async function toggleRouteEnabled(row: VirtualRouteRow, enabled: boolean) {
    const { error } = await adminApi.PATCH('/api/v1/admin/mcp/virtual-routes/{id}', {
      params: { path: { id: row.id } },
      body: { enabled },
    });
    if (error) {
      reportError(`Failed to ${enabled ? 'enable' : 'disable'} route`, error);
      return;
    }
    void loadRoutes();
  }

  function openNewUpstream() {
    editingUpstream = null;
    showUpstreamModal = true;
  }
  function openEditUpstream(row: UpstreamRow) {
    editingUpstream = row;
    showUpstreamModal = true;
  }
  // After adopting a per_user_oauth server without its OAuth client, land the
  // operator on that upstream's edit form to finish setup.
  async function configureAdoptedOauth(upstreamId: string) {
    tab.current = 'upstream-servers';
    await loadUpstreams();
    const row = upstreams.find((u) => u.id === upstreamId);
    if (row) {
      editingUpstream = row;
      showUpstreamModal = true;
    }
  }
  async function confirmDeleteUpstream() {
    const row = pendingDeleteUpstream;
    if (!row) return;
    pendingDeleteUpstream = null;
    const { error } = await adminApi.DELETE('/api/v1/admin/mcp/upstream-servers/{id}', {
      params: { path: { id: row.id } },
    });
    if (error) {
      reportError(`Failed to delete upstream "${row.name}"`, error);
      return;
    }
    void loadUpstreams();
  }

  function openNewVs() {
    editingVs = null;
    showVsModal = true;
  }
  function openEditVs(row: VirtualServerRow) {
    editingVs = row;
    showVsModal = true;
  }
  async function confirmDeleteVs() {
    const row = pendingDeleteVs;
    if (!row) return;
    pendingDeleteVs = null;
    const { error } = await adminApi.DELETE('/api/v1/admin/mcp/virtual-servers/{id}', {
      params: { path: { id: row.id } },
    });
    if (error) {
      reportError(`Failed to delete endpoint "${row.slug}"`, error);
      return;
    }
    void loadVirtualServers();
    void loadRoutes();
  }

  function openNewRoute(virtualServerId?: string) {
    editingRoute = null;
    routeDefaultVirtualServerId = virtualServerId;
    const siblings = virtualServerId
      ? routes.filter((r) => r.virtual_server_id === virtualServerId)
      : [];
    routeDefaultPosition = siblings.length > 0
      ? Math.max(...siblings.map((r) => r.position)) + 1
      : 0;
    showRouteModal = true;
  }
  function openEditRoute(row: VirtualRouteRow) {
    editingRoute = row;
    routeDefaultVirtualServerId = row.virtual_server_id;
    routeDefaultPosition = undefined;
    showRouteModal = true;
  }
  async function moveRoute(row: VirtualRouteRow, direction: -1 | 1) {
    const siblings = routes
      .filter((r) => r.virtual_server_id === row.virtual_server_id)
      .sort((a, b) => a.position - b.position);
    const current = siblings.findIndex((r) => r.id === row.id);
    if (current < 0) return;
    const target = current + direction;
    if (target < 0 || target >= siblings.length) return;
    const neighbor = siblings[target];
    // Swap positions so the visible order changes by exactly one step
    // without creating ties (no unique constraint on (vs_id, position),
    // but `ORDER BY position, prefix` would tie-break by prefix which
    // doesn't match operator intent).
    const [{ error: e1 }, { error: e2 }] = await Promise.all([
      adminApi.PATCH('/api/v1/admin/mcp/virtual-routes/{id}', {
        params: { path: { id: row.id } },
        body: { position: neighbor.position },
      }),
      adminApi.PATCH('/api/v1/admin/mcp/virtual-routes/{id}', {
        params: { path: { id: neighbor.id } },
        body: { position: row.position },
      }),
    ]);
    if (e1 || e2) {
      reportError('Failed to reorder route', e1 ?? e2);
      void loadRoutes();
      return;
    }
    void loadRoutes();
  }
  async function confirmDeleteRoute() {
    const row = pendingDeleteRoute;
    if (!row) return;
    pendingDeleteRoute = null;
    const { error } = await adminApi.DELETE('/api/v1/admin/mcp/virtual-routes/{id}', {
      params: { path: { id: row.id } },
    });
    if (error) {
      reportError('Failed to detach upstream', error);
      return;
    }
    void loadRoutes();
  }

  function openNewOauthClient() {
    editingOauthClient = null;
    showOauthClientModal = true;
  }
  function openEditOauthClient(row: OauthClientRow) {
    editingOauthClient = row;
    showOauthClientModal = true;
  }
  async function confirmDeleteOauthClient() {
    const row = pendingDeleteOauthClient;
    if (!row) return;
    pendingDeleteOauthClient = null;
    const { error } = await adminApi.DELETE('/api/v1/admin/mcp/oauth-clients/{id}', {
      params: { path: { id: row.id } },
    });
    if (error) {
      reportError(`Failed to delete OAuth client "${row.name}"`, error);
      return;
    }
    void loadOauthClients();
    // A registered client's tokens can carry its metadata URL as well, so
    // deleting it changes what this inventory shows.
    void loadCimdClients();
  }

  async function confirmRevokeCimd() {
    const row = pendingRevokeCimd;
    if (!row) return;
    pendingRevokeCimd = null;
    const { data, error } = await adminApi.POST('/api/v1/admin/mcp/cimd-clients/actions/revoke', {
      body: { client_id: row.client_id },
    });
    if (error) {
      reportError('Failed to revoke the client\u2019s tokens', error);
      return;
    }
    toast.success(data?.message ?? 'Tokens revoked');
    void loadCimdClients();
  }
</script>

<TabbedPage
  title="MCP Gateway"
  tabs={[
    { id: 'endpoints', label: 'Endpoints' },
    { id: 'oauth', label: 'OAuth' },
    { id: 'upstream-servers', label: 'Upstream Servers' },
    { id: 'catalog', label: 'Catalog' },
    { id: 'tokens', label: 'Tokens' },
    { id: 'web', label: 'Web' },
  ]}
  activeTab={tab.current}
  onTabChange={(t: Tab) => (tab.current = t)}
>
  {#snippet description()}
    Operator-defined endpoints exposed at
    <code class="bg-(--bg-primary) px-1.5 py-0.5 rounded-sm text-(--text-primary)">/mcp/&lt;slug&gt;</code>. All four upstream
    auth modes — <code>no_auth</code>, <code>service_account</code>,
    <code>per_user_oauth</code>, and <code>byot</code> — are honored end-to-end.
  {/snippet}

  {#snippet children(active: Tab)}
    {#if active === 'endpoints'}
      <DownstreamTab
        {virtualServers}
        {virtualServersLoading}
        {virtualServersError}
        {routes}
        {routesLoading}
        {upstreams}
        onOpenNew={openNewVs}
        onOpenEdit={openEditVs}
        onDelete={(row: VirtualServerRow) => (pendingDeleteVs = row)}
        onToggleEnabled={toggleVsEnabled}
        onAttachUpstream={openNewRoute}
        onEditRoute={openEditRoute}
        onDetachRoute={(row: VirtualRouteRow) => (pendingDeleteRoute = row)}
        onToggleRouteEnabled={toggleRouteEnabled}
        onMoveRoute={moveRoute}
      />
    {:else if active === 'oauth'}
      <div class="space-y-6">
        <OAuthClientsCard
          {oauthClients}
          {oauthClientsLoading}
          {oauthClientsError}
          onOpenNew={openNewOauthClient}
          onOpenEdit={openEditOauthClient}
          onDelete={(row: OauthClientRow) => (pendingDeleteOauthClient = row)}
        />
        <CimdClientsCard
          clients={cimdClients}
          loading={cimdClientsLoading}
          error={cimdClientsError}
          onRevoke={(row: CimdClientRow) => (pendingRevokeCimd = row)}
        />
      </div>
    {:else if active === 'upstream-servers'}
      <UpstreamTab
        {upstreams}
        {upstreamsLoading}
        {upstreamsError}
        {routes}
        {virtualServers}
        onOpenNew={openNewUpstream}
        onOpenEdit={openEditUpstream}
        onDelete={(row: UpstreamRow) => (pendingDeleteUpstream = row)}
        onToggleEnabled={toggleUpstreamEnabled}
      />
    {:else if active === 'catalog'}
      <CatalogTab onConfigureOauth={configureAdoptedOauth} />
    {:else if active === 'tokens'}
      <TokensView {virtualServers} {oauthClients} />
    {:else if active === 'web'}
      <WebSettingsTab />
    {/if}
  {/snippet}
</TabbedPage>

<UpstreamEditModal
  open={showUpstreamModal}
  editing={editingUpstream}
  onclose={() => (showUpstreamModal = false)}
  onsaved={() => { showUpstreamModal = false; void loadUpstreams(); }}
/>

<DownstreamEditModal
  open={showVsModal}
  editing={editingVs}
  onclose={() => (showVsModal = false)}
  onsaved={() => { showVsModal = false; void loadVirtualServers(); }}
/>

<OAuthClientEditModal
  open={showOauthClientModal}
  editing={editingOauthClient}
  onclose={() => (showOauthClientModal = false)}
  onsaved={() => void loadOauthClients()}
/>

<AttachedUpstreamModal
  open={showRouteModal}
  editing={editingRoute}
  defaultVirtualServerId={routeDefaultVirtualServerId}
  defaultPosition={routeDefaultPosition}
  {virtualServers}
  {upstreams}
  onclose={() => (showRouteModal = false)}
  onsaved={() => { showRouteModal = false; void loadRoutes(); }}
/>

<ConfirmDialog
  open={pendingDeleteUpstream !== null}
  title="Delete upstream server"
  message={pendingDeleteUpstream ? `Delete upstream "${pendingDeleteUpstream.name}"? Detach it from every endpoint route first — the gateway refuses the delete while routes still reference it.` : ''}
  confirmLabel="Delete"
  destructive
  onconfirm={confirmDeleteUpstream}
  oncancel={() => (pendingDeleteUpstream = null)}
/>

<ConfirmDialog
  open={pendingDeleteVs !== null}
  title="Delete endpoint"
  message={pendingDeleteVs ? `Delete endpoint /mcp/${pendingDeleteVs.slug}? This deletes all attached routes and invalidates every active token audienced to it. Apps using this endpoint will break.` : ''}
  confirmLabel="Delete endpoint"
  destructive
  requireText={pendingDeleteVs?.slug}
  onconfirm={confirmDeleteVs}
  oncancel={() => (pendingDeleteVs = null)}
/>

<ConfirmDialog
  open={pendingDeleteRoute !== null}
  title="Detach upstream"
  message={pendingDeleteRoute ? `Detach upstream "${pendingDeleteRoute.prefix || '(no prefix)'}" from this endpoint?` : ''}
  confirmLabel="Detach"
  destructive
  onconfirm={confirmDeleteRoute}
  oncancel={() => (pendingDeleteRoute = null)}
/>

<ConfirmDialog
  open={pendingDeleteOauthClient !== null}
  title="Delete OAuth client"
  message={pendingDeleteOauthClient ? `Delete OAuth client "${pendingDeleteOauthClient.name}" (${pendingDeleteOauthClient.client_id})? Every token it holds is revoked, so apps signed in through it stop working immediately.` : ''}
  confirmLabel="Delete client"
  destructive
  requireText={pendingDeleteOauthClient?.name}
  onconfirm={confirmDeleteOauthClient}
  oncancel={() => (pendingDeleteOauthClient = null)}
/>

<ConfirmDialog
  open={pendingRevokeCimd !== null}
  title="Revoke all tokens"
  message={pendingRevokeCimd ? `Revoke every token held by ${pendingRevokeCimd.client_id}? ${pendingRevokeCimd.tokens_active} live token(s) across ${pendingRevokeCimd.grants} grant(s) stop working immediately. The client can consent again unless CIMD is turned off for this tenant.` : ''}
  confirmLabel="Revoke all"
  destructive
  onconfirm={confirmRevokeCimd}
  oncancel={() => (pendingRevokeCimd = null)}
/>
