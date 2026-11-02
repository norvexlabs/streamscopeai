<script lang="ts">
  /**
   * Portal — MCP Connections.
   *
   * Lists per-upstream OAuth connection status for the upstreams reachable
   * through the user's accessible virtual servers, and lets the user connect
   * (full PKCE OAuth dance) or revoke. The connect button kicks off the
   * authorization round-trip — the browser is redirected to the upstream
   * IdP and lands back on this page via the public callback endpoint.
   */
  import { portalApi } from '#lib/portal-client.js';
  import { extractError } from '#lib/api-helpers.js';
  import { formatTimeAgo } from '#lib/formatters.js';
  import ConfirmDialog from '#lib/components/ConfirmDialog.svelte';
  import { page } from '$app/state';
  import type { components } from '#lib/generated/api-types.js';
  import { m } from '#lib/paraglide/messages.js';

  type Connection = components['schemas']['PortalConnectionItem'];

  let items = $state<Connection[]>([]);
  let loading = $state(true);
  let pageError = $state('');
  let revokeUpstreamId = $state<string | null>(null);
  let connectingUpstreamId = $state<string | null>(null);

  let connectedFlash = $derived(page.url.searchParams.get('connected'));
  let connectErrorFlash = $derived(page.url.searchParams.get('error'));

  async function loadConnections() {
    loading = true;
    pageError = '';
    const { data, error } = await portalApi.GET('/api/v1/portal/mcp/connections');
    if (error) {
      pageError = extractError(error, m.portal_comp_failed_load_connections());
    } else {
      items = data?.items ?? [];
    }
    loading = false;
  }

  $effect(() => {
    void loadConnections();
  });

  async function startConnect(upstreamId: string) {
    pageError = '';
    connectingUpstreamId = upstreamId;
    const { data, error } = await portalApi.POST(
      '/api/v1/portal/mcp/connections/{upstream_id}/actions/connect',
      {
        params: { path: { upstream_id: upstreamId } },
      },
    );
    connectingUpstreamId = null;
    if (error || !data) {
      pageError = extractError(error, m.portal_comp_failed_start_oauth());
      return;
    }
    // Hand the browser off to the upstream IdP. The callback handler at
    // /api/v1/portal/mcp/connections/oauth/callback redirects back to this
    // page (tenant-prefixed) with ?connected=<upstream_id> on success or
    // ?error=... on failure (format fixed in portal_mcp_connections.rs).
    window.location.href = data.authorization_url;
  }

  async function confirmRevoke() {
    const id = revokeUpstreamId;
    revokeUpstreamId = null;
    if (!id) return;
    const { error } = await portalApi.POST(
      '/api/v1/portal/mcp/connections/{upstream_id}/actions/revoke',
      {
        params: { path: { upstream_id: id } },
      },
    );
    if (error) {
      pageError = extractError(error, m.portal_comp_failed_revoke_connection());
    } else {
      await loadConnections();
    }
  }

  function statusOf(it: Connection): { label: string; color: string } {
    switch (it.status) {
      case 'connected':
        return { label: m.portal_comp_connected(), color: 'text-(--success) bg-(--success-bg)' };
      case 'expired':
        return { label: m.portal_comp_expired(), color: 'text-(--warning) bg-(--warning-bg)' };
      case 'not_connected':
      default:
        return { label: m.portal_comp_not_connected(), color: 'text-(--text-secondary) bg-(--bg-primary)' };
    }
  }
</script>

<div>
  {#if connectedFlash}
    <div data-testid="connected-flash" class="mb-3 px-3 py-2 rounded-lg bg-(--success-bg) border border-(--success-border) text-xs text-(--success)">
      {m.portal_comp_connected_to_prefix()} <code class="font-mono">{connectedFlash}</code>.
    </div>
  {/if}
  {#if connectErrorFlash}
    <div class="mb-3 px-3 py-2 rounded-lg bg-(--error)/10 border border-(--error) text-xs text-(--error)">
      {m.portal_comp_oauth_failed({ error: connectErrorFlash })}
    </div>
  {/if}
  {#if pageError}
    <div class="mb-3 px-3 py-2 rounded-lg bg-(--error)/10 text-(--error) text-sm">
      {pageError}
    </div>
  {/if}

  {#if loading}
    <div class="text-sm text-(--text-secondary)">{m.portal_comp_loading()}</div>
  {:else if items.length === 0}
    <div class="text-sm text-(--text-secondary) py-12 text-center">
      {m.portal_comp_no_oauth_upstreams()}
    </div>
  {:else}
    <div class="space-y-2" data-testid="connections-list">
      {#each items as it (it.upstream_server_id)}
        {@const status = statusOf(it)}
        <div
          data-testid="connection-row"
          data-upstream-id={it.upstream_server_id}
          data-status={it.status}
          class="bg-(--bg-card) border border-(--border) rounded-lg p-3 flex items-center gap-3"
        >
          <div class="flex-1 min-w-0">
            <div class="flex items-center gap-2 flex-wrap">
              <span class="text-sm font-medium text-(--text-primary) truncate">{it.upstream_name}</span>
              <span class="text-[10px] font-medium px-1.5 py-0.5 rounded-sm {status.color}" data-testid="status-badge">{status.label}</span>
              {#if it.scope}
                <code class="text-[10px] text-(--text-secondary) font-mono bg-(--bg-primary) px-1.5 py-0.5 rounded-sm">{it.scope}</code>
              {/if}
            </div>
            {#if it.upstream_description}
              <div class="text-xs text-(--text-secondary) mt-0.5">{it.upstream_description}</div>
            {/if}
            <div class="text-[10px] text-(--text-secondary) mt-1">
              {#if it.virtual_servers.length > 0}
                {m.portal_comp_routes_via()}
                {#each it.virtual_servers as vs (vs.id)}
                  <code class="font-mono">/mcp/{vs.slug}</code>{#if vs !== it.virtual_servers[it.virtual_servers.length - 1]}, {/if}
                {/each}
              {/if}
              {#if it.expires_at}
                · {m.portal_comp_expires_ago({ ago: formatTimeAgo(it.expires_at) })}
              {/if}
              {#if it.last_used_at}
                · {m.portal_comp_last_used_ago({ ago: formatTimeAgo(it.last_used_at) })}
              {/if}
            </div>
          </div>
          <div class="flex items-center gap-2">
            {#if it.status === 'connected' || it.status === 'expired'}
              <button
                data-testid="reconnect-button"
                onclick={() => startConnect(it.upstream_server_id)}
                disabled={connectingUpstreamId === it.upstream_server_id}
                class="text-xs px-2 py-1 rounded-sm text-(--accent) hover:bg-(--accent)/10 disabled:opacity-50"
              >{m.portal_comp_reconnect()}</button>
              <button
                data-testid="disconnect-button"
                onclick={() => (revokeUpstreamId = it.upstream_server_id)}
                class="text-xs px-2 py-1 rounded-sm text-(--error) hover:bg-(--error-bg)"
              >{m.portal_comp_disconnect()}</button>
            {:else}
              <button
                data-testid="connect-button"
                onclick={() => startConnect(it.upstream_server_id)}
                disabled={connectingUpstreamId === it.upstream_server_id}
                class="text-xs px-3 py-1 rounded-sm bg-(--accent) text-(--accent-fg) hover:bg-(--accent-hover) disabled:opacity-50"
              >{connectingUpstreamId === it.upstream_server_id ? m.portal_comp_starting() : m.portal_comp_connect()}</button>
            {/if}
          </div>
        </div>
      {/each}
    </div>
  {/if}
</div>

<ConfirmDialog
  open={!!revokeUpstreamId}
  title={m.portal_comp_disconnect_upstream_title()}
  message={m.portal_comp_disconnect_upstream_message()}
  confirmLabel={m.portal_comp_disconnect()}
  destructive
  oncancel={() => (revokeUpstreamId = null)}
  onconfirm={confirmRevoke}
/>
