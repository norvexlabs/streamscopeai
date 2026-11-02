<script lang="ts">
  import type { components } from '#lib/generated/api-types.js';
  import SystemRowBadge from '#lib/components/SystemRowBadge.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import { page } from '$app/state';
  import { thref } from '#lib/tenant.js';

  let slug = $derived(page.params.slug ?? '');

  type UpstreamRow = components['schemas']['McpUpstreamServerRow'];
  type VirtualRouteRow = components['schemas']['McpVirtualRouteRow'];
  type VirtualServerRow = components['schemas']['McpVirtualServerRow'];

  interface Props {
    upstreams: UpstreamRow[];
    upstreamsLoading: boolean;
    upstreamsError: string;
    routes: VirtualRouteRow[];
    virtualServers: VirtualServerRow[];
    onOpenNew: () => void;
    onOpenEdit: (row: UpstreamRow) => void;
    onDelete: (row: UpstreamRow) => void;
    onToggleEnabled: (row: UpstreamRow, enabled: boolean) => void;
  }

  let {
    upstreams,
    upstreamsLoading,
    upstreamsError,
    routes,
    virtualServers,
    onOpenNew,
    onOpenEdit,
    onDelete,
    onToggleEnabled,
  }: Props = $props();

  // Track which upstream cards are expanded.
  let expandedIds = $state<Record<string, boolean>>({});
  function toggleExpand(id: string) {
    expandedIds = { ...expandedIds, [id]: !expandedIds[id] };
  }

  function usedBy(upstreamId: string): VirtualServerRow[] {
    const vsIds = new Set(routes.filter((r) => r.upstream_server_id === upstreamId).map((r) => r.virtual_server_id));
    return virtualServers.filter((v) => vsIds.has(v.id));
  }

  // A per_user_oauth upstream is unusable until its shared OAuth-App client is
  // set — without it no portal user can connect and the endpoint can't be
  // granted to a workspace. Mirrors the server-side grant gate's required set
  // (client_id, secret, authorization_url, token_url).
  function oauthIncomplete(u: UpstreamRow): boolean {
    return (
      u.auth_mode === 'per_user_oauth' &&
      (!u.oauth_client_id ||
        !u.has_oauth_client_secret ||
        !u.oauth_authorization_url ||
        !u.oauth_token_url)
    );
  }

  function authPillClass(mode: string, hasCredential: boolean, incompleteOauth: boolean): string {
    if (mode === 'service_account') {
      return hasCredential
        ? 'bg-(--success-bg) text-(--success-text)'
        : 'bg-(--warning-bg) text-(--warning-text)';
    }
    if (mode === 'per_user_oauth') {
      return incompleteOauth
        ? 'bg-(--warning-bg) text-(--warning-text)'
        : 'bg-(--info-bg) text-(--info-text)';
    }
    if (mode === 'byot') return 'bg-(--tag-violet-bg) text-(--tag-violet-text)';
    return 'bg-(--bg-primary) border border-(--border) text-(--text-secondary)';
  }
</script>

<div class="bg-(--bg-card) rounded-xl border border-(--border)">
  <!-- Header -->
  <div class="flex items-center justify-between px-6 py-4 border-b border-(--border)">
    <div>
      <h3 class="text-lg font-semibold text-(--text-primary)">Upstream MCP Servers</h3>
      <p class="text-sm text-(--text-secondary) mt-1">
        Real MCP servers we proxy to. Each carries its own URL, auth mode, and capability surface.
      </p>
    </div>
    <button
      type="button"
      class="px-4 py-2 bg-(--accent) hover:bg-(--accent-hover) text-(--accent-fg) rounded-lg text-sm font-medium ml-4 shrink-0"
      onclick={onOpenNew}>+ New Upstream</button>
  </div>

  {#if upstreamsError}
    <div class="m-4 bg-(--error-bg) border border-(--error-border) rounded-lg p-3 text-sm text-(--error-text)">
      {upstreamsError}
    </div>
  {/if}

  {#if upstreamsLoading}
    <div class="px-6 py-8 text-sm text-(--text-secondary)">Loading…</div>
  {:else if upstreams.length === 0}
    <div class="px-6 py-12 text-center">
      <h4 class="text-base font-medium text-(--text-primary) mb-2">No upstreams configured</h4>
      <p class="text-sm text-(--text-secondary) max-w-md mx-auto mb-4">
        Register a real MCP server (URL + auth mode) so you can attach it to one of your endpoints.
      </p>
      <button
        type="button"
        class="px-4 py-2 bg-(--accent) hover:bg-(--accent-hover) text-(--accent-fg) rounded-lg text-sm font-medium"
        onclick={onOpenNew}>+ New Upstream</button>
    </div>
  {:else}
    <div class="divide-y divide-(--border)">
      {#each upstreams as u (u.id)}
        {@const isExpanded = expandedIds[u.id] ?? false}
        {@const usingVses = usedBy(u.id)}
        {@const isBuiltIn = u.built_in === true}
        {@const oauthBad = oauthIncomplete(u)}
        <div class="px-6 py-4">
          <div class="flex items-center justify-between gap-3">
            <div class="flex items-center gap-3 min-w-0 flex-1">
              <button
                type="button"
                class="text-(--text-secondary) hover:text-(--text-primary)"
                aria-label="Toggle expand"
                onclick={() => toggleExpand(u.id)}>
                <span class="inline-flex transition-transform {isExpanded ? 'rotate-90' : ''}"><Icon name="chevronRight" size="sm" tone="neutral" /></span>
              </button>
              <!-- svelte-ignore a11y_click_events_have_key_events -->
              <!-- svelte-ignore a11y_no_static_element_interactions -->
              <div class="text-left min-w-0 flex-1 cursor-pointer" onclick={() => toggleExpand(u.id)}>
                <p class="text-sm text-(--text-primary) font-medium flex items-center gap-2">
                  {u.name}
                  {#if isBuiltIn}
                    <SystemRowBadge title="System upstream — managed by the gateway. Configure via the Web tab." />
                  {/if}
                </p>
                <p class="text-xs text-(--text-secondary) truncate font-mono">{u.upstream_url}</p>
              </div>
              <div class="flex items-center gap-2 shrink-0 flex-wrap">
                <span
                  class="inline-block px-1.5 py-0.5 text-[10px] rounded-sm font-medium {authPillClass(u.auth_mode, u.has_credential, oauthBad)}"
                  title={u.auth_mode === 'service_account' && !u.has_credential
                    ? 'Service-account upstream is missing its credential — every call returns JSON-RPC -32500'
                    : oauthBad
                      ? 'OAuth client incomplete — set the Client ID and Secret (Edit) before granting this endpoint or connecting from the portal'
                      : ''}
                >
                  {u.auth_mode}{#if u.auth_mode === 'service_account'} {u.has_credential ? '✓' : '⚠'}{:else if oauthBad} ⚠{/if}
                </span>
                {#if usingVses.length > 0}
                  <span class="text-[10px] text-(--text-secondary)">used by:</span>
                  {#each usingVses.slice(0, 3) as vs}
                    <a
                      href={thref(slug, '/gateways/mcp?tab=endpoints')}
                      class="text-[10px] font-mono px-1.5 py-0.5 rounded-sm bg-(--bg-primary) border border-(--border) text-(--text-primary) hover:text-(--accent)"
                    >{vs.slug}</a>
                  {/each}
                  {#if usingVses.length > 3}
                    <span class="text-[10px] text-(--text-secondary)">+{usingVses.length - 3}</span>
                  {/if}
                {/if}
              </div>
            </div>
            <div class="flex items-center gap-3 shrink-0">
              <button
                type="button"
                class="w-7 h-3.5 rounded-full relative transition-colors {u.enabled ? 'bg-(--success)' : 'bg-(--toggle-off)'}"
                aria-label="Toggle enabled"
                title="{u.enabled ? 'Disable' : 'Enable'} upstream"
                onclick={() => onToggleEnabled(u, !u.enabled)}>
                <span class="absolute top-0.5 w-2.5 h-2.5 rounded-full bg-white ring-1 ring-(--bg-primary)/60 transition-all {u.enabled ? 'left-3.5' : 'left-0.5'}"></span>
              </button>
              <button
                type="button"
                class="text-xs font-medium {isBuiltIn ? 'text-(--text-secondary) opacity-50 cursor-not-allowed' : 'text-(--accent) hover:text-(--accent-hover)'}"
                disabled={isBuiltIn}
                aria-disabled={isBuiltIn}
                title={isBuiltIn ? 'System upstream — manage via the Web tab' : 'Edit upstream'}
                onclick={() => { if (!isBuiltIn) onOpenEdit(u); }}
              >Edit</button>
              <button
                type="button"
                class="text-xs font-medium {isBuiltIn ? 'text-(--text-secondary) opacity-50 cursor-not-allowed' : 'text-(--error) hover:bg-(--error-bg) px-1.5 rounded-sm'}"
                disabled={isBuiltIn}
                aria-disabled={isBuiltIn}
                title={isBuiltIn ? 'System upstream — cannot be deleted' : 'Delete upstream'}
                onclick={() => { if (!isBuiltIn) onDelete(u); }}
              >Delete</button>
            </div>
          </div>

          {#if isExpanded}
            <div class="mt-4 ml-7 bg-(--bg-primary) rounded-lg p-4 space-y-2">
              <div class="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
                <div>
                  <span class="text-(--text-secondary)">Transport:</span>
                  <span class="text-(--text-primary) font-mono ml-1">{u.transport}</span>
                </div>
                <div>
                  <span class="text-(--text-secondary)">Connect timeout:</span>
                  <span class="text-(--text-primary) font-mono ml-1">{u.connect_timeout_ms}ms</span>
                </div>
                <div>
                  <span class="text-(--text-secondary)">Request timeout:</span>
                  <span class="text-(--text-primary) font-mono ml-1">{u.request_timeout_ms}ms</span>
                </div>
                <div>
                  <span class="text-(--text-secondary)">Cred version:</span>
                  <span class="text-(--text-primary) font-mono ml-1">{u.cred_version}</span>
                </div>
              </div>
              {#if u.description}
                <p class="text-xs text-(--text-secondary)">{u.description}</p>
              {/if}
              {#if u.auth_mode === 'per_user_oauth'}
                <div class="pt-2 border-t border-(--border)">
                  <p class="text-[10px] text-(--text-secondary) uppercase tracking-wider">Per-user OAuth</p>
                  <p class="text-xs text-(--text-secondary) mt-1">
                    Each user connects individually via the portal with their own account; the
                    Client ID/Secret is the single OAuth-App credential the gateway registers once
                    with the provider. Issuer:
                    <code class="font-mono">{u.oauth_issuer_url ?? '—'}</code>
                  </p>
                  {#if oauthBad}
                    <div class="mt-2 flex items-center gap-2 text-xs text-(--warning-text)">
                      <span>⚠ OAuth client incomplete — set the Client ID and Secret before granting this endpoint to a workspace or connecting from the portal.</span>
                      {#if !isBuiltIn}
                        <button
                          type="button"
                          class="font-medium text-(--accent) hover:text-(--accent-hover) underline"
                          onclick={() => onOpenEdit(u)}
                        >Configure</button>
                      {/if}
                    </div>
                  {/if}
                </div>
              {/if}
              {#if u.auth_mode === 'byot'}
                <div class="pt-2 border-t border-(--border)">
                  <p class="text-[10px] text-(--text-secondary) uppercase tracking-wider">BYOT</p>
                  <p class="text-xs text-(--text-secondary) mt-1">
                    Agents forward their own bearer via <code class="font-mono">vk-*</code> keys. Single-route binding required.
                  </p>
                </div>
              {/if}
            </div>
          {/if}
        </div>
      {/each}
    </div>
  {/if}
</div>
