<script lang="ts">
  import type { components } from '#lib/generated/api-types.js';
  import Icon from '#lib/components/Icon.svelte';

  type VirtualServerRow = components['schemas']['McpVirtualServerRow'];
  type VirtualRouteRow = components['schemas']['McpVirtualRouteRow'];
  type UpstreamRow = components['schemas']['McpUpstreamServerRow'];

  interface Props {
    virtualServers: VirtualServerRow[];
    virtualServersLoading: boolean;
    virtualServersError: string;
    routes: VirtualRouteRow[];
    routesLoading: boolean;
    upstreams: UpstreamRow[];
    onOpenNew: () => void;
    onOpenEdit: (row: VirtualServerRow) => void;
    onDelete: (row: VirtualServerRow) => void;
    onToggleEnabled: (row: VirtualServerRow, enabled: boolean) => void;
    onAttachUpstream: (virtualServerId?: string) => void;
    onEditRoute: (row: VirtualRouteRow) => void;
    onDetachRoute: (row: VirtualRouteRow) => void;
    onToggleRouteEnabled: (row: VirtualRouteRow, enabled: boolean) => void;
    onMoveRoute: (row: VirtualRouteRow, direction: -1 | 1) => void;
  }

  let {
    virtualServers,
    virtualServersLoading,
    virtualServersError,
    routes,
    upstreams,
    onOpenNew,
    onOpenEdit,
    onDelete,
    onToggleEnabled,
    onAttachUpstream,
    onEditRoute,
    onDetachRoute,
    onToggleRouteEnabled,
    onMoveRoute,
  }: Props = $props();

  // Track which endpoints are expanded.
  let expandedIds = $state<Record<string, boolean>>({});
  function toggleExpand(id: string) {
    expandedIds = { ...expandedIds, [id]: !expandedIds[id] };
  }

  function routesFor(vsId: string): VirtualRouteRow[] {
    return routes
      .filter((r) => r.virtual_server_id === vsId)
      .sort((a, b) => a.position - b.position);
  }
  function upstreamName(id: string): string {
    return upstreams.find((u) => u.id === id)?.name ?? id.slice(0, 8) + '…';
  }
  // Filter chip generator for a route's three filters.
  type FilterShape = components['schemas']['McpRouteFilterShape'] | null | undefined;
  function summarizeFilter(label: string, f: FilterShape): string | null {
    if (!f) return null;
    if (f.allow && f.allow.length > 0) return `${label} allow ${f.allow.length}`;
    if (f.deny && f.deny.length > 0) return `${label} deny ${f.deny.length}`;
    return null;
  }
  function filterChips(r: VirtualRouteRow): string[] {
    const chips: string[] = [];
    const t = summarizeFilter('tools', r.tools_filter);
    const re = summarizeFilter('res', r.resources_filter);
    const p = summarizeFilter('prompts', r.prompts_filter);
    if (t) chips.push(t);
    if (re) chips.push(re);
    if (p) chips.push(p);
    return chips;
  }
</script>

<div class="bg-(--bg-card) rounded-xl border border-(--border)">
  <!-- Header -->
  <div class="flex items-center justify-between px-6 py-4 border-b border-(--border)">
    <div>
      <h3 class="text-lg font-semibold text-(--text-primary)">Endpoints</h3>
      <p class="text-sm text-(--text-secondary) mt-1">
        Operator-defined endpoints exposed at <code class="bg-(--bg-primary) px-1 py-0.5 rounded-sm text-xs">/mcp/&lt;slug&gt;</code>. Click an endpoint to manage attached upstreams.
      </p>
    </div>
    <button
      type="button"
      class="px-4 py-2 bg-(--accent) hover:bg-(--accent-hover) text-(--accent-fg) rounded-lg text-sm font-medium ml-4 shrink-0"
      onclick={onOpenNew}>+ New Endpoint</button>
  </div>

  {#if virtualServersError}
    <div class="m-4 bg-(--error-bg) border border-(--error-border) rounded-lg p-3 text-sm text-(--error-text)">
      {virtualServersError}
    </div>
  {/if}

  {#if virtualServersLoading}
    <div class="px-6 py-8 text-sm text-(--text-secondary)">Loading…</div>
  {:else if virtualServers.length === 0}
    <div class="px-6 py-12 text-center">
      <h4 class="text-base font-medium text-(--text-primary) mb-2">No endpoints yet</h4>
      <p class="text-sm text-(--text-secondary) max-w-md mx-auto mb-4">
        Create an endpoint to expose your MCP gateway at <code class="bg-(--bg-primary) px-1 py-0.5 rounded-sm text-xs">/mcp/&lt;slug&gt;</code>.
        You'll then attach one or more upstream MCP servers to it.
      </p>
      <button
        type="button"
        class="px-4 py-2 bg-(--accent) hover:bg-(--accent-hover) text-(--accent-fg) rounded-lg text-sm font-medium"
        onclick={onOpenNew}>+ New Endpoint</button>
    </div>
  {:else}
    <div class="divide-y divide-(--border)">
      {#each virtualServers as v (v.id)}
        {@const isExpanded = expandedIds[v.id] ?? false}
        {@const vsRoutes = routesFor(v.id)}
        <div class="px-6 py-4">
          <!-- Card header row -->
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-3 min-w-0 flex-1">
              <button
                type="button"
                class="text-(--text-secondary) hover:text-(--text-primary)"
                aria-label="Toggle expand"
                onclick={() => toggleExpand(v.id)}>
                <span class="inline-flex transition-transform {isExpanded ? 'rotate-90' : ''}"><Icon name="chevronRight" size="sm" tone="neutral" /></span>
              </button>
              <button
                type="button"
                class="text-left min-w-0 flex-1"
                onclick={() => toggleExpand(v.id)}>
                <p class="font-mono text-sm text-(--text-primary)">/mcp/{v.slug}</p>
                <p class="text-xs text-(--text-secondary) truncate">{v.name}{#if v.description} · {v.description}{/if}</p>
              </button>
              <!-- Pills -->
              <div class="flex items-center gap-2 shrink-0">
                {#if v.oauth_enabled}
                  <span class="inline-block px-1.5 py-0.5 text-[10px] rounded-sm font-medium bg-(--info-bg) text-(--info-text)" title="Spec OAuth 2.1 enabled (RFC 9728/8707)">OAuth 2.1</span>
                {/if}
                {#if v.sampling_intercept_enabled}
                  <span class="inline-block px-1.5 py-0.5 text-[10px] rounded-sm font-medium bg-(--info-bg) text-(--info-text)" title="sampling/createMessage answered via the gateway LLM pipeline (auth, budgets, audit, transforms)">sampling intercept</span>
                {/if}
                {#if v.fwd_mount}
                  <span
                    data-testid="vs-fwd-mount"
                    class="inline-block px-1.5 py-0.5 text-[10px] rounded-sm font-medium bg-(--warning-bg) text-(--warning-text)"
                    title="A client sends its own Authorization header to an upstream, so it connects to /fwd/<gateway-key>/mcp/{v.slug} with its gateway key in the path"
                  >/fwd mount</span>
                {/if}
                {#if v.client_headers.length > 0}
                  <span
                    data-testid="vs-client-headers"
                    class="inline-block px-1.5 py-0.5 text-[10px] rounded-sm font-mono bg-(--bg-primary) border border-(--border) text-(--text-secondary)"
                    title="Headers the client sends on every request; each goes only to the upstream that declares it"
                  >client: {v.client_headers.join(', ')}</span>
                {/if}
                <span class="text-xs text-(--text-secondary) font-mono">{vsRoutes.length} upstream{vsRoutes.length === 1 ? '' : 's'}</span>
              </div>
            </div>
            <div class="flex items-center gap-3 shrink-0 ml-4">
              <!-- Inline enabled toggle -->
              <button
                type="button"
                class="w-7 h-3.5 rounded-full relative transition-colors {v.enabled ? 'bg-(--success)' : 'bg-(--toggle-off)'}"
                aria-label="Toggle enabled"
                title="{v.enabled ? 'Disable' : 'Enable'} endpoint"
                onclick={() => onToggleEnabled(v, !v.enabled)}>
                <span class="absolute top-0.5 w-2.5 h-2.5 rounded-full bg-white ring-1 ring-(--bg-primary)/60 transition-all {v.enabled ? 'left-3.5' : 'left-0.5'}"></span>
              </button>
              <button type="button" class="text-xs text-(--accent) hover:text-(--accent-hover) font-medium" onclick={() => onOpenEdit(v)}>Edit</button>
              <button type="button" class="text-xs text-(--error) hover:bg-(--error-bg) px-1.5 rounded-sm font-medium" onclick={() => onDelete(v)}>Delete</button>
            </div>
          </div>

          <!-- Expanded view: attached upstreams (routes) -->
          {#if isExpanded}
            <div class="mt-4 ml-7 bg-(--bg-primary) rounded-lg p-4">
              {#if v.client_headers.length > 0}
                <p class="mb-3 text-xs text-(--text-secondary)" data-testid="vs-client-note">
                  Clients send
                  {#each v.client_headers as h, hi}<code class="font-mono text-(--text-primary)">{h}</code>{hi < v.client_headers.length - 1 ? ', ' : ''}{/each}
                  on every request and connect to
                  {#if v.fwd_mount}
                    <code class="font-mono text-(--text-primary)">/fwd/&lt;gateway-key&gt;/mcp/{v.slug}</code> — their own
                    <code class="font-mono">Authorization</code> header goes to the upstream, so the gateway key rides the path.
                  {:else}
                    <code class="font-mono text-(--text-primary)">/mcp/{v.slug}</code> with their gateway key.
                  {/if}
                </p>
              {/if}
              <div class="flex items-center justify-between mb-3">
                <p class="text-xs font-medium text-(--text-secondary) uppercase tracking-wider">Attached upstreams ({vsRoutes.length})</p>
                <button
                  type="button"
                  class="text-xs text-(--accent) hover:text-(--accent-hover) font-medium"
                  onclick={() => onAttachUpstream(v.id)}>+ Attach</button>
              </div>
              {#if vsRoutes.length === 0}
                <p class="text-xs text-(--text-secondary) py-3">No upstreams attached. Click <strong>+ Attach</strong> to bind one.</p>
              {:else}
                <table class="w-full text-sm">
                  <tbody>
                    {#each vsRoutes as r, idx (r.id)}
                      <tr class="border-b border-(--border) last:border-0">
                        <td class="px-2 py-2 text-xs text-(--text-secondary) font-mono w-8 text-right">{idx + 1}</td>
                        <td class="px-2 py-2">
                          <span class="text-sm text-(--text-primary)">{upstreamName(r.upstream_server_id)}</span>
                        </td>
                        <td class="px-2 py-2">
                          {#if r.prefix}
                            <span class="inline-block px-1.5 py-0.5 text-[10px] rounded-sm bg-(--bg-card) border border-(--border) text-(--text-secondary) font-mono">{r.prefix}__</span>
                          {/if}
                        </td>
                        <td class="px-2 py-2">
                          {#each filterChips(r) as chip}
                            <span class="inline-block px-1.5 py-0.5 mr-1 text-[10px] rounded-sm bg-(--bg-card) border border-(--border) text-(--text-secondary)">{chip}</span>
                          {/each}
                          {#if filterChips(r).length === 0}
                            <span class="text-[10px] text-(--text-secondary)">no filters</span>
                          {/if}
                        </td>
                        <td class="px-2 py-2 text-right">
                          <div class="flex items-center justify-end gap-1">
                            <button
                              type="button"
                              class="w-6 h-3 rounded-full relative transition-colors {r.enabled ? 'bg-(--success)' : 'bg-(--toggle-off)'} mr-1"
                              aria-label="Toggle route enabled"
                              onclick={() => onToggleRouteEnabled(r, !r.enabled)}>
                              <span class="absolute top-0.5 w-2 h-2 rounded-full bg-white ring-1 ring-(--bg-primary)/60 transition-all {r.enabled ? 'left-3' : 'left-0.5'}"></span>
                            </button>
                            <button
                              type="button"
                              onclick={() => onMoveRoute(r, -1)}
                              disabled={idx === 0}
                              aria-label="Move up"
                              title="Move up"
                              class="p-1 rounded-sm hover:bg-(--bg-elevated) text-(--text-secondary) hover:text-(--text-primary) disabled:opacity-30 disabled:cursor-not-allowed transition-colors">
                              <Icon name="chevronUp" size="sm" tone="neutral" />
                            </button>
                            <button
                              type="button"
                              onclick={() => onMoveRoute(r, 1)}
                              disabled={idx === vsRoutes.length - 1}
                              aria-label="Move down"
                              title="Move down"
                              class="p-1 rounded-sm hover:bg-(--bg-elevated) text-(--text-secondary) hover:text-(--text-primary) disabled:opacity-30 disabled:cursor-not-allowed transition-colors">
                              <Icon name="chevronDown" size="sm" tone="neutral" />
                            </button>
                            <button type="button" class="text-xs text-(--accent) hover:text-(--accent-hover) ml-1" onclick={() => onEditRoute(r)}>Edit</button>
                            <button type="button" class="text-xs text-(--error) hover:bg-(--error-bg) px-1.5 rounded-sm" onclick={() => onDetachRoute(r)}>Detach</button>
                          </div>
                        </td>
                      </tr>
                    {/each}
                  </tbody>
                </table>
              {/if}
            </div>
          {/if}
        </div>
      {/each}
    </div>
  {/if}
</div>
