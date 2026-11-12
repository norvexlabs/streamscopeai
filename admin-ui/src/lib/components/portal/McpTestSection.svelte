<script lang="ts">
  /**
   * Portal — MCP Test.
   *
   * Pick one of your accessible virtual servers, run an `initialize` /
   * `tools/list` / `prompts/list` / `resources/list` round-trip against each
   * upstream the route fans into, and render the merged catalog. Mirrors the
   * proxy's auth resolution: an upstream the user hasn't connected yet
   * surfaces "needs_connection", one waiting for a header only the client
   * sends "needs_client_header", and a redirect is reported, never followed.
   */
  import { portalApi } from '#lib/portal-client.js';
  import { extractError, fetchAllPages } from '#lib/api-helpers.js';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import type { components } from '#lib/generated/api-types.js';
  import { m } from '#lib/paraglide/messages.js';

  type VirtualServer = components['schemas']['PortalMcpVirtualServer'];
  type TestResponse = components['schemas']['PortalMcpTestResponse'];

  let virtualServers = $state<VirtualServer[]>([]);
  let selectedVsId = $state('');
  let loading = $state(true);
  let running = $state(false);
  let result = $state<TestResponse | null>(null);
  let pageError = $state('');

  async function loadVs() {
    loading = true;
    try {
      virtualServers = await fetchAllPages<VirtualServer>((offset, limit) =>
        portalApi.GET('/api/v1/portal/mcp/virtual-servers', { params: { query: { offset, limit } } }));
      if (virtualServers.length > 0 && !selectedVsId) {
        selectedVsId = virtualServers[0].id;
      }
    } catch {
      pageError = m.portal_comp_failed_load_vs();
    }
    loading = false;
  }

  $effect(() => {
    void loadVs();
  });

  async function runTest() {
    if (!selectedVsId) return;
    running = true;
    pageError = '';
    result = null;
    const { data, error } = await portalApi.POST(
      '/api/v1/portal/mcp/virtual-servers/{virtual_server_id}/actions/test',
      {
        params: { path: { virtual_server_id: selectedVsId } },
      },
    );
    if (error) {
      pageError = extractError(error, m.portal_comp_failed_run_test());
    } else if (data) {
      result = data;
    }
    running = false;
  }

  function statusBadge(s: string): { label: string; color: string } {
    switch (s) {
      case 'ok':
        return { label: m.portal_comp_status_ok(), color: 'text-(--success) bg-(--success-bg)' };
      case 'needs_connection':
        return { label: m.portal_comp_needs_connection(), color: 'text-(--warning) bg-(--warning-bg)' };
      case 'needs_client_header':
        return { label: m.portal_comp_status_needs_client_header(), color: 'text-(--text-secondary) bg-(--bg-primary)' };
      case 'unavailable':
        return { label: m.portal_comp_status_unavailable(), color: 'text-(--error) bg-(--error)/10' };
      case 'redirected':
        return { label: m.portal_comp_status_redirected(), color: 'text-(--warning) bg-(--warning-bg)' };
      case 'http_error':
        return { label: m.portal_comp_http_error(), color: 'text-(--error) bg-(--error)/10' };
      case 'jsonrpc_error':
        return { label: m.portal_comp_jsonrpc_error(), color: 'text-(--error) bg-(--error)/10' };
      case 'disabled':
        return { label: m.portal_comp_disabled(), color: 'text-(--text-secondary) bg-(--bg-primary)' };
      default:
        return { label: s, color: 'text-(--text-secondary) bg-(--bg-primary)' };
    }
  }
</script>

<div>
  {#if pageError}
    <div class="mb-3 px-3 py-2 rounded-lg bg-(--error)/10 text-(--error) text-sm">{pageError}</div>
  {/if}

  {#if loading}
    <div class="text-sm text-(--text-secondary)">{m.portal_comp_loading()}</div>
  {:else if virtualServers.length === 0}
    <div class="text-sm text-(--text-secondary) py-12 text-center">
      {m.portal_comp_no_vs_access()}
    </div>
  {:else}
    <div class="bg-(--bg-card) border border-(--border) rounded-lg p-4 mb-4 flex items-end gap-3">
      <label class="flex-1">
        <span class="text-xs font-medium text-(--text-secondary) uppercase tracking-wider">{m.portal_comp_virtual_server()}</span>
        <SelectInput
          data-testid="vs-select"
          class="mt-1"
          bind:value={selectedVsId}
        >
          {#each virtualServers as vs (vs.id)}
            <option value={vs.id}>/mcp/{vs.slug} — {vs.name}</option>
          {/each}
        </SelectInput>
      </label>
      <button
        data-testid="run-test"
        onclick={runTest}
        disabled={running || !selectedVsId}
        class="px-4 py-1.5 text-sm rounded-lg bg-(--accent) text-(--accent-fg) disabled:opacity-50 hover:bg-(--accent-hover)"
      >
        {running ? m.portal_comp_running() : m.portal_comp_run_test()}
      </button>
    </div>
  {/if}

  {#if result}
    <div data-testid="test-result" class="space-y-4">
      <div class="bg-(--bg-card) border border-(--border) rounded-lg p-4 grid grid-cols-3 gap-3">
        <div>
          <div class="text-[10px] text-(--text-secondary) uppercase tracking-wider">{m.portal_comp_tools()}</div>
          <div data-testid="total-tools" class="text-2xl font-bold text-(--text-primary)">{result.total_tools}</div>
        </div>
        <div>
          <div class="text-[10px] text-(--text-secondary) uppercase tracking-wider">{m.portal_comp_prompts()}</div>
          <div class="text-2xl font-bold text-(--text-primary)">{result.total_prompts}</div>
        </div>
        <div>
          <div class="text-[10px] text-(--text-secondary) uppercase tracking-wider">{m.portal_comp_resources()}</div>
          <div class="text-2xl font-bold text-(--text-primary)">{result.total_resources}</div>
        </div>
      </div>

      {#each result.routes as r (r.upstream_id)}
        {@const badge = statusBadge(r.status)}
        <div class="bg-(--bg-card) border border-(--border) rounded-lg p-4">
          <div class="flex items-center justify-between mb-2 gap-2 flex-wrap">
            <div class="flex items-center gap-2">
              <span class="text-sm font-semibold text-(--text-primary)">{r.upstream_name}</span>
              <span class="text-[10px] font-medium px-1.5 py-0.5 rounded-sm {badge.color}" data-testid="route-status" data-status={r.status}>{badge.label}</span>
              <code class="text-[10px] text-(--text-secondary) font-mono bg-(--bg-primary) px-1.5 py-0.5 rounded-sm">{r.auth_mode}</code>
              {#if r.prefix}
                <code class="text-[10px] text-(--accent) font-mono bg-(--accent)/10 px-1.5 py-0.5 rounded-sm">{r.prefix}__</code>
              {/if}
            </div>
            <code class="text-[10px] text-(--text-secondary) font-mono truncate">{r.upstream_url}</code>
          </div>
          {#if r.error}
            <div class="text-xs text-(--error) mb-2">{r.error}</div>
          {/if}
          {#if r.tools.length > 0}
            <div class="mt-2">
              <div class="text-[10px] text-(--text-secondary) uppercase tracking-wider mb-1">{m.portal_comp_tools_count({ count: r.tools.length })}</div>
              <div class="flex flex-wrap gap-1">
                {#each r.tools as t, i (i)}
                  <code title={t.description ?? ''} class="text-xs font-mono px-1.5 py-0.5 rounded-sm bg-(--bg-primary) text-(--text-primary) border border-(--border)">{t.name}</code>
                {/each}
              </div>
            </div>
          {/if}
          {#if r.prompts.length > 0}
            <div class="mt-2">
              <div class="text-[10px] text-(--text-secondary) uppercase tracking-wider mb-1">{m.portal_comp_prompts_count({ count: r.prompts.length })}</div>
              <div class="flex flex-wrap gap-1">
                {#each r.prompts as p, i (i)}
                  <code title={p.description ?? ''} class="text-xs font-mono px-1.5 py-0.5 rounded-sm bg-(--bg-primary) text-(--text-primary) border border-(--border)">{p.name}</code>
                {/each}
              </div>
            </div>
          {/if}
          {#if r.resources.length > 0}
            <div class="mt-2">
              <div class="text-[10px] text-(--text-secondary) uppercase tracking-wider mb-1">{m.portal_comp_resources_count({ count: r.resources.length })}</div>
              <ul class="text-xs space-y-0.5">
                {#each r.resources as res, i (i)}
                  <li class="text-(--text-secondary)">
                    <code class="font-mono text-(--text-primary)">{res.uri}</code>
                    {#if res.name}— {res.name}{/if}
                  </li>
                {/each}
              </ul>
            </div>
          {/if}
        </div>
      {/each}
    </div>
  {/if}
</div>
