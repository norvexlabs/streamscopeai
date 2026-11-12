<script lang="ts">
  import type { components } from '#lib/generated/api-types.js';
  import SystemRowBadge from '#lib/components/SystemRowBadge.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import { page } from '$app/state';
  import { thref } from '#lib/tenant.js';
  import { declaredInputs, missingAdminValues, remoteFillers } from '#lib/mcp/headerInputs.js';
  import { FILLER_HELP, FILLER_NAME, inputRoster } from '#lib/mcp/fillers.js';
  import { adminApi } from '#lib/api-client.js';
  import { extractError } from '#lib/api-helpers.js';
  import FormError from '#lib/components/forms/FormError.svelte';
  import UpstreamTestResult from '#lib/components/mcp/UpstreamTestResult.svelte';
  import type { UpstreamTestResult as TestResult } from '#lib/mcp/upstreamTest.js';

  let slug = $derived(page.params.slug ?? '');
  // The test is a POST, which the server refuses a read-only account.
  const canTest = $derived(page.data.user?.role !== 'read_only');

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

  // The last Test result of each upstream, and the ones in flight.
  let testResults = $state<Record<string, TestResult>>({});
  let testErrors = $state<Record<string, string>>({});
  let testing = $state<Record<string, boolean>>({});

  async function runTest(u: UpstreamRow) {
    testing = { ...testing, [u.id]: true };
    const results = { ...testResults };
    const errors = { ...testErrors };
    delete results[u.id];
    delete errors[u.id];
    testResults = results;
    testErrors = errors;
    const { data, error } = await adminApi.POST('/api/v1/admin/mcp/upstream-servers/{id}/actions/test', {
      params: { path: { id: u.id } },
    });
    if (error || !data) testErrors = { ...testErrors, [u.id]: extractError(error, 'The test could not run.') };
    else testResults = { ...testResults, [u.id]: data };
    testing = { ...testing, [u.id]: false };
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

  /** Who fills the upstream's inputs, and which admin values are missing. */
  function inputSummary(u: UpstreamRow): { admin: number; user: number; client: string[]; missing: string[] } {
    const inputs = declaredInputs(u.remote);
    const fillers = remoteFillers(u.remote);
    const count = (f: string) => inputs.filter((d) => fillers[d.id] === f).length;
    const missing = missingAdminValues(
      inputs,
      fillers,
      (id) => id in u.inputs || u.secret_input_ids.includes(id),
    );
    return { admin: count('admin'), user: count('user'), client: u.client_headers, missing };
  }

  function authLabel(u: UpstreamRow): string {
    return u.auth_mode === 'per_user_oauth' ? 'per-user OAuth' : 'headers';
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
        {@const summary = inputSummary(u)}
        <div class="px-6 py-4" data-testid="upstream-row" data-upstream-id={u.id}>
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
                  data-testid="upstream-auth-pill"
                  class="inline-block px-1.5 py-0.5 text-[10px] rounded-sm font-medium {oauthBad || summary.missing.length > 0
                    ? 'bg-(--warning-bg) text-(--warning-text)'
                    : u.auth_mode === 'per_user_oauth'
                      ? 'bg-(--info-bg) text-(--info-text)'
                      : 'bg-(--bg-primary) border border-(--border) text-(--text-secondary)'}"
                  title={summary.missing.length > 0
                    ? `Missing administrator value: ${summary.missing.join(', ')} — every call fails until it is set`
                    : oauthBad
                      ? 'OAuth client incomplete — set the Client ID and Secret (Edit) before granting this endpoint or connecting from the portal'
                      : ''}
                >
                  {authLabel(u)}{#if oauthBad || summary.missing.length > 0} ⚠{/if}
                </span>
                {#if summary.user > 0}
                  <span class="inline-block px-1.5 py-0.5 text-[10px] rounded-sm bg-(--tag-violet-bg) text-(--tag-violet-text)" title="Inputs each user fills in the portal">user inputs: {summary.user}</span>
                {/if}
                {#if summary.client.length > 0}
                  <span class="inline-block px-1.5 py-0.5 text-[10px] rounded-sm font-mono bg-(--bg-primary) border border-(--border) text-(--text-secondary)" title="Headers the client sends on every request">client: {summary.client.join(', ')}</span>
                {/if}
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
              {#if canTest}
                <button
                  type="button"
                  data-testid="upstream-test"
                  class="text-xs font-medium text-(--accent) hover:text-(--accent-hover) disabled:opacity-50"
                  disabled={testing[u.id] === true}
                  title="Call the upstream with the administrator's values and list what it serves"
                  onclick={() => void runTest(u)}
                >{testing[u.id] ? 'Testing…' : 'Test'}</button>
              {/if}
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

          {#if summary.missing.length > 0}
            <div class="mt-2 ml-7 flex items-center gap-2 text-xs text-(--warning-text)" data-testid="upstream-missing-admin">
              <span>Administrator value not set: <code class="font-mono">{summary.missing.join(', ')}</code> — calls fail until set.</span>
              {#if !isBuiltIn}
                <button type="button" class="font-medium text-(--accent) hover:text-(--accent-hover) underline" onclick={() => onOpenEdit(u)}>Set it</button>
              {/if}
            </div>
          {/if}

          {#if testErrors[u.id]}
            <div class="mt-3 ml-7"><FormError message={testErrors[u.id]} /></div>
          {:else if testResults[u.id]}
            <div class="mt-3 ml-7"><UpstreamTestResult result={testResults[u.id]} onedit={isBuiltIn ? undefined : () => onOpenEdit(u)} /></div>
          {/if}

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
              {#if u.remote.headers && u.remote.headers.length > 0}
                <div class="pt-2 border-t border-(--border)">
                  <p class="text-[10px] text-(--text-secondary) uppercase tracking-wider">Headers</p>
                  <ul class="mt-1 space-y-0.5 text-xs">
                    {#each inputRoster(u.remote, u.inputs, u.secret_input_ids) as r (r.id)}
                      <li class="flex items-center gap-2 flex-wrap" data-testid="upstream-input" data-input-id={r.id} data-state={r.state}>
                        <code class="font-mono text-(--text-primary)">{r.id}</code>
                        <span class="text-(--text-secondary)" title={r.filler ? FILLER_HELP[r.filler] : ''}>{r.filler ? FILLER_NAME[r.filler] : '—'}</span>
                        {#if r.state === 'set'}
                          {#if r.value !== null}
                            <code class="font-mono text-(--text-secondary)">· {r.value}</code>
                          {:else}
                            <span class="text-(--success-text)">· set</span>
                          {/if}
                        {:else if r.state === 'missing'}
                          <span class="text-(--warning-text)">· not set — calls fail until set</span>
                        {:else if r.state === 'unset'}
                          <span class="text-(--text-secondary)">· not set (optional)</span>
                        {:else if r.filler === 'user'}
                          <span class="text-(--text-secondary)">· in the portal's MCP Sign-ins page</span>
                        {:else if r.filler === 'client'}
                          <span class="text-(--text-secondary)">· on each request</span>
                        {/if}
                      </li>
                    {/each}
                  </ul>
                  {#if summary.admin === 0 && summary.user === 0 && summary.client.length === 0}
                    <p class="text-xs text-(--text-secondary) mt-1">Fixed headers only.</p>
                  {/if}
                </div>
              {/if}
            </div>
          {/if}
        </div>
      {/each}
    </div>
  {/if}
</div>
