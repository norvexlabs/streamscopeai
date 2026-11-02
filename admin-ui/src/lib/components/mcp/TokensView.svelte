<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import { extractError, extractErrorCode } from '#lib/api-helpers.js';
  import { page } from '$app/state';
  import { thref } from '#lib/tenant.js';
  import { auditHref } from '#lib/deeplinks.js';

  let slug = $derived(page.params.slug ?? '');
  import { toast } from '#lib/toast.svelte.js';
  import type { components } from '#lib/generated/api-types.js';
  import { formatTimeAgo } from '#lib/formatters.js';
  import { UrlFilters } from '#lib/hooks.svelte.js';
  import ConfirmDialog from '#lib/components/ConfirmDialog.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';

  type VirtualServerRow = components['schemas']['McpVirtualServerRow'];
  type OauthClientRow = components['schemas']['OauthClientRow'];
  type IssuedTokenRow = components['schemas']['IssuedTokenRow'];
  type ListResponse = components['schemas']['IssuedTokensListResponse'];
  type StatusFilter = components['schemas']['TokenStatusFilter'];

  let { virtualServers, oauthClients }: { virtualServers: VirtualServerRow[]; oauthClients: OauthClientRow[] } = $props();

  // URL-bound filter state — refresh / share preserves the operator's
  // view. `status: 'active'` is the default; URLs omit it for clean links.
  type FilterKey = 'client_id' | 'virtual_server_id' | 'audience' | 'status' | 'q';
  const filters = new UrlFilters<FilterKey>(
    ['client_id', 'virtual_server_id', 'audience', 'status', 'q'],
    { status: 'active' },
  );

  let response = $state<ListResponse | null>(null);
  let loading = $state(false);
  let error = $state('');
  let offset = $state(0);
  const limit = 50;

  let pendingRevoke = $state<IssuedTokenRow | null>(null);

  // Pagination footer total must reflect the active status filter — otherwise
  // "Showing 1–50 of N" reads wrong (the list is filtered, the breakdown isn't).
  function totalForStatus(b: ListResponse['total_breakdown'], s: StatusFilter): number {
    switch (s) {
      case 'active': return b.active;
      case 'revoked': return b.revoked;
      case 'expired': return b.expired;
      case 'all': return b.issued;
    }
  }

  async function load() {
    loading = true;
    error = '';
    const q = filters.values.q.trim();
    const query: Record<string, string | number | undefined> = {
      limit,
      offset,
      status: (filters.values.status || 'active') as StatusFilter,
      client_id: filters.values.client_id || undefined,
      virtual_server_id: filters.values.virtual_server_id || undefined,
      audience: filters.values.audience || undefined,
      q: q ? q : undefined,
    };
    const { data, error: err } = await adminApi.GET('/api/v1/admin/mcp/issued-tokens', {
      params: { query },
    });
    if (err) {
      error = extractError(err);
    } else {
      response = data ?? null;
    }
    loading = false;
    // Arm the URL-sync after the first load so the seed-from-URL doesn't
    // immediately re-write a redundant URL.
    filters.arm();
  }

  // Debounce the search-text refetch so a typing user doesn't fire one
  // `GET /issued-tokens` per keystroke. 200ms idle window — same shape
  // as `UrlFilters.flush()`. Dropdown filters refetch immediately
  // (changing client/endpoint/status is a deliberate single click).
  let qDebounceTimer: ReturnType<typeof setTimeout> | null = null;
  $effect(() => {
    void filters.values.client_id;
    void filters.values.virtual_server_id;
    void filters.values.audience;
    void filters.values.status;
    offset = 0;
    void load();
  });
  $effect(() => {
    void filters.values.q;
    offset = 0;
    if (qDebounceTimer != null) clearTimeout(qDebounceTimer);
    qDebounceTimer = setTimeout(() => {
      qDebounceTimer = null;
      void load();
    }, 200);
  });
  $effect(() => {
    void offset;
    void load();
  });

  async function confirmRevoke() {
    const token = pendingRevoke;
    if (!token) return;
    pendingRevoke = null;
    const { error: err } = await adminApi.POST(
      '/api/v1/admin/mcp/issued-tokens/{jti}/actions/revoke',
      { params: { path: { jti: token.jti } } },
    );
    if (err) {
      toast.error('Failed to revoke token', {
        body: extractError(err),
        code: extractErrorCode(err) ?? undefined,
      });
      return;
    }
    void load();
  }

  function tokenStatusLabel(token: IssuedTokenRow): { kind: 'active' | 'revoked' | 'expired'; label: string } {
    if (token.revoked_at) return { kind: 'revoked', label: 'revoked' };
    if (new Date(token.expires_at).getTime() <= Date.now()) return { kind: 'expired', label: 'expired' };
    const left = new Date(token.expires_at).getTime() - Date.now();
    const hours = left / 3_600_000;
    if (hours >= 24) return { kind: 'active', label: `${Math.round(hours / 24)}d left` };
    if (hours >= 1) return { kind: 'active', label: `${Math.round(hours)}h left` };
    return { kind: 'active', label: `${Math.round(left / 60_000)}m left` };
  }

  function audienceForVs(vsId: string): string {
    return virtualServers.find((v) => v.id === vsId)?.slug ?? vsId.slice(0, 8) + '…';
  }
</script>

<div class="space-y-4">
  <!-- Header summary -->
  <div class="flex items-center justify-between text-sm text-(--text-secondary)">
    {#if response}
      <p>
        <span class="font-mono text-(--text-primary)">{response.total_breakdown.issued}</span> issued ·
        <span class="font-mono text-(--success)">{response.total_breakdown.active}</span> active ·
        <span class="font-mono">{response.total_breakdown.revoked + response.total_breakdown.expired}</span> revoked-or-expired
      </p>
    {:else}
      <p>Loading…</p>
    {/if}
  </div>

  <!-- Filter bar -->
  <div class="bg-(--bg-card) rounded-xl border border-(--border) p-4">
    <div class="flex flex-wrap gap-3 items-center">
      <input
        bind:value={filters.values.q}
        placeholder="Filter by jti or scope…"
        class="flex-1 min-w-50 px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm placeholder:text-(--text-secondary)"
      />
      <SelectInput bind:value={filters.values.client_id} fluid={false}>
        <option value="">All clients</option>
        {#each oauthClients as c}
          <option value={c.client_id}>{c.name}</option>
        {/each}
      </SelectInput>
      <SelectInput bind:value={filters.values.virtual_server_id} fluid={false}>
        <option value="">All endpoints</option>
        {#each virtualServers as vs}
          <option value={vs.id}>{vs.slug}</option>
        {/each}
      </SelectInput>
      <SelectInput bind:value={filters.values.status} fluid={false}>
        <option value="active">Active</option>
        <option value="revoked">Revoked</option>
        <option value="expired">Expired</option>
        <option value="all">All</option>
      </SelectInput>
    </div>
    {#if filters.values.audience}
      <div class="mt-2 text-xs">
        <span class="inline-flex items-center gap-1 px-2 py-1 rounded-sm bg-(--bg-primary) text-(--text-secondary)">
          audience: <span class="font-mono">{filters.values.audience}</span>
          <button class="text-(--text-secondary) hover:text-(--error)" onclick={() => (filters.values.audience = '')}>×</button>
        </span>
      </div>
    {/if}
  </div>

  <!-- Error -->
  {#if error}
    <div class="bg-(--error-bg) border border-(--error-border) rounded-lg p-3 text-sm text-(--error-text)">
      {error}
    </div>
  {/if}

  <!-- Table -->
  <div class="bg-(--bg-card) rounded-xl border border-(--border) overflow-hidden">
    {#if loading && !response}
      <div class="px-5 py-12 text-center text-sm text-(--text-secondary)">Loading tokens…</div>
    {:else if response && response.items.length === 0}
      <div class="px-5 py-12 text-center text-sm text-(--text-secondary)">No tokens match these filters</div>
    {:else if response}
      <table class="w-full text-sm">
        <thead>
          <tr class="border-b border-(--border) bg-(--bg-primary)">
            <th class="px-5 py-3 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">JTI</th>
            <th class="px-5 py-3 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Client</th>
            <th class="px-5 py-3 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Endpoint</th>
            <th class="px-5 py-3 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">User</th>
            <th class="px-5 py-3 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Scope</th>
            <th class="px-5 py-3 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Issued</th>
            <th class="px-5 py-3 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Status</th>
            <th class="px-5 py-3 text-right text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Actions</th>
          </tr>
        </thead>
        <tbody>
          {#each response.items as token}
            {@const sp = tokenStatusLabel(token)}
            <tr class="border-b border-(--border) hover:bg-(--bg-elevated)">
              <td class="px-5 py-2.5 font-mono text-xs text-(--text-primary)">{token.jti.toString().slice(0, 8)}…</td>
              <td class="px-5 py-2.5 text-(--text-primary)">{token.client_name ?? token.client_id}</td>
              <td class="px-5 py-2.5 font-mono text-xs">{token.virtual_server_slug ?? audienceForVs(token.virtual_server_id)}</td>
              <td class="px-5 py-2.5 text-xs">{token.user_email}</td>
              <td class="px-5 py-2.5 font-mono text-xs text-(--text-secondary)">{token.scope || '—'}</td>
              <td class="px-5 py-2.5 text-xs text-(--text-secondary)">{formatTimeAgo(token.issued_at)}</td>
              <td class="px-5 py-2.5">
                <span
                  class="inline-flex items-center gap-1.5 text-xs"
                  class:text-success={sp.kind === 'active'}
                  class:text-error={sp.kind === 'revoked'}
                  class:text-muted={sp.kind === 'expired'}
                >
                  <span class="w-1.5 h-1.5 rounded-full {sp.kind === 'active' ? 'bg-(--success)' : sp.kind === 'revoked' ? 'bg-(--error)' : 'bg-(--text-secondary)'}"></span>
                  {sp.label}
                </span>
              </td>
              <td class="px-5 py-2.5 text-right">
                <a
                  href={thref(slug, auditHref({ kind: 'mcp', jti: token.jti }))}
                  class="text-xs text-(--accent) hover:text-(--accent-hover) mr-3"
                >Audit</a>
                {#if !token.revoked_at}
                  <button
                    onclick={() => (pendingRevoke = token)}
                    class="text-xs text-(--error) hover:bg-(--error-bg) px-1.5 rounded-sm"
                  >Revoke</button>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>

      <!-- Pagination -->
      <div class="flex items-center justify-between px-5 py-3 border-t border-(--border) text-xs text-(--text-secondary)">
        <span>Showing {offset + 1}–{offset + response.items.length} of {totalForStatus(response.total_breakdown, (filters.values.status || 'active') as StatusFilter)}</span>
        <div class="flex items-center gap-2">
          <button
            disabled={offset === 0}
            onclick={() => (offset = Math.max(0, offset - limit))}
            class="px-2 py-1 rounded-sm hover:bg-(--bg-elevated) disabled:opacity-30">Prev</button>
          <button
            disabled={!response.has_more}
            onclick={() => (offset = offset + limit)}
            class="px-2 py-1 rounded-sm hover:bg-(--bg-elevated) disabled:opacity-30">Next</button>
        </div>
      </div>
    {/if}
  </div>
</div>

<ConfirmDialog
  open={pendingRevoke !== null}
  title="Revoke token"
  message={pendingRevoke ? `Revoke token ${pendingRevoke.jti.toString().slice(0, 8)}…? The user will be disconnected mid-session and cannot reconnect with this token.` : ''}
  confirmLabel="Revoke"
  destructive
  onconfirm={confirmRevoke}
  oncancel={() => (pendingRevoke = null)}
/>

<style>
  .text-success { color: var(--success); }
  .text-error { color: var(--error); }
  .text-muted { color: var(--text-secondary); }
</style>
