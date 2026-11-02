<script lang="ts">
  import { toast } from '#lib/toast.svelte.js';
  import { extractError } from '#lib/api-helpers.js';
  import { page } from '$app/state';
  import { goto } from '$app/navigation';
  import { thref } from '#lib/tenant.js';
  import type { PageProps } from './$types';

  let { params }: PageProps = $props();

  let slug = $derived(params.slug);
  import type { components } from '#lib/generated/api-types.js';
  import { adminApi } from '#lib/api-client.js';
  import { daysToDateRange, formatDateTime } from '#lib/formatters.js';
  import EmptyState from '#lib/components/EmptyState.svelte';
  import Skeleton from '#lib/components/Skeleton.svelte';
  import Pagination from '#lib/components/Pagination.svelte';
  import RawJsonBlock from '#lib/components/RawJsonBlock.svelte';
  import { diffSides, isTruncated, truncatedBytes } from '#lib/audit-record.js';
  import TagBadge from '#lib/components/TagBadge.svelte';
  import Copyable from '#lib/components/Copyable.svelte';
  import Tabs from '#lib/components/Tabs.svelte';
  import FilterField from '#lib/components/filter/FilterField.svelte';
  import TextInput from '#lib/components/forms/TextInput.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import { consoleScope, PERIOD_FILTER_KEYS, PERIOD_FILTER_DEFAULTS, workspaceIdsQuery } from '#lib/scope.svelte.js';
  import { usePeriodicLoad, usePagination, UrlFilters, useAuditPeriod } from '#lib/hooks.svelte.js';
  import { useRefreshView } from '#lib/loadView.svelte.js';
  import PeriodSelector from '#lib/components/PeriodSelector.svelte';
  import { httpMethodTag } from '#lib/colormaps/http_methods.js';
  import { adminActionTag } from '#lib/colormaps/admin_actions.js';
  import { statusCodeColor } from '#lib/colormaps/status_codes.js';

  type AdminAuditRow = components['schemas']['AdminAuditRow'];
  type GlobalAdminAuditRow = components['schemas']['GlobalAdminAuditRow'];
  type PortalAuditRow = components['schemas']['PortalAuditRow'];
  type GlobalPortalAuditRow = components['schemas']['GlobalPortalAuditRow'];
  type SecurityAuditRow = components['schemas']['SecurityAuditRow'];

  type Plane = 'admin' | 'portal' | 'security';

  /** Unified row across the three planes — each load maps its rows into this. */
  interface Row {
    id: string;
    at: string;
    method: string;
    path: string;
    route_template?: string | null;
    action: string;
    status_code: number;
    request_id: string;
    actor_email?: string | null;
    actor_id?: string | null;
    actor_ip?: string | null;
    request_body?: unknown;
    response_error?: unknown;
    change_diff?: unknown;
    // admin / portal
    resource_kind?: string | null;
    resource_id?: string | null;
    tenant_slug?: string | null;
    // portal
    workspace_id?: string | null;
    target_user_id?: string | null;
    // security
    actor_identity?: string | null;
    succeeded?: boolean;
  }

  const isSuperAdmin = !!page.data.user?.is_super_admin;

  const PLANES: Array<{ id: Plane; label: string }> = [
    { id: 'admin', label: 'Admin' },
    { id: 'portal', label: 'Portal' },
    { id: 'security', label: 'Security' },
  ];
  const PLANE_BLURB: Record<Plane, string> = {
    admin: 'Operator-action log — every mutating admin API call records who did what, when, and with which payload (secrets redacted).',
    portal: 'End-user action log — portal key, MCP connection, and quickstart mutations, scoped to this tenant.',
    security: 'Pre-auth security events for this tenant — login, account setup, OIDC exchange, invite acceptance, and MCP-OAuth attempts (success and failure).',
  };

  const initialTab = (page.url.searchParams.get('tab') as Plane) ?? 'admin';
  let plane = $state<Plane>(PLANES.some((p) => p.id === initialTab) ? initialTab : 'admin');

  let rows = $state<Row[]>([]);
  let loading = $state(true);
  // A refresh keeps what is shown, so an auto-refresh tick never blanks it;
  // a filter or page change shows the skeleton (`useRefreshView`).
  const view = useRefreshView(() => loading);
  let expandedId = $state<string | null>(null);
  let pendingFocusRid: string | null = page.url.searchParams.get('request_id');
  /** The focus the page's last own load used — what a refresh keeps. */
  let focusedRid: string | null = null;

  // Email → id lookup for the admin-plane actor_email filter. Loaded once.
  let emailToId = $state<Map<string, string>>(new Map());
  // Tenant dropdown options (super-admin only, admin plane). slug → display name.
  let tenants = $state<Array<{ slug: string; name: string }>>([]);

  type FilterKey =
    | 'actor_email' | 'actor_id' | 'action' | 'resource_kind' | 'tenant_slug'
    | 'workspace_ids' | 'succeeded'
    // Inline, URL-bound period (rolling `days` OR absolute `start`/`end`).
    | 'days' | 'start' | 'end';
  const filters = new UrlFilters<FilterKey>([
    'actor_email', 'actor_id', 'action', 'resource_kind', 'tenant_slug',
    'workspace_ids', 'succeeded',
    ...PERIOD_FILTER_KEYS,
  ], { ...PERIOD_FILTER_DEFAULTS });

  // Inline period + cross-view persistence: URL-bound `<PeriodSelector>` whose
  // range follows the operator across the investigative views and stays
  // shareable via the URL. Applies to all three planes. The workspace filter is
  // portal-plane only and semantically distinct from the audit family's, so it
  // does NOT share the remembered workspace (persistWorkspace: false).
  const period = useAuditPeriod(filters, applyFilters, { persistWorkspace: false });

  const pager = usePagination({ limit: 50 });

  usePeriodicLoad(async () => {
    try {
      const { data } = await adminApi.GET('/api/v1/admin/admin-accounts', {
        params: { query: { limit: 500 } },
      });
      type AdminAccountSummary = components['schemas']['AdminAccountResponse'];
      const accounts: AdminAccountSummary[] = data?.items ?? [];
      emailToId = new Map(
        accounts.map((a: AdminAccountSummary): [string, string] => [a.email.toLowerCase(), a.id]),
      );
    } catch (e) {
      toast.error(extractError(e));
    }
    if (isSuperAdmin) {
      try {
        const { data } = await adminApi.GET('/api/v1/admin/tenants', {
          params: { query: { limit: 500 } },
        });
        type TenantSummary = components['schemas']['TenantResponse'];
        const items: TenantSummary[] = data?.items ?? [];
        tenants = items
          .filter((t: TenantSummary) => t.slug !== 'system')
          .map((t: TenantSummary) => ({ slug: t.slug, name: t.name }));
      } catch (e) {
        toast.error(extractError(e));
      }
    }
    await loadRows();
    filters.arm();
    filters.pushToUrl();
  }, (cause) => view.refresh(loadRows, cause));

  // Monotonic load token: the workspace list loads async after mount, so the
  // initial (unfiltered) query and the corrective (default-filtered) re-fire
  // overlap on the portal plane. Threaded into `absorb` so a superseded
  // response is dropped instead of clobbering the list.
  let loadGen = 0;
  async function loadRows() {
    view.begin();
    loading = true;
    const gen = ++loadGen;
    const pv = period.value;
    const { start, end } = pv.kind === 'absolute'
      ? { start: pv.start, end: pv.end }
      : daysToDateRange(pv.days);
    // Consumed by the page's own load; a refresh keeps the focus that load
    // used, so a tick never swaps the focused row for the whole list.
    const refreshing = view.refreshing;
    const focusRid = (refreshing ? focusedRid : pendingFocusRid) ?? undefined;
    if (!refreshing) focusedRid = pendingFocusRid;
    pendingFocusRid = null;
    const action = filters.values.action || undefined;

    if (plane === 'admin') {
      let actorId = filters.values.actor_id || undefined;
      if (!actorId && filters.values.actor_email) {
        actorId = emailToId.get(filters.values.actor_email.toLowerCase());
      }
      if (isSuperAdmin) {
        const { data, error: err } = await adminApi.GET('/api/v1/admin/global/admin-audit', {
          params: { query: {
            tenant_slug: filters.values.tenant_slug || undefined,
            actor_id: actorId,
            action,
            resource_kind: filters.values.resource_kind || undefined,
            request_id: focusRid,
            start: focusRid ? undefined : start,
            end: focusRid ? undefined : end,
            limit: pager.limit,
            offset: pager.offset,
          } },
        });
        if (err) toast.error(extractError(err));
        else absorb(gen, data, (r: GlobalAdminAuditRow): Row => r, focusRid);
      } else {
        const { data, error: err } = await adminApi.GET('/api/v1/admin/admin-audit', {
          params: { query: {
            actor_id: actorId,
            action,
            resource_kind: filters.values.resource_kind || undefined,
            request_id: focusRid,
            start: focusRid ? undefined : start,
            end: focusRid ? undefined : end,
            limit: pager.limit,
            offset: pager.offset,
          } },
        });
        if (err) toast.error(extractError(err));
        else absorb(gen, data, (r: AdminAuditRow): Row => r, focusRid);
      }
    } else if (plane === 'portal') {
      if (isSuperAdmin) {
        const { data, error: err } = await adminApi.GET('/api/v1/admin/global/portal-audit', {
          params: { query: {
            tenant_slug: filters.values.tenant_slug || undefined,
            action,
            ...workspaceIdsQuery(filters.values.workspace_ids, consoleScope.workspaces),
            request_id: focusRid,
            start: focusRid ? undefined : start,
            end: focusRid ? undefined : end,
            limit: pager.limit,
            offset: pager.offset,
          } },
        });
        if (err) toast.error(extractError(err));
        else absorb(gen, data, (r: GlobalPortalAuditRow): Row => r, focusRid);
      } else {
        const { data, error: err } = await adminApi.GET('/api/v1/admin/portal-audit', {
          params: { query: {
            action,
            ...workspaceIdsQuery(filters.values.workspace_ids, consoleScope.workspaces),
            request_id: focusRid,
            start: focusRid ? undefined : start,
            end: focusRid ? undefined : end,
            limit: pager.limit,
            offset: pager.offset,
          } },
        });
        if (err) toast.error(extractError(err));
        else absorb(gen, data, (r: PortalAuditRow): Row => r, focusRid);
      }
    } else {
      const succeeded =
        filters.values.succeeded === 'true' ? true
        : filters.values.succeeded === 'false' ? false
        : undefined;
      if (isSuperAdmin) {
        const { data, error: err } = await adminApi.GET('/api/v1/admin/global/security-audit', {
          params: { query: {
            tenant_slug: filters.values.tenant_slug || undefined,
            action,
            succeeded,
            request_id: focusRid,
            start: focusRid ? undefined : start,
            end: focusRid ? undefined : end,
            limit: pager.limit,
            offset: pager.offset,
          } },
        });
        if (err) toast.error(extractError(err));
        else absorb(gen, data, (r: SecurityAuditRow): Row => r, focusRid);
      } else {
        const { data, error: err } = await adminApi.GET('/api/v1/admin/security-audit', {
          params: { query: {
            action,
            succeeded,
            request_id: focusRid,
            start: focusRid ? undefined : start,
            end: focusRid ? undefined : end,
            limit: pager.limit,
            offset: pager.offset,
          } },
        });
        if (err) toast.error(extractError(err));
        else absorb(gen, data, (r: SecurityAuditRow): Row => r, focusRid);
      }
    }
    if (gen === loadGen) loading = false;
  }

  function absorb<T>(
    gen: number,
    data: { items?: T[]; has_more: boolean } | undefined,
    map: (r: T) => Row,
    focusRid?: string,
  ) {
    if (gen !== loadGen) return; // superseded by a newer load
    if (!data) return;
    const items = (pager.absorbOffset(data) as T[]).map(map);
    rows = items;
    // Once, on the load that consumed the link — a refresh keeps the viewer's
    // own expansion.
    if (focusRid && rows.length > 0 && !view.refreshing) expandedId = focusRid;
  }

  function switchPlane(next: string) {
    plane = next as Plane;
    expandedId = null;
    pager.reset();
    void loadRows();
  }

  function handleFilterKeydown(e: KeyboardEvent) {
    if (e.key === 'Enter') applyFilters();
  }

  async function applyFilters() {
    pager.reset();
    await loadRows();
  }

  async function clearFilters() {
    filters.clear();
    pager.reset();
    await loadRows();
  }

  function toggleExpand(id: string) {
    expandedId = expandedId === id ? null : id;
    const params = new URLSearchParams(page.url.search);
    if (expandedId) params.set('request_id', expandedId);
    else params.delete('request_id');
    const qs = params.toString();
    void goto(thref(slug, `/admin-audit${qs ? '?' + qs : ''}`), { replace: true, reset: false });
  }
</script>

<div>
  <div class="flex items-center justify-between mb-4">
    <div>
      <h1 class="text-2xl font-semibold text-(--text-primary)">Audit</h1>
      <p class="text-sm text-(--text-secondary) mt-1">
        {PLANE_BLURB[plane]}
        {#if isSuperAdmin}<span class="text-(--accent)">Super-admin view: showing every tenant{#if plane === 'security'} (including events with no resolvable tenant){/if}.</span>{/if}
      </p>
    </div>
  </div>

  <Tabs tabs={PLANES} active={plane} onchange={switchPlane} class="mb-4" />

  <!-- Filter bar -->
  <div class="bg-(--bg-card) rounded-xl p-3 border border-(--border) mb-6">
    <div class="flex flex-wrap items-end gap-3">
      <div class="pb-px"><PeriodSelector selected={period.value} onchange={period.change} /></div>
      {#if isSuperAdmin}
        <FilterField label="Tenant" class="min-w-40">
          <SelectInput bind:value={filters.values.tenant_slug} onchange={applyFilters}>
            <option value="">All tenants</option>
            {#each tenants as t (t.slug)}
              <option value={t.slug}>{t.name}</option>
            {/each}
          </SelectInput>
        </FilterField>
      {/if}
      {#if plane === 'admin'}
        <FilterField label="Actor email" class="min-w-45">
          <TextInput
            bind:value={filters.values.actor_email}
            onkeydown={handleFilterKeydown}
            placeholder="admin@example.com"
          />
        </FilterField>
      {/if}
      <FilterField label="Action" class="min-w-45">
        <TextInput
          bind:value={filters.values.action}
          onkeydown={handleFilterKeydown}
          placeholder={plane === 'security' ? 'e.g. auth.login' : plane === 'portal' ? 'e.g. portal_key.create' : 'e.g. users.create'}
          mono
        />
      </FilterField>
      {#if plane === 'admin'}
        <FilterField label="Resource" class="min-w-40">
          <SelectInput bind:value={filters.values.resource_kind} onchange={applyFilters}>
            <option value="">All</option>
            <option value="users">Users</option>
            <option value="keys">Keys</option>
            <option value="admin_accounts">Admin accounts</option>
            <option value="servers">Upstream servers</option>
            <option value="models">Models</option>
            <option value="catalog">Catalog</option>
            <option value="downstream_providers">Downstream providers</option>
            <option value="route_policies">Route policies</option>
            <option value="mcp">MCP</option>
            <option value="tool_rules">Tool rules</option>
            <option value="tool_field_profiles">Tool field profiles</option>
            <option value="transforms">Transforms</option>
            <option value="experts">Experts</option>
            <option value="workspaces">Workspaces</option>
            <option value="settings">Settings</option>
            <option value="maintenance">Maintenance</option>
            <option value="tenants">Tenants</option>
            <option value="edge_nodes">Edge nodes</option>
            <option value="changelog">Changelog</option>
          </SelectInput>
        </FilterField>
      {/if}
      {#if plane === 'portal'}
        <FilterField label="Workspace ID" class="min-w-50">
          <TextInput
            bind:value={filters.values.workspace_ids}
            onkeydown={handleFilterKeydown}
            placeholder="workspace UUID"
            mono
          />
        </FilterField>
      {/if}
      {#if plane === 'security'}
        <FilterField label="Outcome" class="min-w-35">
          <SelectInput bind:value={filters.values.succeeded} onchange={applyFilters}>
            <option value="">All</option>
            <option value="true">Success</option>
            <option value="false">Failure</option>
          </SelectInput>
        </FilterField>
      {/if}
      <button
        onclick={clearFilters}
        class="px-3 py-1.5 border border-(--border) rounded-lg text-(--text-secondary) text-sm hover:text-(--text-primary) transition-colors"
      >
        Clear
      </button>
    </div>
  </div>

  {#if view.skeleton}
    <div class="bg-(--bg-card) rounded-xl border border-(--border) p-4">
      <Skeleton variant="row" count={10} height="2.75rem" />
    </div>
  {:else}
    <div class="bg-(--bg-card) rounded-xl border border-(--border) overflow-hidden">
      {#each rows as row (row.id)}
        <div
          class="border-b border-(--border) hover:bg-(--bg-elevated) transition-colors cursor-pointer"
          onclick={() => toggleExpand(row.id)}
          role="button"
          tabindex="0"
          aria-expanded={expandedId === row.id}
          onkeydown={(e) => { if ((e.key === 'Enter' || e.key === ' ') && e.target === e.currentTarget) { e.preventDefault(); toggleExpand(row.id); } }}
        >
          <div class="flex items-center gap-3 px-4 py-2.5 text-sm">
            <span class="text-(--text-secondary) w-4 inline-block transition-transform {expandedId === row.id ? 'rotate-90' : ''}">&#9654;</span>
            <TagBadge color={httpMethodTag(row.method)} class="uppercase tracking-wider w-15 justify-center">
              {row.method}
            </TagBadge>
            <span class="text-(--text-secondary) whitespace-nowrap font-mono text-xs min-w-37.5">
              {formatDateTime(row.at)}
            </span>
            {#if isSuperAdmin && row.tenant_slug}
              <TagBadge color="neutral" class="font-mono" title="Tenant">{row.tenant_slug}</TagBadge>
            {/if}
            <TagBadge color={adminActionTag(row.action)} class="font-mono">{row.action}</TagBadge>
            <div class="flex-1 min-w-0">
              {#if plane === 'security'}
                <span class="text-sm text-(--text-primary) truncate block" title={row.actor_identity ?? ''}>
                  {row.actor_identity ?? '—'}
                </span>
              {:else if row.actor_email}
                <span class="text-sm text-(--text-primary) truncate block" title={row.actor_email}>
                  {row.actor_email}
                </span>
              {:else}
                <span class="text-sm text-(--text-secondary) font-mono" title={row.actor_id ?? ''}>
                  {row.actor_id?.substring(0, 8) ?? '—'}
                </span>
              {/if}
            </div>
            {#if plane === 'security'}
              <TagBadge color={row.succeeded ? 'teal' : 'rose'} class="w-17.5 justify-center">
                {row.succeeded ? 'success' : 'failure'}
              </TagBadge>
            {/if}
            <span
              class="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium border whitespace-nowrap"
              style="color: {statusCodeColor(row.status_code)}; border-color: color-mix(in srgb, {statusCodeColor(row.status_code)} 19%, transparent); background-color: color-mix(in srgb, {statusCodeColor(row.status_code)} 6%, transparent)"
              title="HTTP {row.status_code}"
            >
              {row.status_code}
            </span>
          </div>
        </div>
        {#if expandedId === row.id}
          <div class="bg-(--bg-elevated) px-5 py-4 space-y-3 border-b border-(--border)">
            <div class="grid grid-cols-2 gap-x-6 gap-y-2 text-sm">
              <div>
                <span class="text-[10px] uppercase tracking-wider text-(--text-tertiary)">Path</span>
                <div class="font-mono text-xs text-(--text-primary) break-all">{row.path}</div>
              </div>
              <div>
                <span class="text-[10px] uppercase tracking-wider text-(--text-tertiary)">Route template</span>
                <div class="font-mono text-xs text-(--text-secondary)">{row.route_template ?? '—'}</div>
              </div>
              {#if plane !== 'security'}
                <div>
                  <span class="text-[10px] uppercase tracking-wider text-(--text-tertiary)">Resource</span>
                  <div class="text-xs text-(--text-primary)">
                    {row.resource_kind}{#if row.resource_id} · <span class="font-mono text-(--text-secondary)">{row.resource_id}</span>{/if}
                  </div>
                </div>
              {/if}
              {#if plane === 'security'}
                <div>
                  <span class="text-[10px] uppercase tracking-wider text-(--text-tertiary)">Attempted identity</span>
                  <div class="text-xs text-(--text-primary) break-all">{row.actor_identity ?? '—'}</div>
                </div>
                <div>
                  <span class="text-[10px] uppercase tracking-wider text-(--text-tertiary)">Tenant slug (attempted)</span>
                  <div class="font-mono text-xs text-(--text-secondary)">{row.tenant_slug ?? '—'}</div>
                </div>
              {/if}
              {#if plane === 'portal' && row.workspace_id}
                <div>
                  <span class="text-[10px] uppercase tracking-wider text-(--text-tertiary)">Workspace</span>
                  <div class="font-mono text-xs text-(--text-secondary)"><Copyable value={row.workspace_id} /></div>
                </div>
              {/if}
              {#if plane === 'portal' && row.target_user_id}
                <div>
                  <span class="text-[10px] uppercase tracking-wider text-(--text-tertiary)">Target user</span>
                  <div class="font-mono text-xs text-(--text-secondary)"><Copyable value={row.target_user_id} /></div>
                </div>
              {/if}
              <div>
                <span class="text-[10px] uppercase tracking-wider text-(--text-tertiary)">Actor IP</span>
                <div class="font-mono text-xs text-(--text-secondary)">{row.actor_ip ?? '—'}</div>
              </div>
              <div>
                <span class="text-[10px] uppercase tracking-wider text-(--text-tertiary)">Request ID</span>
                <div class="font-mono text-xs text-(--text-secondary)"><Copyable value={row.request_id} /></div>
              </div>
              <div>
                <span class="text-[10px] uppercase tracking-wider text-(--text-tertiary)">Audit row ID</span>
                <div class="font-mono text-xs text-(--text-secondary)"><Copyable value={row.id} /></div>
              </div>
            </div>
            {#if row.response_error}
              <div>
                <span class="text-[10px] uppercase tracking-wider text-(--text-tertiary)">Error response</span>
                <div class="mt-1 px-3 py-2 rounded-lg bg-(--error-bg) border border-(--error-border) text-xs text-(--error-text)">
                  {#if (row.response_error as { code?: string }).code}
                    <span class="font-mono font-medium">{(row.response_error as { code?: string }).code}</span>
                    {#if (row.response_error as { message?: string }).message}<span class="text-(--text-secondary)"> — </span>{(row.response_error as { message?: string }).message}{/if}
                  {:else}
                    <RawJsonBlock value={row.response_error} />
                  {/if}
                </div>
              </div>
            {/if}
            <div>
              <span class="text-[10px] uppercase tracking-wider text-(--text-tertiary)">Request body (redacted)</span>
              {#if row.request_body == null}
                <div class="text-xs text-(--text-tertiary) italic mt-1">empty / non-JSON</div>
              {:else}
                <RawJsonBlock value={row.request_body} />
              {/if}
            </div>
            {#if isTruncated(row.change_diff)}
              {@const bytes = truncatedBytes(row.change_diff)}
              <div>
                <span class="text-[10px] uppercase tracking-wider text-(--text-tertiary)">Change diff</span>
                <div class="text-xs text-(--text-tertiary) italic mt-1">
                  too large to record{bytes === null ? '' : ` (${bytes} bytes)`}
                </div>
              </div>
            {:else if row.change_diff}
              {@const sides = diffSides(row.change_diff)}
              <div>
                <span class="text-[10px] uppercase tracking-wider text-(--text-tertiary)">Change diff (before → after)</span>
                <div class="grid grid-cols-2 gap-3 mt-1">
                  <div>
                    <div class="text-[10px] uppercase tracking-wider text-(--text-tertiary) mb-1">Before</div>
                    <RawJsonBlock value={sides.before} />
                  </div>
                  <div>
                    <div class="text-[10px] uppercase tracking-wider text-(--text-tertiary) mb-1">After</div>
                    <RawJsonBlock value={sides.after} />
                  </div>
                </div>
              </div>
            {/if}
          </div>
        {/if}
      {/each}
      {#if rows.length === 0}
        <EmptyState
          title="No events match these filters"
          body="Loosen the time window or clear the filter bar above. Only mutating verbs (POST / PUT / PATCH / DELETE) are recorded — GETs are not audited."
        >
          {#snippet action()}
            <button
              onclick={clearFilters}
              class="px-4 py-1.5 text-sm rounded-lg border border-(--border) text-(--text-secondary) hover:text-(--text-primary) hover:bg-(--bg-elevated) transition-colors"
            >
              Clear filters
            </button>
          {/snippet}
        </EmptyState>
      {/if}
    </div>
    <Pagination state={pager} onchange={loadRows} itemsShown={rows.length} />
  {/if}
</div>
