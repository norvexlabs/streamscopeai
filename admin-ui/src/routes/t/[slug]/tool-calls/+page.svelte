<script lang="ts">
  import { oneOf, TOOL_CALL_OUTCOMES } from '#lib/filter-values.js';
  import { toast } from '#lib/toast.svelte.js';
  import { extractError } from '#lib/api-helpers.js';
  import { page } from '$app/state';
  import { goto } from '$app/navigation';
  import { thref } from '#lib/tenant.js';
  import type { PageProps } from './$types';

  let { params }: PageProps = $props();

  let slug = $derived(params.slug);
  import type { ToolCallRow, ToolCallKind } from '#lib/api-types.js';
  import type { components } from '#lib/generated/api-types.js';
  import { adminApi } from '#lib/api-client.js';
  import { daysToDateRange } from '#lib/formatters.js';
  import EmptyState from '#lib/components/EmptyState.svelte';
  import Skeleton from '#lib/components/Skeleton.svelte';
  import { consoleScope, workspaceIdsQuery, PERIOD_FILTER_KEYS, PERIOD_FILTER_DEFAULTS } from '#lib/scope.svelte.js';
  import { TOOLCALLS_FILTER_KEYS, type ToolCallsFilterKey } from '#lib/deeplinks.js';
  import { usePeriodicLoad, usePagination, UrlFilters, useAuditPeriod } from '#lib/hooks.svelte.js';
  import { useRefreshView } from '#lib/loadView.svelte.js';
  import PeriodSelector from '#lib/components/PeriodSelector.svelte';
  import Pagination from '#lib/components/Pagination.svelte';
  import UserEmailFilter from '#lib/components/UserEmailFilter.svelte';
  import WorkspaceFilter from '#lib/components/filter/WorkspaceFilter.svelte';
  import McpAuditDetail from '#lib/components/McpAuditDetail.svelte';
  import WebAuditDetail from '#lib/components/WebAuditDetail.svelte';
  import ToolCallRowCard from '#lib/components/tool-calls/ToolCallRowCard.svelte';
  import LlmToolInvocationDetail from '#lib/components/tool-calls/LlmToolInvocationDetail.svelte';
  import FilterField from '#lib/components/filter/FilterField.svelte';
  import TextInput from '#lib/components/forms/TextInput.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import { searchTooShort, MIN_SEARCH_CHARS } from '#lib/browse/search.js';
  import { m } from '#lib/paraglide/messages.js';

  // Unified row state — `kind`-discriminated. Each row carries either the
  // LLM invocation shape, the MCP audit shape, or the Web audit shape. The
  // card component branches on `row.kind`; expansion dispatches to the
  // matching detail component below.
  let calls = $state<ToolCallRow[]>([]);
  let loading = $state(true);
  // A refresh keeps what is shown, so an auto-refresh tick never blanks it;
  // a filter or page change shows the skeleton (`useRefreshView`).
  const view = useRefreshView(() => loading);
  let expandedId = $state<string | null>(null);
  // One-shot deep-link focus consumed at first load. The URL can carry either
  // `?request_id=…` (MCP / Web) or `?invocation_id=…` (LLM) — the resolver
  // tries both. After the initial expansion, subsequent loads ignore the
  // param so the operator can leave the focused row. The sync-back path lives
  // in `syncExpansionUrl()` below.
  let pendingFocusRid: string | null = page.url.searchParams.get('request_id');
  let pendingFocusInv: string | null = page.url.searchParams.get('invocation_id');
  /** The focus the page's last own load used — what a refresh keeps. */
  let focusedRid: string | null = null;
  let focusedInv: string | null = null;

  // `TOOLCALLS_FILTER_KEYS` (shared with the typed `toolCallsHref` deep-link
  // builder) is the single source of truth for this page's filter keys, plus the
  // period keys — so a deep-link can't carry a param the page silently drops.
  type FilterKey = ToolCallsFilterKey | (typeof PERIOD_FILTER_KEYS)[number];
  const filters = new UrlFilters<FilterKey>(
    [...TOOLCALLS_FILTER_KEYS, ...PERIOD_FILTER_KEYS],
    { kind: 'all', ...PERIOD_FILTER_DEFAULTS },
  );

  // Inline period + cross-view persistence: a URL-bound `<PeriodSelector>` whose
  // range (and the inline workspace filter) follows the operator across the
  // investigative views and stays shareable via the URL.
  const period = useAuditPeriod(filters, applyFilters);

  // MCP lookup tables for the Endpoint / Upstream dropdowns rendered under
  // `kind=mcp`. Loaded once at mount.
  type VirtualServerRow = components['schemas']['McpVirtualServerRow'];
  type UpstreamRow = components['schemas']['McpUpstreamServerRow'];
  let virtualServers = $state<VirtualServerRow[]>([]);
  let upstreamServers = $state<UpstreamRow[]>([]);
  let filterKind = $derived<ToolCallKind>(filters.values.kind as ToolCallKind);

  const pager = usePagination({ limit: 50 });

  /** Stable per-row key. LLM rows can share `request_id` across multiple
   *  invocations from one turn — `invocation_id` is the unique key. MCP and
   *  Web rows are one-call-per-row so `request_id` is unique. */
  function rowKey(row: ToolCallRow): string {
    return row.kind === 'llm' ? row.invocation_id : row.request_id;
  }

  usePeriodicLoad(async () => {
    try {
      const [vsRes, upRes] = await Promise.all([
        adminApi.GET('/api/v1/admin/mcp/virtual-servers', { params: { query: { limit: 200 } } }),
        adminApi.GET('/api/v1/admin/mcp/upstream-servers', { params: { query: { limit: 200 } } }),
      ]);
      virtualServers = vsRes.data?.items ?? [];
      upstreamServers = upRes.data?.items ?? [];
    } catch (e) {
      toast.error(extractError(e));
    }

    await loadCalls();
    filters.arm();
    filters.pushToUrl();
  }, (cause) => view.refresh(loadCalls, cause));

  // Monotonic load token: the workspace list loads async after mount, so the
  // initial (unfiltered) query and the corrective (default-filtered) re-fire
  // overlap. Drop any response a newer load has superseded.
  let loadGen = 0;
  async function loadCalls() {
    view.begin();
    loading = true;
    const gen = ++loadGen;
    const pv = period.value;
    const { start, end } = pv.kind === 'absolute'
      ? { start: pv.start, end: pv.end }
      : daysToDateRange(pv.days);
    // Deep-link focus skips the time window so a row outside the current
    // period still resolves. Consumed by the page's own load; a refresh keeps
    // the focus that load used, so a tick never swaps the focused row for the
    // whole list.
    const refreshing = view.refreshing;
    let focusRid = (refreshing ? focusedRid : pendingFocusRid) ?? undefined;
    const focusInv = (refreshing ? focusedInv : pendingFocusInv) ?? undefined;
    if (!refreshing) {
      focusedRid = pendingFocusRid;
      focusedInv = pendingFocusInv;
    }
    pendingFocusRid = null;
    pendingFocusInv = null;
    // `invocation_id` is `{request_id}:{the call's place in the turn}` — derive the turn's
    // request_id so the LLM-side helper narrows to that one turn (matches
    // the audit page's request_id-narrowing pattern). MCP/Web rows aren't
    // affected because their request_ids never use that compound shape.
    if (focusInv && !focusRid) {
      const colon = focusInv.indexOf(':');
      if (colon > 0) focusRid = focusInv.slice(0, colon);
    }
    const narrowed = focusRid || focusInv;

    const { data, error: err } = await adminApi.GET('/api/v1/admin/tool-calls', {
      params: { query: {
        kind: filterKind,
        user_email: filters.values.user_email || undefined,
        user_id: filters.values.user_id || undefined,
        ...workspaceIdsQuery(filters.values.workspace_ids, consoleScope.workspaces),
        app_id: filters.values.app_id || undefined,
        // A term too short to search is left out (the API refuses it): the
        // bar says why, and every other filter still applies.
        search: searchTooShort(filters.values.search) ? undefined : filters.values.search?.trim() || undefined,
        // Per-kind filters skipped on the wire under `kind=all` (operator
        // narrows by kind first, then refines — matches /audit semantics).
        tool_name: filterKind === 'llm' ? (filters.values.tool_name || undefined) : undefined,
        outcome: filterKind === 'llm' ? oneOf(TOOL_CALL_OUTCOMES, filters.values.outcome) : undefined,
        tool_id: filterKind === 'mcp' ? (filters.values.tool_id || undefined) : undefined,
        resource_uri: filterKind === 'mcp' ? (filters.values.resource_uri || undefined) : undefined,
        prompt_id: filterKind === 'mcp' ? (filters.values.prompt_id || undefined) : undefined,
        virtual_server_id: filterKind === 'mcp' ? (filters.values.virtual_server_id || undefined) : undefined,
        upstream_server_id: filterKind === 'mcp' ? (filters.values.upstream_server_id || undefined) : undefined,
        surface: filterKind === 'web' ? (filters.values.surface || undefined) : undefined,
        operation: filterKind === 'web' ? (filters.values.operation || undefined) : undefined,
        start: narrowed ? undefined : start,
        end: narrowed ? undefined : end,
        request_id: focusRid,
        limit: pager.limit,
        offset: pager.offset,
      } },
    });
    if (gen !== loadGen) return; // superseded by a newer load
    if (err) {
      toast.error(extractError(err));
    } else {
      let rows = pager.absorbOffset(data);

      // Risk filter is post-filtered client-side (the backend doesn't accept
      // `risk` as a query param). Pagination caveat: a 50-row page may
      // render <50 cards after the post-filter. The proper fix is
      // server-side risk evaluation; tracked separately.
      const risk = filterKind === 'llm' ? filters.values.risk : '';
      if (risk) {
        rows = rows.filter((r) => {
          if (r.kind !== 'llm') return false;
          if (risk === 'blocked') return r.outcomes.some((o) => o.startsWith('blocked_'));
          return r.risk_level === risk;
        });
      }
      calls = rows;

      // Deep-link auto-expand: try invocation_id first (LLM-side), then
      // request_id (MCP / Web). The endpoint already returned the matching
      // row when `request_id` was sent, so it's in `calls`. Once, on the load
      // that consumed the link — a refresh keeps the viewer's own expansion.
      if (!refreshing) {
        if (focusInv && calls.some((r) => r.kind === 'llm' && r.invocation_id === focusInv)) {
          expandedId = focusInv;
        } else if (focusRid && calls.some((r) => r.kind !== 'llm' && r.request_id === focusRid)) {
          expandedId = focusRid;
        }
      }
    }
    loading = false;
  }

  async function applyFilters() {
    pager.reset();
    await loadCalls();
  }

  async function clearFilters() {
    filters.clear();
    pager.reset();
    await loadCalls();
  }

  function handleFilterKeydown(e: KeyboardEvent) {
    if (e.key === 'Enter') applyFilters();
  }

  function toggleExpand(id: string, row: ToolCallRow) {
    expandedId = expandedId === id ? null : id;
    syncExpansionUrl(row);
  }

  /**
   * Mirror `expandedId` onto the URL so a copy-pasted URL deep-links back to
   * the open row. LLM rows use `?invocation_id=…` (the unique per-call key);
   * MCP / Web use `?request_id=…`. a replace (not a push) so back
   * doesn't walk through every row the operator opened.
   */
  function syncExpansionUrl(row: ToolCallRow) {
    const params = new URLSearchParams(page.url.search);
    params.delete('request_id');
    params.delete('invocation_id');
    if (expandedId) {
      if (row.kind === 'llm') {
        params.set('invocation_id', expandedId);
      } else {
        params.set('request_id', expandedId);
      }
    }
    const qs = params.toString();
    void goto(thref(slug, `/tool-calls${qs ? '?' + qs : ''}`), { replace: true, reset: false });
  }

  function filterByUser(email: string) {
    if (!email) return;
    filters.values.user_email = email;
    pager.reset();
    loadCalls();
  }
</script>

<div>
  <header class="flex items-end justify-between gap-4 pb-4 mb-6 border-b border-(--border)">
    <div>
      <h1 class="text-2xl font-semibold text-(--text-primary)">Tool Calls</h1>
      <p class="text-sm text-(--text-secondary) mt-1">
        Cross-protocol invocations: LLM tool calls, MCP
        <code class="font-mono text-xs">tools/call</code> /
        <code class="font-mono text-xs">resources/read</code> /
        <code class="font-mono text-xs">prompts/get</code>,
        and built-in Web <code class="font-mono text-xs">search</code> /
        <code class="font-mono text-xs">fetch</code>.
      </p>
    </div>
  </header>

  <!-- Filter Bar — Kind → Common → Kind-specific. The kind-specific block is
       hidden under `kind=all` so the operator narrows by kind first, then
       refines. Same layout as /audit. -->
  <div class="bg-(--bg-card) rounded-xl p-3 border border-(--border) mb-6">
    <div class="flex flex-wrap items-end gap-3">
      <!-- ── Kind (plain combo, matches App / Risk styling) ── -->
      <FilterField label="Kind" class="min-w-30">
        <SelectInput bind:value={filters.values.kind} onchange={applyFilters}>
          <option value="all">All</option>
          <option value="llm">LLM</option>
          <option value="mcp">MCP</option>
          <option value="web">Web</option>
        </SelectInput>
      </FilterField>

      <!-- ── Common (apply across every kind) ── -->
      <FilterField label="Search" class="flex-1 min-w-40">
        <TextInput
          bind:value={filters.values.search}
          onkeydown={handleFilterKeydown}
          placeholder="Search content (3+ characters)..."
        />
      </FilterField>
      <UserEmailFilter bind:value={filters.values.user_email} onfilter={applyFilters} />
      <WorkspaceFilter bind:value={filters.values.workspace_ids} onchange={applyFilters} />
      <div class="pb-px"><PeriodSelector selected={period.value} onchange={period.change} /></div>
      <FilterField label="App" class="min-w-27.5">
        <TextInput
          bind:value={filters.values.app_id}
          onkeydown={handleFilterKeydown}
          placeholder="App..."
        />
      </FilterField>

      <!-- ── LLM-specific (visible only when kind=llm) ── -->
      {#if filterKind === 'llm'}
        <FilterField label="Tool" class="min-w-35">
          <TextInput
            bind:value={filters.values.tool_name}
            onkeydown={handleFilterKeydown}
            placeholder="Tool name..."
            mono
          />
        </FilterField>
        <FilterField label="Risk" class="min-w-30">
          <SelectInput
            bind:value={filters.values.risk}
            onchange={applyFilters}
            title="Filter is applied to the currently fetched page (client-side). Deep pages with an active risk filter may render fewer than 50 cards."
          >
            <option value="">All risks</option>
            <option value="safe">Safe</option>
            <option value="caution">Caution</option>
            <option value="danger">Danger</option>
            <option value="unknown">Unknown</option>
            <option value="blocked">Blocked</option>
          </SelectInput>
        </FilterField>
        <FilterField label="Outcome" class="min-w-32.5">
          <SelectInput bind:value={filters.values.outcome} onchange={applyFilters}>
            <option value="">All outcomes</option>
            <option value="ok">OK</option>
            <option value="blocked">Blocked</option>
            <option value="redacted">Redacted</option>
            <option value="args_modified">Args modified</option>
            <option value="not_applied">Would block</option>
          </SelectInput>
        </FilterField>
      {/if}

      <!-- ── MCP-specific (visible only when kind=mcp) ── -->
      {#if filterKind === 'mcp'}
        <FilterField label="Tool ID" class="min-w-35">
          <TextInput
            bind:value={filters.values.tool_id}
            onkeydown={handleFilterKeydown}
            placeholder="tool_id..."
            mono
          />
        </FilterField>
        <FilterField label="Resource URI" class="min-w-40">
          <TextInput
            bind:value={filters.values.resource_uri}
            onkeydown={handleFilterKeydown}
            placeholder="resource://..."
            mono
          />
        </FilterField>
        <FilterField label="Prompt ID" class="min-w-35">
          <TextInput
            bind:value={filters.values.prompt_id}
            onkeydown={handleFilterKeydown}
            placeholder="prompt id..."
            mono
          />
        </FilterField>
        <FilterField label="Endpoint" class="min-w-40">
          <SelectInput bind:value={filters.values.virtual_server_id} onchange={applyFilters}>
            <option value="">All endpoints</option>
            {#each virtualServers as vs (vs.id)}
              <option value={vs.id}>{vs.slug}</option>
            {/each}
          </SelectInput>
        </FilterField>
        <FilterField label="Upstream" class="min-w-40">
          <SelectInput bind:value={filters.values.upstream_server_id} onchange={applyFilters}>
            <option value="">All upstreams</option>
            {#each upstreamServers as us (us.id)}
              <option value={us.id}>{us.name}</option>
            {/each}
          </SelectInput>
        </FilterField>
      {/if}

      <!-- ── Web-specific (visible only when kind=web) ── -->
      {#if filterKind === 'web'}
        <FilterField label="Surface" class="min-w-35">
          <SelectInput bind:value={filters.values.surface} onchange={applyFilters}>
            <option value="">All surfaces</option>
            <option value="mcp">MCP</option>
            <option value="substitution">Substitution</option>
            <option value="admin_test">Admin test</option>
          </SelectInput>
        </FilterField>
        <FilterField label="Operation" class="min-w-30">
          <SelectInput bind:value={filters.values.operation} onchange={applyFilters}>
            <option value="">All operations</option>
            <option value="search">Search</option>
            <option value="fetch">Fetch</option>
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
  {#if searchTooShort(filters.values.search)}
    <p class="-mt-3 mb-6 text-xs text-(--warning)">{m.browse_search_too_short({ min: MIN_SEARCH_CHARS })}</p>
  {/if}

  <!-- Card list -->
  {#if view.skeleton}
    <div class="bg-(--bg-card) rounded-xl border border-(--border) p-4">
      <Skeleton variant="row" count={10} height="2.75rem" />
    </div>
  {:else}
    <div class="bg-(--bg-card) rounded-xl border border-(--border) overflow-hidden">
      {#each calls as row (rowKey(row))}
        {@const key = rowKey(row)}
        <ToolCallRowCard
          {row}
          expanded={expandedId === key}
          onToggle={() => toggleExpand(key, row)}
          onFilterUser={filterByUser}
          showKindChip={filterKind === 'all'}
        />
        {#if expandedId === key}
          <div class="bg-(--bg-elevated) px-5 py-4">
            {#if row.kind === 'llm'}
              <LlmToolInvocationDetail item={row} />
            {:else if row.kind === 'mcp'}
              <McpAuditDetail row={row} onfilteruser={filterByUser} hideFeedLink />
            {:else}
              <WebAuditDetail row={row} onfilteruser={filterByUser} />
            {/if}
          </div>
        {/if}
      {/each}
      {#if calls.length === 0}
        <EmptyState
          title="No tool calls match these filters"
          body="Loosen the time window or clear filters above. If you're deep-linked to a specific request, the row may sit in a partition outside the current scan."
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
    <Pagination state={pager} onchange={loadCalls} itemsShown={calls.length} />
  {/if}
</div>
