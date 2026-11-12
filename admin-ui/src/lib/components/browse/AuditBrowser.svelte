<script lang="ts">
  // The audit log, on both planes: the console's Audit page and the portal's
  // Requests page render this one component; `plane` (`#lib/browse/planes.js`)
  // is the only thing that differs — which API answers, the scope controls
  // (console: user + workspaces; portal: Me/Team + a teammate in a team view),
  // and the period default. Every kind (LLM, MCP, A2A, web) lists as one card
  // per row and expands into its detail component.
  //
  // `request_id` in the URL focuses one row: the list narrows to it, skips the
  // window (the row may be older), and expands it. The focus is sticky until
  // the viewer leaves it — collapsing the row, opening another, or changing a
  // filter — so a reload right after mount cannot strand them on an unfiltered
  // list.
  import { page } from '$app/state';
  import { goto } from '$app/navigation';
  import type { AuditLogRow, AuditKind } from '#lib/api-types.js';
  import type { AuditFilterQuery, AuditOptions, BrowsePlane } from '#lib/browse/planes.js';
  import { extractError } from '#lib/api-helpers.js';
  import { toast } from '#lib/toast.svelte.js';
  import { scopeHref } from '#lib/tenant.js';
  import { daysToDateRange } from '#lib/formatters.js';
  import { FINISH_REASONS, ERROR_CATEGORIES, A2A_METHODS, A2A_TASK_STATES } from '#lib/constants.js';
  import { PERIOD_FILTER_KEYS, portalWorkspaceName } from '#lib/scope.svelte.js';
  import { usePeriodicLoad, usePagination, UrlFilters, useAuditPeriod } from '#lib/hooks.svelte.js';
  import { useRefreshView } from '#lib/loadView.svelte.js';
  import { setPortalWorkspace, setSelfScoped } from '#lib/selfScoped.js';
  import { searchTooShort, MIN_SEARCH_CHARS } from '#lib/browse/search.js';
  import { pageHidden } from '#lib/portalPages.svelte.js';
  import Page from '#lib/components/page/Page.svelte';
  import EmptyState from '#lib/components/EmptyState.svelte';
  import Skeleton from '#lib/components/Skeleton.svelte';
  import PeriodSelector from '#lib/components/PeriodSelector.svelte';
  import Pagination from '#lib/components/Pagination.svelte';
  import McpAuditDetail from '#lib/components/McpAuditDetail.svelte';
  import A2aAuditDetail from '#lib/components/A2aAuditDetail.svelte';
  import WebAuditDetail from '#lib/components/WebAuditDetail.svelte';
  import LlmAuditDetail from '#lib/components/LlmAuditDetail.svelte';
  import AuditRowCard from '#lib/components/audit/AuditRowCard.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import FilterBar from '#lib/components/filter/FilterBar.svelte';
  import FilterField from '#lib/components/filter/FilterField.svelte';
  import TextInput from '#lib/components/forms/TextInput.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import ScopeFilters from '#lib/components/browse/ScopeFilters.svelte';
  import DiffPanel, { type DiffDetail } from '#lib/components/browse/DiffPanel.svelte';
  import { m } from '#lib/paraglide/messages.js';

  interface Props {
    plane: BrowsePlane;
    /** The heading, given the name of the team being viewed (portal only). */
    heading: (team: string | undefined) => { title: string; subtitle: string };
  }

  let { plane, heading }: Props = $props();

  // The plane is fixed for the component's life: the console and the portal
  // are different routes.
  // svelte-ignore state_referenced_locally
  const p = plane;
  if (p.portal) setSelfScoped(true);

  const slug = $derived(page.params.slug ?? '');

  let logs = $state<AuditLogRow[]>([]);
  let options = $state<AuditOptions>({
    apps: new Map(),
    virtualServers: [],
    upstreamServers: [],
    a2aAgents: [],
    qosClassNames: new Map(),
  });
  let loading = $state(true);
  // A refresh keeps what is shown, so a refresh never blanks it; a filter or
  // page change shows the skeleton (`useRefreshView`).
  const view = useRefreshView(() => loading);
  let expandedId = $state<string | null>(null);
  let focusedRid = $state<string | null>(page.url.searchParams.get('request_id'));
  let diff = $state<DiffDetail | null>(null);

  // `kind: 'all'` is the default; the helper omits defaults from the URL.
  // `request_id` stays OUTSIDE the filters: it is the expanded row (selection
  // state), synced by hand in `syncExpansionUrl`.
  const filters = new UrlFilters<string>([...p.auditKeys, ...PERIOD_FILTER_KEYS], { kind: 'all', ...p.periodDefaults });
  const period = useAuditPeriod(filters, applyFilters, { persist: p.persistPeriod });
  const filterKind = $derived<AuditKind>(filters.values.kind as AuditKind);

  // The workspace being viewed (portal): every detail a row opens is read in it.
  setPortalWorkspace(() => filters.values.workspace_id || undefined);
  const team = $derived(p.portal ? portalWorkspaceName(filters.values.workspace_id || undefined) : undefined);
  const head = $derived(heading(team));
  const scope = $derived<Record<string, string>>(Object.fromEntries(p.scopeKeys.map((k) => [k, filters.values[k] ?? ''])));
  const userFilter = $derived(p.filtersByUser(scope));

  // Conversation content is hidden for the viewer's workspaces (portal): the
  // gateway answers each row with its metadata only and refuses its detail,
  // so a row does not open, and the search and the filters on what is
  // withheld — which the gateway would ignore — are not offered.
  const contentHidden = $derived(pageHidden('sessions', page.data));
  $effect(() => {
    if (contentHidden) expandedId = null;
  });

  const pager = usePagination({ limit: 50 });
  const shortSearch = $derived(!contentHidden && searchTooShort(filters.values.search));

  usePeriodicLoad(async () => {
    try {
      options = await p.auditOptions();
    } catch (e) {
      toast.error(extractError(e));
    }
    await loadLogs();
    // Arm URL → state sync only after the first load, so the seed from the
    // URL does not re-write a redundant URL.
    filters.arm();
    filters.pushToUrl();
  }, (cause) => view.refresh(loadLogs, cause));

  /** A per-kind filter is sent only under its kind: under `all` it is hidden
   *  in the bar and skipped on the wire. */
  function when(kinds: AuditKind[], v: string | undefined): string | undefined {
    return kinds.includes(filterKind) && v ? v : undefined;
  }

  function query(): AuditFilterQuery {
    const v = filters.values;
    const pv = period.value;
    const { start, end } = pv.kind === 'absolute' ? { start: pv.start, end: pv.end } : daysToDateRange(pv.days);
    // A deep-linked request (or an MCP token, console) is found whatever its
    // age: the window is skipped.
    const narrowed = !!focusedRid || !!v.jti;
    return {
      kind: filterKind,
      model: when(['llm'], v.model),
      finish_reason: when(['llm'], v.finish_reason),
      upstream_server: when(['llm'], v.upstream_server),
      api_version: when(['llm'], v.api_version),
      media_type: contentHidden ? undefined : when(['llm'], v.media_type),
      // A policy refusal is badged on an LLM row (a suppressed tool call) and on
      // an A2A row (a refused agent call).
      has_blocked: (filterKind === 'llm' || filterKind === 'a2a') && v.has_blocked === 'true' ? true : undefined,
      // Cross-kind: a gateway column, or a badge on several arms.
      error_category: v.error_category || undefined,
      has_guardrail: v.has_guardrail === 'true' ? true : undefined,
      app_id: v.app_id || undefined,
      surface: when(['web'], v.surface),
      operation: when(['web'], v.operation),
      tool_id: when(['mcp'], v.tool_id),
      resource_uri: contentHidden ? undefined : when(['mcp'], v.resource_uri),
      prompt_id: when(['mcp'], v.prompt_id),
      virtual_server_id: when(['mcp'], v.virtual_server_id),
      upstream_server_id: when(['mcp'], v.upstream_server_id),
      agent_slug: when(['a2a'], v.agent_slug),
      task_state: when(['a2a'], v.task_state),
      methods: when(['a2a'], v.methods),
      start: narrowed ? undefined : start,
      end: narrowed ? undefined : end,
      // A term too short to search is left out (the API refuses it): the bar
      // says why, and every other filter still applies.
      search: shortSearch || contentHidden ? undefined : v.search?.trim() || undefined,
      request_id: focusedRid ?? undefined,
      limit: pager.limit,
      offset: pager.offset,
    };
  }

  // Monotonic load token: only the latest load writes.
  let loadGen = 0;
  async function loadLogs() {
    view.begin();
    loading = true;
    const gen = ++loadGen;
    try {
      const { data, error: err } = await p.listAudit(query(), scope);
      if (gen !== loadGen) return;
      if (err) {
        toast.error(extractError(err));
        // A failed refresh keeps the list it showed.
        if (!view.refreshing) { logs = []; }
      } else {
        logs = pager.absorbOffset(data);
        // A deep link selecting one row lands with it open.
        if (focusedRid && logs.length > 0 && !view.refreshing && !contentHidden) expandedId = focusedRid;
      }
    } catch (e) {
      toast.error(extractError(e));
      if (gen === loadGen && !view.refreshing) { logs = []; }
    } finally {
      if (gen === loadGen) loading = false;
    }
  }

  function handleFilterKeydown(e: KeyboardEvent) {
    if (e.key === 'Enter') void applyFilters();
  }

  /** Releasing the deep-link focus re-syncs the URL, so a refresh cannot
   *  re-seed it from a stale `request_id`. */
  function releaseFocus() {
    const wasFocused = focusedRid !== null;
    focusedRid = null;
    if (wasFocused) syncExpansionUrl();
  }

  async function applyFilters() {
    releaseFocus();
    pager.reset();
    await loadLogs();
  }

  async function clearFilters() {
    // The portal's Me/Team choice is not a filter: it stays.
    const keep: Record<string, string> = p.portal ? { workspace_id: filters.values.workspace_id ?? '' } : {};
    filters.clear();
    filters.values = { ...filters.values, ...keep };
    focusedRid = null;
    expandedId = null;
    syncExpansionUrl();
    pager.reset();
    await loadLogs();
  }

  function toggleExpand(id: string) {
    expandedId = expandedId === id ? null : id;
    // Leaving the deep-linked row releases its narrowing: the full list loads.
    const released = focusedRid !== null && expandedId !== focusedRid;
    if (released) focusedRid = null;
    syncExpansionUrl();
    if (released) {
      pager.reset();
      void loadLogs();
    }
  }

  /** Mirror the open row onto the URL (`?request_id=`), replacing the entry so
   *  Back does not walk every row opened. Keeps every other key. */
  function syncExpansionUrl() {
    const params = new URLSearchParams(page.url.search);
    if (expandedId) params.set('request_id', expandedId);
    else params.delete('request_id');
    const qs = params.toString();
    void goto(scopeHref(slug, page.url.pathname, `/audit${qs ? '?' + qs : ''}`), { replace: true, reset: false });
  }

  function filterByUser(email: string) {
    filters.values.user_email = email;
    void applyFilters();
  }

  /** Me/Team changed — by the viewer, or following the header. A focused
   *  request stays focused: it is read in the new scope. */
  function changeTeam(id: string | undefined) {
    filters.values = { ...filters.values, workspace_id: id ?? '', user_email: '' };
    pager.reset();
    void loadLogs();
  }
</script>

<Page title={head.title} subtitle={head.subtitle}>
  <!-- Kind → common filters → the selected kind's own filters → Clear. A
       kind's own filters are hidden under `all`: narrow by kind first. -->
  <FilterBar>
    <FilterField label={m.browse_filter_kind()} class="min-w-30">
      <SelectInput bind:value={filters.values.kind} onchange={applyFilters}>
        <option value="all">{m.browse_kind_all()}</option>
        <option value="llm">LLM</option>
        <option value="mcp">MCP</option>
        <option value="a2a">A2A</option>
        <option value="web">{m.browse_kind_web()}</option>
      </SelectInput>
    </FilterField>
    {#if !contentHidden}
      <FilterField label={m.browse_filter_search()} class="flex-1 min-w-40">
        <TextInput bind:value={filters.values.search} onkeydown={handleFilterKeydown} placeholder={m.browse_search_placeholder()} />
      </FilterField>
    {/if}
    <ScopeFilters {plane} {filters} {userFilter} onchange={applyFilters} onteam={changeTeam} />
    <div class="pb-px"><PeriodSelector selected={period.value} onchange={period.change} /></div>
    <FilterField label={m.browse_filter_app()} class="min-w-27.5">
      <TextInput bind:value={filters.values.app_id} onkeydown={handleFilterKeydown} placeholder={m.browse_filter_app_placeholder()} />
    </FilterField>
    <!-- A gateway column: narrows every arm of the interleaved view. -->
    <FilterField label={m.browse_filter_error()} class="min-w-32.5">
      <SelectInput bind:value={filters.values.error_category} onchange={applyFilters}>
        <option value="">{m.browse_filter_error_none()}</option>
        <option value="_any">{m.browse_filter_error_any()}</option>
        {#each ERROR_CATEGORIES as cat (cat.value)}
          <option value={cat.value}>{cat.label()}</option>
        {/each}
      </SelectInput>
    </FilterField>
    <!-- A badge on the LLM, web and A2A arms: findings and scans that could
         not cover the content. -->
    <FilterField label={m.browse_filter_guardrail()} class="min-w-32.5">
      <SelectInput bind:value={filters.values.has_guardrail} onchange={applyFilters}>
        <option value="">{m.browse_all()}</option>
        <option value="true">{m.browse_filter_guardrail_flagged()}</option>
      </SelectInput>
    </FilterField>

    {#if filterKind === 'llm'}
      <FilterField label={m.browse_filter_model()} class="min-w-30">
        <TextInput bind:value={filters.values.model} onkeydown={handleFilterKeydown} placeholder={m.browse_filter_model_placeholder()} />
      </FilterField>
      <FilterField label={m.browse_filter_result()} class="min-w-30">
        <SelectInput bind:value={filters.values.finish_reason} onchange={applyFilters}>
          <option value="">{m.browse_all()}</option>
          {#each FINISH_REASONS as reason (reason.value)}
            <option value={reason.value}>{reason.label()}</option>
          {/each}
        </SelectInput>
      </FilterField>
      <FilterField label={m.browse_filter_upstream()} class="min-w-35">
        <TextInput bind:value={filters.values.upstream_server} onkeydown={handleFilterKeydown} placeholder={m.browse_filter_upstream_placeholder()} mono />
      </FilterField>
      <FilterField label={m.browse_filter_protocol()} class="min-w-35">
        <SelectInput bind:value={filters.values.api_version} onchange={applyFilters}>
          <option value="">{m.browse_filter_protocol_all()}</option>
          <option value="chat_completions">Chat Completions</option>
          <option value="responses">Responses</option>
          <option value="anthropic_messages">Anthropic Messages</option>
          <option value="google_gemini">Google Gemini</option>
        </SelectInput>
      </FilterField>
      {#if !contentHidden}
        <FilterField label={m.browse_filter_media()} class="min-w-32.5">
          <SelectInput bind:value={filters.values.media_type} onchange={applyFilters}>
            <option value="">{m.browse_all()}</option>
            <option value="_any">{m.browse_filter_media_any()}</option>
            <option value="image">{m.browse_filter_media_image()}</option>
            <option value="audio">{m.browse_filter_media_audio()}</option>
            <option value="embedding">{m.browse_filter_media_embedding()}</option>
            <option value="video">{m.browse_filter_media_video()}</option>
          </SelectInput>
        </FilterField>
      {/if}
      <FilterField label={m.browse_filter_blocked_tools()} class="min-w-32.5">
        <SelectInput bind:value={filters.values.has_blocked} onchange={applyFilters}>
          <option value="">{m.browse_all()}</option>
          <option value="true">{m.browse_filter_blocked_only()}</option>
        </SelectInput>
      </FilterField>
    {/if}

    {#if filterKind === 'web'}
      <FilterField label={m.browse_filter_operation()} class="min-w-30">
        <SelectInput bind:value={filters.values.operation} onchange={applyFilters}>
          <option value="">{m.browse_all()}</option>
          <option value="search">{m.browse_filter_web_search()}</option>
          <option value="fetch">{m.browse_filter_web_fetch()}</option>
        </SelectInput>
      </FilterField>
      <FilterField label={m.browse_filter_surface()} class="min-w-32.5">
        <SelectInput bind:value={filters.values.surface} onchange={applyFilters}>
          <option value="">{m.browse_all()}</option>
          <option value="mcp">MCP (/mcp/web)</option>
          <option value="substitution">{m.browse_filter_surface_substitution()}</option>
          <option value="admin_test">{m.browse_filter_surface_admin_test()}</option>
        </SelectInput>
      </FilterField>
    {/if}

    {#if filterKind === 'a2a'}
      <FilterField label={m.browse_filter_agent()} class="min-w-40">
        <SelectInput bind:value={filters.values.agent_slug} onchange={applyFilters}>
          <option value="">{m.browse_filter_agent_all()}</option>
          {#each options.a2aAgents as agent (agent.id)}
            <option value={agent.id}>{agent.name}</option>
          {/each}
        </SelectInput>
      </FilterField>
      <FilterField label={m.browse_filter_operation()} class="min-w-42.5">
        <SelectInput bind:value={filters.values.methods} onchange={applyFilters}>
          <option value="">{m.browse_filter_operation_all()}</option>
          {#each A2A_METHODS as method (method)}
            <option value={method}>{method}</option>
          {/each}
        </SelectInput>
      </FilterField>
      <FilterField label={m.browse_filter_task_state()} class="min-w-37.5">
        <SelectInput bind:value={filters.values.task_state} onchange={applyFilters}>
          <option value="">{m.browse_filter_task_state_all()}</option>
          {#each A2A_TASK_STATES as st (st.value)}
            <option value={st.value}>{st.label()}</option>
          {/each}
        </SelectInput>
      </FilterField>
      <FilterField label={m.browse_filter_blocked()} class="min-w-32.5">
        <SelectInput bind:value={filters.values.has_blocked} onchange={applyFilters}>
          <option value="">{m.browse_all()}</option>
          <option value="true">{m.browse_filter_blocked_only()}</option>
        </SelectInput>
      </FilterField>
    {/if}

    {#if filterKind === 'mcp'}
      <FilterField label={m.browse_filter_tool_id()} class="min-w-35">
        <TextInput bind:value={filters.values.tool_id} onkeydown={handleFilterKeydown} placeholder="tool_id..." mono />
      </FilterField>
      {#if !contentHidden}
        <FilterField label={m.browse_filter_resource_uri()} class="min-w-40">
          <TextInput bind:value={filters.values.resource_uri} onkeydown={handleFilterKeydown} placeholder="resource://..." mono />
        </FilterField>
      {/if}
      <FilterField label={m.browse_filter_prompt_id()} class="min-w-35">
        <TextInput bind:value={filters.values.prompt_id} onkeydown={handleFilterKeydown} placeholder={m.browse_filter_prompt_id_placeholder()} mono />
      </FilterField>
      <FilterField label={m.browse_filter_endpoint()} class="min-w-40">
        <SelectInput bind:value={filters.values.virtual_server_id} onchange={applyFilters}>
          <option value="">{m.browse_filter_endpoint_all()}</option>
          {#each options.virtualServers as vs (vs.id)}
            <option value={vs.id}>{vs.name}</option>
          {/each}
        </SelectInput>
      </FilterField>
      <FilterField label={m.browse_filter_upstream()} class="min-w-40">
        <SelectInput bind:value={filters.values.upstream_server_id} onchange={applyFilters}>
          <option value="">{m.browse_filter_upstream_all()}</option>
          {#each options.upstreamServers as us (us.id)}
            <option value={us.id}>{us.name}</option>
          {/each}
        </SelectInput>
      </FilterField>
    {/if}

    <button
      onclick={clearFilters}
      class="px-3 py-1.5 border border-(--border) rounded-lg text-(--text-secondary) text-sm hover:text-(--text-primary) transition-colors"
    >
      {m.browse_clear()}
    </button>
  </FilterBar>
  {#if shortSearch}
    <p class="-mt-3 text-xs text-(--warning)">{m.browse_search_too_short({ min: MIN_SEARCH_CHARS })}</p>
  {/if}
  {#if contentHidden}
    <p class="-mt-3 text-xs text-(--text-secondary)" data-testid="content-hidden-note">{m.browse_content_hidden()}</p>
  {/if}

  {#if view.skeleton}
    <div class="bg-(--bg-card) rounded-xl border border-(--border) p-4">
      <Skeleton variant="row" count={10} height="2.75rem" />
    </div>
  {:else}
    {#if focusedRid}
      <div class="flex items-center gap-2 px-3 py-2 rounded-lg bg-(--accent)/10 border border-(--accent)/30 text-sm">
        <Icon name="filtered" size="sm" tone="info" />
        <span class="text-(--text-primary)">{m.browse_focus_one()}</span>
        <span class="font-mono text-xs text-(--text-secondary)">{focusedRid}</span>
        <button
          type="button"
          class="ml-auto text-xs font-medium text-(--accent) hover:underline"
          onclick={() => { focusedRid = null; expandedId = null; syncExpansionUrl(); void loadLogs(); }}
        >{m.browse_focus_clear()}</button>
      </div>
    {/if}
    <!-- One card per row, every kind; the kind chip only when kinds mix. -->
    <div class="bg-(--bg-card) rounded-xl border border-(--border) overflow-hidden">
      {#each logs as row (row.request_id)}
        <AuditRowCard
          {row}
          expanded={expandedId === row.request_id}
          onToggle={contentHidden ? undefined : () => toggleExpand(row.request_id)}
          onFilterUser={userFilter ? filterByUser : undefined}
          showKindChip={filterKind === 'all'}
        />
        {#if expandedId === row.request_id && !contentHidden}
          <div class="bg-(--bg-elevated) px-5 py-4">
            {#if row.kind === 'mcp'}
              <McpAuditDetail {row} onfilteruser={userFilter ? filterByUser : undefined} />
            {:else if row.kind === 'a2a'}
              <A2aAuditDetail {row} onfilteruser={userFilter ? filterByUser : undefined} />
            {:else if row.kind === 'web'}
              <WebAuditDetail {row} onfilteruser={userFilter ? filterByUser : undefined} />
            {:else}
              <LlmAuditDetail {row} appRegistry={options.apps} qosClassNames={options.qosClassNames} ondiff={(d) => (diff = d)} />
            {/if}
          </div>
        {/if}
      {/each}
      <!-- A cut search found nothing yet: the notice below says why. -->
      {#if logs.length === 0 && !pager.scanCut}
        <EmptyState title={m.browse_audit_empty_title()} body={m.browse_audit_empty_body()}>
          {#snippet action()}
            <button
              onclick={clearFilters}
              class="px-4 py-1.5 text-sm rounded-lg border border-(--border) text-(--text-secondary) hover:text-(--text-primary) hover:bg-(--bg-elevated) transition-colors"
            >
              {m.browse_clear_filters()}
            </button>
          {/snippet}
        </EmptyState>
      {/if}
    </div>
    <Pagination state={pager} onchange={loadLogs} itemsShown={logs.length} />
  {/if}
</Page>

<DiffPanel {diff} onclose={() => (diff = null)} />
