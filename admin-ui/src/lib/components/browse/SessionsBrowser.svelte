<script lang="ts">
  // The session list, on both planes: the console's Sessions page and the
  // portal's. `plane` (`#lib/browse/planes.js`) decides which API answers, the
  // scope controls and the period default. Expert alerts reach a portal member
  // only where the profile of each session's workspace shows them — the
  // server masks them, and the alert filter matches only what it shows.
  //
  // The list is a tree (`#lib/browse/sessionTree.js`): its rows are the top
  // level, and a row's sub-agents badge loads them under it. A search, or a
  // Linked choice, lists flat — each sub-agent then carries its parent chip.
  import type { SessionSummary } from '#lib/api-types.js';
  import type { BrowsePlane, SessionFilterQuery } from '#lib/browse/planes.js';
  import { ALERT_LEVELS, LINKAGE_CHOICES, oneOf } from '#lib/filter-values.js';
  import { canExpand, EXPAND_LIMIT, listLinkage, nests, unlisted } from '#lib/browse/sessionTree.js';
  import { page } from '$app/state';
  import { toast } from '#lib/toast.svelte.js';
  import { extractError } from '#lib/api-helpers.js';
  import { daysToDateRange, appName } from '#lib/formatters.js';
  import { PERIOD_FILTER_KEYS, portalWorkspaceName } from '#lib/scope.svelte.js';
  import { usePeriodicLoad, usePagination, UrlFilters, useAuditPeriod } from '#lib/hooks.svelte.js';
  import { useRefreshView } from '#lib/loadView.svelte.js';
  import { sessionHref, setPortalWorkspace } from '#lib/selfScoped.js';
  import { searchTooShort, MIN_SEARCH_CHARS } from '#lib/browse/search.js';
  import Page from '#lib/components/page/Page.svelte';
  import PeriodSelector from '#lib/components/PeriodSelector.svelte';
  import SessionRow from '#lib/components/SessionRow.svelte';
  import EmptyState from '#lib/components/EmptyState.svelte';
  import Skeleton from '#lib/components/Skeleton.svelte';
  import Pagination from '#lib/components/Pagination.svelte';
  import FilterBar from '#lib/components/filter/FilterBar.svelte';
  import FilterField from '#lib/components/filter/FilterField.svelte';
  import TextInput from '#lib/components/forms/TextInput.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import ScopeFilters from '#lib/components/browse/ScopeFilters.svelte';
  import BadgePicker from '#lib/components/filter/BadgePicker.svelte';
  import { offeredBadgeFilter } from '#lib/badges.js';
  import { FIGURE_SORT_MAX_DAYS, figureSortFits } from '#lib/browse/sort.js';
  import { m } from '#lib/paraglide/messages.js';

  interface Props {
    plane: BrowsePlane;
    /** The heading, given the name of the team being viewed (portal only). */
    heading: (team: string | undefined) => { title: string; subtitle: string };
  }

  let { plane, heading }: Props = $props();

  // The plane is fixed for the component's life.
  // svelte-ignore state_referenced_locally
  const p = plane;

  let sessions = $state<SessionSummary[]>([]);
  // Whether the rows shown are a tree's top level, as the last load asked.
  let nested = $state(false);
  /** A row's sub-agents, once its badge was opened: `null` while they load. */
  let expanded = $state<Record<string, SessionSummary[] | null>>({});
  let apps = $state<Map<string, { name?: string }>>(new Map());
  let loading = $state(true);
  // A refresh keeps what is shown; a filter or page change shows the skeleton.
  const view = useRefreshView(() => loading);

  const filters = new UrlFilters<string>([...p.sessionKeys, ...PERIOD_FILTER_KEYS], { ...p.periodDefaults });
  const period = useAuditPeriod(filters, applyFilters, { persist: p.persistPeriod });
  const pager = usePagination({ limit: 50 });
  const shortSearch = $derived(searchTooShort(filters.values.search));
  const searching = $derived(!shortSearch && !!filters.values.search?.trim());

  // A search pages its matches by time: under a term only `newest` and
  // `oldest` are sent (the server refuses a rank with one).
  const SORTS = ['oldest', 'alerts', 'turns', 'cost', 'tokens'] as const;
  type Sort = (typeof SORTS)[number];
  const sortLabel: Record<Sort, () => string> = {
    oldest: m.browse_sort_oldest,
    alerts: m.browse_sort_alerts,
    turns: m.browse_sort_turns,
    cost: m.browse_sort_cost,
    tokens: m.browse_sort_tokens,
  };
  // A figure sorts every session of the window: offered only over a window
  // the server serves it on.
  const FIGURES: readonly Sort[] = ['turns', 'cost', 'tokens'];
  const sortWindow = $derived(figureSortFits(period.value));
  const unservable = (sort: Sort) => (searching && sort !== 'oldest') || (!sortWindow && FIGURES.includes(sort));
  const sortSent = $derived.by(() => {
    const v = oneOf(SORTS, filters.values.sort);
    return v && !unservable(v) ? v : undefined;
  });
  /** The badge codes the list sends: those the picker shows ticked (a
   *  session's codes are its LLM turns'). */
  const badgesSent = $derived(offeredBadgeFilter(filters.values.badges, ['llm']).join(','));

  // Each row opens in the workspace being viewed (portal).
  setPortalWorkspace(() => filters.values.workspace_id || undefined);
  const team = $derived(p.portal ? portalWorkspaceName(filters.values.workspace_id || undefined) : undefined);
  const head = $derived(heading(team));
  const scope = $derived<Record<string, string>>(Object.fromEntries(p.scopeKeys.map((k) => [k, filters.values[k] ?? ''])));
  const userFilter = $derived(p.filtersByUser(scope));

  usePeriodicLoad(async () => {
    try {
      apps = await p.apps();
    } catch (e) {
      toast.error(extractError(e));
    }
    await loadSessions();
    filters.arm();
    filters.pushToUrl();
  }, (cause) => view.refresh(loadSessions, cause));

  function query(): SessionFilterQuery {
    const v = filters.values;
    const pv = period.value;
    const { start, end } = pv.kind === 'absolute' ? { start: pv.start, end: pv.end } : daysToDateRange(pv.days);
    const alertLevel = oneOf(ALERT_LEVELS, v.alert_level);
    return {
      app_id: v.app_id || undefined,
      model: v.model || undefined,
      // A term too short to search is left out (the API refuses it): the bar
      // says why, and every other filter still applies.
      search: shortSearch ? undefined : v.search?.trim() || undefined,
      start,
      end,
      alert_level: alertLevel,
      badges: badgesSent || undefined,
      sort: sortSent,
      linked: listLinkage(oneOf(LINKAGE_CHOICES, v.linked), shortSearch ? undefined : v.search?.trim() || undefined, alertLevel),
      limit: pager.limit,
      offset: pager.offset,
    };
  }

  // Monotonic load token: only the latest load writes.
  let loadGen = 0;
  async function loadSessions() {
    view.begin();
    loading = true;
    const gen = ++loadGen;
    try {
      const q = query();
      const { data, error: err } = await p.listSessions(q, scope);
      if (gen !== loadGen) return;
      nested = nests(q.linked);
      if (err) {
        toast.error(extractError(err));
        // A failed refresh keeps the list it showed.
        if (!view.refreshing) { sessions = []; }
      } else {
        sessions = pager.absorbOffset(data);
        // A refresh keeps what is open and still shown, read again; a flat
        // list shows nothing under a row.
        expanded = nested ? shownOpen() : {};
        for (const id of Object.keys(expanded)) void loadChildren(id);
      }
    } catch (e) {
      toast.error(extractError(e));
      if (gen === loadGen && !view.refreshing) { sessions = []; }
    } finally {
      if (gen === loadGen) loading = false;
    }
  }

  /** A session row's badge chip: list the sessions carrying that badge. */
  function filterByBadge(code: string) {
    filters.values.badges = code;
    void applyFilters();
  }

  function handleFilterKeydown(e: KeyboardEvent) {
    if (e.key === 'Enter') void applyFilters();
  }

  async function applyFilters() {
    pager.reset();
    await changeList();
  }

  // A new set of rows (filters, page): what was opened belonged to the old one.
  // A refresh keeps it.
  async function changeList() {
    expanded = {};
    await loadSessions();
  }

  /** The open rows still on the list: a row of the page, or a sub-agent shown
   *  under an open row that is. */
  function shownOpen(): Record<string, SessionSummary[] | null> {
    const kept: Record<string, SessionSummary[] | null> = {};
    const visit = (rows: SessionSummary[]) => {
      for (const row of rows) {
        const id = row.session_id;
        if (!(id in expanded) || id in kept) continue;
        kept[id] = expanded[id];
        visit(expanded[id] ?? []);
      }
    };
    visit(sessions);
    return kept;
  }

  // The latest read of each open row: an older answer arriving after a newer
  // read started (a refresh, a close and reopen) is dropped.
  const childGen: Record<string, number> = {};

  async function toggle(session: SessionSummary) {
    const id = session.session_id;
    if (id in expanded) {
      // Closing a row closes what was open under it.
      const closed = new Set<string>();
      const close = (rowId: string) => {
        if (closed.has(rowId) || !(rowId in expanded)) return;
        closed.add(rowId);
        for (const child of expanded[rowId] ?? []) close(child.session_id);
      };
      close(id);
      expanded = Object.fromEntries(Object.entries(expanded).filter(([k]) => !closed.has(k)));
      return;
    }
    expanded = { ...expanded, [id]: null };
    await loadChildren(id);
  }

  /** Read the sub-agents of an open row; a row closed meanwhile stays closed.
   *  A failed read closes a row that was opening, and keeps what a row already
   *  showed (a refresh), as the list does. */
  async function loadChildren(id: string) {
    const gen = (childGen[id] = (childGen[id] ?? 0) + 1);
    let failure: unknown;
    try {
      const { data, error: err } = await p.linked(id, filters.values.workspace_id || undefined, {
        kind: 'sub_agent',
        limit: EXPAND_LIMIT,
      });
      if (gen !== childGen[id] || !(id in expanded)) return; // superseded, or closed meanwhile
      if (!err) {
        expanded = { ...expanded, [id]: data?.children ?? [] };
        return;
      }
      failure = err;
    } catch (e) {
      failure = e;
    }
    if (gen !== childGen[id] || !(id in expanded) || expanded[id] !== null) return;
    toast.error(extractError(failure));
    const { [id]: _failed, ...rest } = expanded;
    expanded = rest;
  }

  async function clearFilters() {
    // The portal's Me/Team choice is not a filter: it stays.
    const keep: Record<string, string> = p.portal ? { workspace_id: filters.values.workspace_id ?? '' } : {};
    filters.clear();
    filters.values = { ...filters.values, ...keep };
    await applyFilters();
  }

  function changeTeam(id: string | undefined) {
    filters.values = { ...filters.values, workspace_id: id ?? '', user_email: '' };
    void applyFilters();
  }
</script>

<Page title={head.title} subtitle={head.subtitle}>
  <!-- No Kind filter: a session is a conversation; its MCP and web calls show
       inside its turns. -->
  <FilterBar>
    <FilterField label={m.browse_filter_search()} class="flex-1 min-w-40">
      <TextInput bind:value={filters.values.search} onkeydown={handleFilterKeydown} placeholder={m.browse_search_placeholder()} />
    </FilterField>
    <ScopeFilters {plane} {filters} {userFilter} onchange={applyFilters} onteam={changeTeam} />
    <div class="pb-px"><PeriodSelector selected={period.value} onchange={period.change} /></div>
    <FilterField label={m.browse_filter_app()} class="min-w-27.5">
      <TextInput bind:value={filters.values.app_id} onkeydown={handleFilterKeydown} placeholder={m.browse_filter_app_placeholder()} />
    </FilterField>
    <FilterField label={m.browse_filter_model()} class="min-w-30">
      <TextInput bind:value={filters.values.model} onkeydown={handleFilterKeydown} placeholder={m.browse_filter_model_placeholder()} />
    </FilterField>
    <FilterField label={m.browse_filter_alert()} class="min-w-22.5">
      <SelectInput bind:value={filters.values.alert_level} onchange={applyFilters}>
        <option value="">{m.browse_all()}</option>
        <option value="major">{m.browse_alert_major()}</option>
        <option value="minor">{m.browse_alert_minor()}</option>
        <option value="info">{m.browse_alert_info()}</option>
      </SelectInput>
    </FilterField>
    <FilterField label={m.browse_filter_linked()} class="min-w-27.5">
      <SelectInput bind:value={filters.values.linked} onchange={applyFilters}>
        <option value="">{m.browse_all()}</option>
        <option value="has_children">{m.browse_linked_has_children()}</option>
        <option value="has_parent">{m.browse_linked_has_parent()}</option>
        <option value="unlinked">{m.browse_linked_unlinked()}</option>
      </SelectInput>
    </FilterField>
    <!-- The badges a session's LLM turns carried, any of them. -->
    <BadgePicker bind:value={filters.values.badges} surfaces={['llm']} onchange={applyFilters} />
    <FilterField label={m.browse_sort()} class="min-w-32.5">
      <SelectInput
        bind:value={filters.values.sort}
        onchange={applyFilters}
        title={searching ? m.browse_sort_with_search() : !sortWindow ? m.browse_sort_needs_window({ days: FIGURE_SORT_MAX_DAYS }) : undefined}>
        <option value="">{m.browse_sort_newest()}</option>
        {#each SORTS as sort (sort)}
          <option value={sort} disabled={unservable(sort)}>{sortLabel[sort]()}</option>
        {/each}
      </SelectInput>
    </FilterField>
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

  {#if view.skeleton}
    <div class="bg-(--bg-card) rounded-xl border border-(--border) p-4">
      <Skeleton variant="row" count={8} height="3rem" />
    </div>
  {:else}
    <div class="bg-(--bg-card) rounded-xl border border-(--border) overflow-hidden">
      <div class="divide-y divide-(--border)">
        {#each sessions as session (session.session_id)}
          {@render branch(session, 0)}
        {/each}
      </div>
      <!-- A cut search found nothing yet: the notice below says why. -->
      {#if sessions.length === 0 && !pager.scanCut}
        <EmptyState title={m.browse_sessions_empty_title()} body={m.browse_sessions_empty_body()}>
          {#snippet icon()}
            <Icon name="chat" size="lg" tone="neutral" />
          {/snippet}
        </EmptyState>
      {/if}
    </div>
    <Pagination state={pager} onchange={changeList} itemsShown={sessions.length} />
  {/if}
</Page>

{#snippet branch(session: SessionSummary, depth: number)}
  <SessionRow
    {session}
    selfScoped={p.portal && !userFilter}
    appName={(id) => appName(apps, id)}
    nested={depth > 0}
    expand={canExpand(nested, depth, session.links?.sub_agents)
      ? { open: session.session_id in expanded, toggle: () => void toggle(session) }
      : undefined}
    onbadge={filterByBadge}
    filtered={badgesSent ? badgesSent.split(',') : []}
  />
  <!-- Only a row that offers the toggle shows its sub-agents: below the depth
       cap a session open elsewhere (a link cycle) renders nothing more. -->
  {#if canExpand(nested, depth, session.links?.sub_agents) && session.session_id in expanded}
    {@const children = expanded[session.session_id]}
    <div class="ml-6 border-l-2 border-l-(--accent)/40 bg-(--bg-secondary) divide-y divide-(--border) border-t border-t-(--border)">
      {#if children === null}
        <p class="px-6 py-2 text-xs text-(--text-secondary)">{m.browse_subagents_loading()}</p>
      {:else}
        {@const more = unlisted(session.links?.sub_agents, children.length)}
        {#each children as child (child.session_id)}
          {@render branch(child, depth + 1)}
        {/each}
        {#if more > 0}
          <a
            href={sessionHref(page.params.slug ?? '', page.url.pathname, session.session_id, filters.values.workspace_id || undefined)}
            class="block px-6 py-2 text-xs text-(--accent) hover:underline"
          >
            {m.browse_subagents_more({ count: more })}
          </a>
        {/if}
      {/if}
    </div>
  {/if}
{/snippet}
