<script lang="ts">
  // The session list, on both planes: the console's Sessions page and the
  // portal's. `plane` (`#lib/browse/planes.js`) decides which API answers, the
  // scope controls and the period default. The expert alert filter is offered
  // only where the server applies it (`plane.offersAlerts`): the portal
  // withholds expert findings, so a control there would do nothing.
  import type { SessionSummary } from '#lib/api-types.js';
  import type { BrowsePlane, SessionFilterQuery } from '#lib/browse/planes.js';
  import { ALERT_LEVELS, oneOf, SESSION_LINKAGE } from '#lib/filter-values.js';
  import { toast } from '#lib/toast.svelte.js';
  import { extractError } from '#lib/api-helpers.js';
  import { daysToDateRange, appName } from '#lib/formatters.js';
  import { PERIOD_FILTER_KEYS, portalWorkspaceName } from '#lib/scope.svelte.js';
  import { usePeriodicLoad, usePagination, UrlFilters, useAuditPeriod } from '#lib/hooks.svelte.js';
  import { useRefreshView } from '#lib/loadView.svelte.js';
  import { setPortalWorkspace } from '#lib/selfScoped.js';
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
  let apps = $state<Map<string, { name?: string }>>(new Map());
  let loading = $state(true);
  // A refresh keeps what is shown; a filter or page change shows the skeleton.
  const view = useRefreshView(() => loading);

  const filters = new UrlFilters<string>([...p.sessionKeys, ...PERIOD_FILTER_KEYS], { ...p.periodDefaults });
  const period = useAuditPeriod(filters, applyFilters, { persist: p.persistPeriod });
  const pager = usePagination({ limit: 50 });
  const shortSearch = $derived(searchTooShort(filters.values.search));

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
    return {
      app_id: v.app_id || undefined,
      model: v.model || undefined,
      // A term too short to search is left out (the API refuses it): the bar
      // says why, and every other filter still applies.
      search: shortSearch ? undefined : v.search?.trim() || undefined,
      start,
      end,
      alert_level: p.offersAlerts ? oneOf(ALERT_LEVELS, v.alert_level) : undefined,
      linked: oneOf(SESSION_LINKAGE, v.linked),
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
      const { data, error: err } = await p.listSessions(query(), scope);
      if (gen !== loadGen) return;
      if (err) {
        toast.error(extractError(err));
        // A failed refresh keeps the list it showed.
        if (!view.refreshing) { sessions = []; }
      } else {
        sessions = pager.absorbOffset(data);
      }
    } catch (e) {
      toast.error(extractError(e));
      if (gen === loadGen && !view.refreshing) { sessions = []; }
    } finally {
      if (gen === loadGen) loading = false;
    }
  }

  function handleFilterKeydown(e: KeyboardEvent) {
    if (e.key === 'Enter') void applyFilters();
  }

  async function applyFilters() {
    pager.reset();
    await loadSessions();
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
    {#if p.offersAlerts}
      <FilterField label={m.browse_filter_alert()} class="min-w-22.5">
        <SelectInput bind:value={filters.values.alert_level} onchange={applyFilters}>
          <option value="">{m.browse_all()}</option>
          <option value="major">{m.browse_alert_major()}</option>
          <option value="minor">{m.browse_alert_minor()}</option>
          <option value="info">{m.browse_alert_info()}</option>
        </SelectInput>
      </FilterField>
    {/if}
    <FilterField label={m.browse_filter_linked()} class="min-w-27.5">
      <SelectInput bind:value={filters.values.linked} onchange={applyFilters}>
        <option value="">{m.browse_all()}</option>
        <option value="has_children">{m.browse_linked_has_children()}</option>
        <option value="has_parent">{m.browse_linked_has_parent()}</option>
        <option value="unlinked">{m.browse_linked_unlinked()}</option>
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
          <SessionRow {session} selfScoped={p.portal && !userFilter} appName={(id) => appName(apps, id)} />
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
    <Pagination state={pager} onchange={loadSessions} itemsShown={sessions.length} />
  {/if}
</Page>
