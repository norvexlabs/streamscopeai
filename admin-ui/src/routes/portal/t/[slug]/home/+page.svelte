<script lang="ts">
  // Portal — Home: where every member lands, and their dashboard. The ways to
  // start (a key, a tool, an MCP server), the caller's own activity over every
  // workspace they use, their latest sessions, and — only when something
  // applies — what waits on them, their limits in the header workspace and
  // their team (managers). One read, `/api/v1/portal/home`, built from cheap
  // reads only (its handler says which).
  import type { PortalHome } from '#lib/api-types.js';
  import { portalApi } from '#lib/portal-client.js';
  import { extractError } from '#lib/api-helpers.js';
  import { onRefresh } from '#lib/hooks.svelte.js';
  import { portalScope, resolvePortalWorkspace } from '#lib/scope.svelte.js';
  import { formatAmount, formatCost, formatSpend } from '#lib/formatters.js';
  import { homeTodos } from '#lib/portalHome.js';
  import { pthref } from '#lib/tenant.js';
  import { auditHref } from '#lib/deeplinks.js';
  import { hiddenPages, pageHidden } from '#lib/portalPages.svelte.js';
  import Page from '#lib/components/page/Page.svelte';
  import Callout from '#lib/components/Callout.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import MetricGrid from '#lib/components/dashboard/MetricGrid.svelte';
  import MetricCard from '#lib/components/dashboard/MetricCard.svelte';
  import Panel from '#lib/components/dashboard/Panel.svelte';
  import LimitMeter from '#lib/components/limits/LimitMeter.svelte';
  import EffectiveLimitStack from '#lib/components/limits/EffectiveLimitStack.svelte';
  import HomeTodoCard from '#lib/components/portal/HomeTodoCard.svelte';
  import SpendStripCard from '#lib/components/portal/SpendStripCard.svelte';
  import SessionRow from '#lib/components/SessionRow.svelte';
  import { m } from '#lib/paraglide/messages.js';
  import type { PageProps } from './$types';

  let { data, params }: PageProps = $props();

  let home = $state<PortalHome | null>(null);
  let loading = $state(true);
  let error = $state('');

  const name = $derived(
    data.portalUser?.display_name || data.portalUser?.email.split('@')[0] || data.portalUser?.email || '',
  );
  // The header workspace, resolved from the server-loaded memberships by the
  // header's own rule: right on the first render, before the layout has
  // reconciled a remembered choice (never a load with a stale one).
  const memberships = $derived(data.portalWorkspaces ?? []);
  // The Sessions page is hidden for the viewer's workspaces: the gateway
  // answers `null` for the recent sessions, and the card that would list them
  // is left out — never shown empty, which would read "no session yet". Until
  // the Home's own answer is in, the identity the layout holds says it.
  const sessionsHidden = $derived(home ? home.recent_sessions === null : pageHidden('sessions', data));
  // The Requests page is hidden: the 7-day tile is a figure, not a link to it.
  const requestsHidden = $derived(pageHidden('requests', data));
  // The Home's answer disagrees with the identity the layout holds: that one
  // is stale, and is re-read so the sidebar follows.
  $effect(() => {
    if (home && (home.recent_sessions === null) !== (data.portalHiddenPages ?? []).includes('sessions')) {
      void hiddenPages.recheck();
    }
  });
  const workspaceId = $derived(resolvePortalWorkspace(memberships, portalScope.activeWorkspace));
  const membership = $derived(memberships.find((w) => w.id === workspaceId) ?? null);
  // No figures yet (loading, or the load failed) reads "--", never "mixed".
  const spendOf = (w: PortalHome['today'] | undefined) => (w ? formatSpend(w.spend) : formatCost(null));
  const requestsOf = (w: PortalHome['today'] | undefined) => (w ? m.portal_home_requests_count({ count: w.requests }) : undefined);

  // Only the latest load writes: a refresh or a header switch never lands
  // under a newer read.
  let loadGen = 0;

  /** A `reload` (a refresh) keeps what is shown until the new figures land,
   *  and a failed one keeps them too, under the error. A first load or a
   *  workspace switch clears them: another workspace's team and limits
   *  never show under this one's name. */
  async function load(ws: string | null, reload = false) {
    const gen = ++loadGen;
    if (!reload) {
      loading = true;
      home = null;
      error = '';
    }
    const { data: body, error: err } = await portalApi.GET('/api/v1/portal/home', {
      params: { query: ws ? { workspace_id: ws } : {} },
    });
    if (gen !== loadGen) return;
    if (err) {
      error = extractError(err, m.portal_home_err_load());
    } else {
      error = '';
      home = body;
    }
    loading = false;
  }

  // Loads on mount and again whenever the header workspace changes.
  $effect(() => {
    void load(workspaceId);
  });

  onRefresh(() => {
    if (!loading) void load(workspaceId, true);
  });

  // The 7-day tile opens Requests on its model calls.
  const last7Days = `/portal${auditHref({ kind: 'llm', days: '7' })}`;

  const todos = $derived(home ? homeTodos(home, Date.now()) : []);
  // The right column renders only what applies; with none of it the
  // sessions take the full width.
  const hasSide = $derived(!!home && (todos.length > 0 || !!home.limits || !!home.team));

  const actionClass =
    'inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors';
</script>

<Page
  title={name ? m.portal_home_title({ name }) : m.nav_portal_home()}
  subtitle={membership
    ? membership.role === 'manager'
      ? m.portal_home_context_manager({ workspace: membership.name })
      : m.portal_home_context_member({ workspace: membership.name })
    : undefined}>
  {#snippet actions()}
    <nav class="flex flex-wrap items-center gap-2" aria-label={m.portal_home_actions()}>
      <a href={pthref(params.slug, '/portal/keys')} data-testid="home-action-new-key"
        class="{actionClass} bg-(--accent) text-(--accent-fg) hover:bg-(--accent-hover)">
        <Icon name="plus" size="sm" color="currentColor" />{m.portal_home_action_new_key()}
      </a>
      <a href={pthref(params.slug, '/portal/quickstart')} data-testid="home-action-set-up"
        class="{actionClass} border border-(--border) text-(--text-primary) hover:bg-(--bg-hover)">
        <Icon name="compass" size="sm" color="currentColor" />{m.portal_home_action_set_up_tool()}
      </a>
      <a href={pthref(params.slug, '/portal/mcp/test')} data-testid="home-action-try-mcp"
        class="{actionClass} border border-(--border) text-(--text-primary) hover:bg-(--bg-hover)">
        <Icon name="wrench" size="sm" color="currentColor" />{m.portal_home_action_try_mcp()}
      </a>
    </nav>
  {/snippet}

  {#if error}
    <Callout severity="error" title={error} />
  {/if}

  <!-- The caller's own figures span every workspace they use: the header
       workspace scopes only the limits and the team block below. -->
  <section aria-label={m.portal_home_your_activity()}>
    <h2 class="text-[11px] font-semibold uppercase tracking-wider text-(--text-tertiary) mb-3">{m.portal_home_your_activity()}</h2>
    <MetricGrid>
      <MetricCard label={m.portal_home_today()} value={spendOf(home?.today)} subtitle={requestsOf(home?.today)} icon="cost" loading={loading && !home} />
      <MetricCard label={m.portal_home_last_7_days()} value={spendOf(home?.last_7_days)} subtitle={requestsOf(home?.last_7_days)} icon="requests" loading={loading && !home} href={requestsHidden ? undefined : last7Days} />
      <SpendStripCard days={home?.daily} loading={loading && !home} />
    </MetricGrid>
  </section>

  <div class="grid grid-cols-1 gap-6 {hasSide ? 'lg:grid-cols-3' : ''}">
    <div class={hasSide ? 'lg:col-span-2' : ''}>
      {#if (home || loading) && !sessionsHidden}
        <Panel
          title={m.portal_home_recent_sessions()}
          action={m.portal_home_all_sessions()}
          actionHref="/portal/sessions"
          flush
          loading={loading && !home}
          empty={!!home && (home.recent_sessions ?? []).length === 0}
          emptyMessage={home?.has_active_key ? m.portal_home_no_sessions() : m.portal_home_no_sessions_yet()}>
          <div class="divide-y divide-(--border)">
            {#each home?.recent_sessions ?? [] as session (session.session_id)}
              <SessionRow {session} selfScoped />
            {/each}
          </div>
        </Panel>
      {/if}
    </div>

    {#if hasSide && home}
      <div class="space-y-6 min-w-0">
        <HomeTodoCard slug={params.slug} {todos} />

        {#if home.limits}
          <div data-testid="home-my-limits">
            <Panel title={membership ? m.portal_home_my_limits_in({ workspace: membership.name }) : m.portal_home_my_limits()}>
              <EffectiveLimitStack stack={home.limits} compact />
            </Panel>
          </div>
        {/if}

        {#if home.team}
          {@const team = home.team}
          <Panel
            title={m.portal_home_team_title({ workspace: team.name })}
            subtitle={m.portal_home_team_members({ count: team.members })}
            action={m.portal_home_action_manage()}
            actionHref="/portal/team">
            <div class="space-y-4">
              <LimitMeter label={m.portal_home_team_today()} used={team.daily.used} cap={team.daily.cap} fmt={(n: number) => formatAmount(n, team.currency)} />
              <LimitMeter label={m.portal_home_team_period()} used={team.monthly.used} cap={team.monthly.cap} fmt={(n: number) => formatAmount(n, team.currency)} />
            </div>
          </Panel>
        {/if}
      </div>
    {/if}
  </div>
</Page>
