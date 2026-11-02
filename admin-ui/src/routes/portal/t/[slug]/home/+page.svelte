<script lang="ts">
  // Portal — Home: where every member lands. What needs doing (only what
  // applies), the quick actions, the caller's own spend, their team (managers),
  // and their latest sessions — one read, `/api/v1/portal/home`, built from
  // cheap reads only (its handler says which).
  import type { PortalHome } from '#lib/api-types.js';
  import { portalApi } from '#lib/portal-client.js';
  import { extractError } from '#lib/api-helpers.js';
  import { onRefresh } from '#lib/hooks.svelte.js';
  import { portalScope, resolvePortalWorkspace } from '#lib/scope.svelte.js';
  import { formatAmount, formatCost, formatCount, formatDate, formatKeyLabel, formatSpend } from '#lib/formatters.js';
  import { limitBucketLabel, meterRatio, meterTone } from '#lib/limits.js';
  import { pthref } from '#lib/tenant.js';
  import { auditHref } from '#lib/deeplinks.js';
  import Page from '#lib/components/page/Page.svelte';
  import Callout from '#lib/components/Callout.svelte';
  import LinkTile from '#lib/components/LinkTile.svelte';
  import MetricGrid from '#lib/components/dashboard/MetricGrid.svelte';
  import MetricCard from '#lib/components/dashboard/MetricCard.svelte';
  import Panel from '#lib/components/dashboard/Panel.svelte';
  import LimitMeter from '#lib/components/limits/LimitMeter.svelte';
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
  const workspaceId = $derived(resolvePortalWorkspace(memberships, portalScope.activeWorkspace));
  const membership = $derived(memberships.find((w) => w.id === workspaceId) ?? null);
  // No figures yet (loading, or the load failed) reads "--", never "mixed".
  const spendOf = (w: PortalHome['today'] | undefined) => (w ? formatSpend(w.spend) : formatCost(null));

  // Only the latest load writes: a refresh or a header switch never lands
  // under a newer read.
  let loadGen = 0;

  /** A `reload` (a refresh) keeps what is shown until the new figures land,
   *  and a failed one keeps them too, under the error. A first load or a
   *  workspace switch clears them: another workspace's team and warnings
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

  const expired = (at: string) => new Date(at).getTime() <= Date.now();

  // The 7-day request figure counts model calls over the last 7 days: its
  // tile opens Requests on the same.
  const last7Days = `/portal${auditHref({ kind: 'llm', days: '7' })}`;

  // A member who reaches the gateway without a key (OAuth sign-in) has recent
  // traffic: they are set up, so only a member with neither is told to.
  const needsSetUp = $derived(!!home && !home.has_active_key && home.last_7_days.requests === 0);

  const hasTodo = $derived(
    !!home &&
      (needsSetUp ||
        home.expiring_keys.length > 0 ||
        home.mcp_sign_in.length > 0 ||
        home.limit_warnings.length > 0),
  );
</script>

<Page
  title={name ? m.portal_home_title({ name }) : m.nav_portal_home()}
  subtitle={membership
    ? membership.role === 'manager'
      ? m.portal_home_context_manager({ workspace: membership.name })
      : m.portal_home_context_member({ workspace: membership.name })
    : undefined}>
  {#if error}
    <Callout severity="error" title={error} />
  {/if}

  {#if hasTodo && home}
    <section class="space-y-2" aria-label={m.portal_home_todo()}>
      {#if needsSetUp}
        <Callout severity="info" title={m.portal_home_todo_no_key_title()}>
          {m.portal_home_todo_no_key_body()}
          {#snippet action()}
            <a href={pthref(params.slug, '/portal/quickstart')} class="inline-block px-3 py-1.5 rounded-lg bg-(--accent) text-(--accent-fg) text-xs font-semibold hover:bg-(--accent-hover) transition-colors">{m.portal_home_action_set_up()}</a>
          {/snippet}
        </Callout>
      {/if}
      {#each home.expiring_keys as key (key.id)}
        <Callout
          severity={expired(key.expires_at) ? 'error' : 'warning'}
          title={(expired(key.expires_at) ? m.portal_home_todo_key_expired : m.portal_home_todo_key_expiring)({
            name: formatKeyLabel(key.name, key.key_prefix),
            date: formatDate(key.expires_at),
          })}>
          {#snippet action()}
            <a href={pthref(params.slug, '/portal/keys')} class="inline-block px-3 py-1.5 rounded-lg border border-(--accent) text-(--accent) text-xs font-semibold hover:bg-(--bg-hover) transition-colors">{m.portal_home_action_keys()}</a>
          {/snippet}
        </Callout>
      {/each}
      {#each home.mcp_sign_in as server (server.slug)}
        <Callout severity="warning" title={m.portal_home_todo_sign_in({ name: server.name })}>
          {#snippet action()}
            <a href={pthref(params.slug, '/portal/mcp/connections')} class="inline-block px-3 py-1.5 rounded-lg border border-(--accent) text-(--accent) text-xs font-semibold hover:bg-(--bg-hover) transition-colors">{m.portal_home_action_sign_in()}</a>
          {/snippet}
        </Callout>
      {/each}
      {#each home.limit_warnings as w, i (i)}
        <Callout
          severity={meterTone(meterRatio(w.used, w.cap)) === 'error' ? 'error' : 'warning'}
          title={m.portal_home_todo_limit({
            limit: limitBucketLabel(w.bucket, w.key_name, w.key_prefix),
            window: w.window === 'daily' ? m.portal_home_window_daily() : m.portal_home_window_monthly(),
            used: formatAmount(w.used, w.currency),
            cap: formatAmount(w.cap, w.currency),
          })}>
          {#snippet action()}
            <a href={pthref(params.slug, '/portal/usage')} class="inline-block px-3 py-1.5 rounded-lg border border-(--accent) text-(--accent) text-xs font-semibold hover:bg-(--bg-hover) transition-colors">{m.portal_home_action_limits()}</a>
          {/snippet}
        </Callout>
      {/each}
    </section>
  {/if}

  <section aria-label={m.portal_home_quick_actions()}>
    <h2 class="text-[11px] font-semibold uppercase tracking-wider text-(--text-tertiary) mb-3">{m.portal_home_quick_actions()}</h2>
    <div class="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
      <LinkTile href="/portal/keys" icon="key" title={m.portal_home_qa_key_title()} body={m.portal_home_qa_key_body()} />
      <LinkTile href="/portal/quickstart" icon="compass" title={m.portal_home_qa_tool_title()} body={m.portal_home_qa_tool_body()} />
      <LinkTile href="/portal/quickstart?tab=cli" icon="desktop" title={m.portal_home_qa_cli_title()} body={m.portal_home_qa_cli_body()} />
      <LinkTile href="/portal/mcp/test" icon="wrench" title={m.portal_home_qa_mcp_title()} body={m.portal_home_qa_mcp_body()} />
    </div>
  </section>

  <!-- The caller's own figures span every workspace they use: the header
       workspace scopes only the warnings and the team block above. -->
  <section aria-label={m.portal_home_your_activity()}>
    <h2 class="text-[11px] font-semibold uppercase tracking-wider text-(--text-tertiary) mb-3">{m.portal_home_your_activity()}</h2>
    <MetricGrid>
      <MetricCard label={m.portal_home_spend_today()} value={spendOf(home?.today)} icon="cost" loading={loading && !home} />
      <MetricCard label={m.portal_home_requests_today()} value={formatCount(home?.today.requests)} icon="requests" loading={loading && !home} />
      <MetricCard label={m.portal_home_spend_7d()} value={spendOf(home?.last_7_days)} icon="cost" loading={loading && !home} href="/portal/usage" />
      <MetricCard label={m.portal_home_requests_7d()} value={formatCount(home?.last_7_days.requests)} icon="requests" loading={loading && !home} href={last7Days} />
    </MetricGrid>
  </section>

  {#if home?.team}
    {@const team = home.team}
    <Panel
      title={m.portal_home_team_title({ workspace: team.name })}
      subtitle={m.portal_home_team_members({ count: team.members })}
      action={m.portal_home_action_manage()}
      actionHref="/portal/team">
      <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
        <LimitMeter label={m.portal_home_team_today()} used={team.daily.used} cap={team.daily.cap} fmt={(n: number) => formatAmount(n, team.currency)} />
        <LimitMeter label={m.portal_home_team_period()} used={team.monthly.used} cap={team.monthly.cap} fmt={(n: number) => formatAmount(n, team.currency)} />
      </div>
    </Panel>
  {/if}

  {#if home || loading}
    <Panel
      title={m.portal_home_recent_sessions()}
      action={m.portal_home_all_sessions()}
      actionHref="/portal/sessions"
      flush
      loading={loading && !home}
      empty={!!home && home.recent_sessions.length === 0}
      emptyMessage={home?.has_active_key ? m.portal_home_no_sessions() : m.portal_home_no_sessions_yet()}>
      <div class="divide-y divide-(--border)">
        {#each home?.recent_sessions ?? [] as session (session.session_id)}
          <SessionRow {session} selfScoped />
        {/each}
      </div>
    </Panel>
  {/if}
</Page>
