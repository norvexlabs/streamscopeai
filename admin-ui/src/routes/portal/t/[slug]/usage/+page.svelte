<script lang="ts">
  import { workspaceQuery } from '#lib/selfScoped.js';
  // Portal — My Usage (member self-service).
  //
  // The caller's own spend / requests / tokens, server-forced to their user_id
  // by the existing `/api/v1/portal/stats` endpoint (workspace-confined for an
  // `ak-` key). Read-only summary; per-key breakdown links nowhere admin-only.
  import { onMount } from 'svelte';
  import { onRefresh } from '#lib/hooks.svelte.js';
  import type { PortalStats } from '#lib/api-types.js';
  import { portalApi } from '#lib/portal-client.js';
  import { extractError } from '#lib/api-helpers.js';
  import { toast } from '#lib/toast.svelte.js';
  import { formatTokens, formatSpend, formatTimeAgo } from '#lib/formatters.js';
  import { m } from '#lib/paraglide/messages.js';
  import PortalScopeSelector from '#lib/components/portal/PortalScopeSelector.svelte';
  import Page from '#lib/components/page/Page.svelte';
  import EffectiveLimitStack from '#lib/components/limits/EffectiveLimitStack.svelte';
  import { portalScope, portalWorkspaceName, type PortalWorkspaceMembership } from '#lib/scope.svelte.js';
  import type { components } from '#lib/generated/api-types.js';

  type LimitStack = components['schemas']['EffectiveLimitStack'];

  let stats = $state<PortalStats | null>(null);
  let loading = $state(true);
  let error = $state('');
  // Undefined = the caller's own rows; a workspace id widens to that
  // workspace, which the server honours only where sharing is on.
  let scopeWorkspaceId = $state<string | undefined>(undefined);
  // The heading names the team being viewed, never "my" rows in a team view.
  const scopeName = $derived(portalWorkspaceName(scopeWorkspaceId));

  // Monotonic: only the latest load writes, so a refresh landing after a
  // scope change never puts the other scope's figures back.
  let loadGen = 0;

  /** A `reload` (a refresh) keeps the figures shown until the new ones land:
   *  an auto-refresh tick never blanks the page. */
  async function load(reload = false) {
    const gen = ++loadGen;
    if (!reload) {
      loading = true;
      error = '';
    }
    const { data, error: err } = await portalApi.GET('/api/v1/portal/stats', {
      params: { query: workspaceQuery(scopeWorkspaceId) },
    });
    if (gen !== loadGen) return;
    if (err) {
      error = extractError(err, m.portal_usage_err_load());
      // A failed refresh keeps what is shown, under the error.
      if (!reload) stats = null;
    } else {
      error = '';
      stats = data ?? null;
    }
    loading = false;
  }

  // What limits the caller in each of their workspaces — the same stack the
  // gateway enforces, computed server-side.
  let myLimits = $state<{ id: string; name: string; stack: LimitStack }[]>([]);
  // Only the latest load may land: a slower earlier one (an empty list read
  // before the layout filled it, a refresh overtaken by the next) must not
  // overwrite a newer answer.
  let limitsGen = 0;
  async function loadLimits(list: PortalWorkspaceMembership[]) {
    const gen = ++limitsGen;
    const loaded = await Promise.all(
      list.map(async (ws) => {
        const { data, error: err } = await portalApi.GET('/api/v1/portal/workspaces/{id}/my-limits', {
          params: { path: { id: ws.id } },
        });
        return { ws, stack: data ?? null, err };
      }),
    );
    if (gen !== limitsGen) return;
    // A workspace whose re-read failed keeps the card it had.
    const previous = new Map(myLimits.map((l) => [l.id, l.stack]));
    myLimits = loaded.flatMap((w) => {
      const stack = w.stack ?? (w.err ? previous.get(w.ws.id) : undefined);
      return stack ? [{ id: w.ws.id, name: w.ws.name, stack }] : [];
    });
    // A workspace whose limits could not be read is said so, never left out
    // silently — an empty card reads as "nothing limits you".
    // One notice per load, naming every workspace that failed.
    const failed = loaded.filter((w) => w.err);
    if (failed.length > 0) {
      toast.error(m.portal_usage_err_limits({ workspace: failed.map((w) => w.ws.name).join(', ') }), {
        body: extractError(failed[0].err),
      });
    }
  }

  onMount(() => {
    void load();
  });

  // The workspace list is filled by the layout, possibly after this page has
  // mounted — so the limits load follows the list (and each refresh), never
  // a one-off read of whatever it held at mount.
  let workspaceList: PortalWorkspaceMembership[] = [];
  $effect(() => {
    workspaceList = portalScope.workspaces;
    void loadLimits(workspaceList);
  });

  // Every refresh re-reads in place — the figures not while the page's own
  // load (a scope change) is under way: it would supersede it, and on failure
  // keep the previous scope's figures under the new one.
  onRefresh(() => {
    if (!loading) void load(true);
    void loadLimits(workspaceList);
  });
</script>

<Page
  title={scopeName ? m.portal_usage_title_team() : m.portal_usage_title()}
  subtitle={scopeName ? m.portal_usage_subtitle_team({ workspace: scopeName }) : m.portal_usage_subtitle()}>
  {#snippet actions()}
    <PortalScopeSelector
      workspaceId={scopeWorkspaceId}
      onChange={(id) => {
        scopeWorkspaceId = id;
        void load();
      }} />
  {/snippet}

  {#if error}
    <div class="rounded-xl border border-(--error) bg-(--error-bg) px-4 py-3 text-sm text-(--error)">{error}</div>
  {/if}

  {#if loading}
    <div class="flex items-center gap-3 py-16 justify-center text-(--text-secondary)">
      <div class="w-5 h-5 border-2 border-(--accent) border-t-transparent rounded-full animate-spin"></div>
      {m.portal_usage_loading()}
    </div>
  {:else if stats}
    <!-- Aggregate cards -->
    <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
      <div class="rounded-xl border border-(--border) bg-(--bg-card) px-4 py-3">
        <div class="text-xs text-(--text-secondary)">{m.portal_usage_requests()}</div>
        <div class="text-2xl font-bold text-(--text-primary) tabular-nums">{stats.total_requests.toLocaleString()}</div>
      </div>
      <div class="rounded-xl border border-(--border) bg-(--bg-card) px-4 py-3">
        <div class="text-xs text-(--text-secondary)">{m.portal_usage_tokens()}</div>
        <div class="text-2xl font-bold text-(--text-primary) tabular-nums">{formatTokens(stats.total_tokens)}</div>
      </div>
      <div class="rounded-xl border border-(--border) bg-(--bg-card) px-4 py-3">
        <div class="text-xs text-(--text-secondary)">{m.portal_usage_cost()}</div>
        <div class="text-2xl font-bold text-(--text-primary) font-mono">{formatSpend(stats.spend)}</div>
      </div>
      <div class="rounded-xl border border-(--border) bg-(--bg-card) px-4 py-3">
        <div class="text-xs text-(--text-secondary)">{m.portal_usage_active_keys()}</div>
        <div class="text-2xl font-bold text-(--text-primary) tabular-nums">{stats.active_keys}{#if stats.expiring_soon > 0}<span class="text-xs text-(--warning) ml-1">({m.portal_usage_expiring({ count: stats.expiring_soon })})</span>{/if}</div>
      </div>
    </div>

    <!-- My limits, per workspace -->
    {#if myLimits.length > 0}
      <div class="rounded-xl border border-(--border) bg-(--bg-card)" data-testid="my-limits">
        <div class="px-4 py-2.5 border-b border-(--border) space-y-0.5">
          <div class="text-xs font-semibold uppercase tracking-wider text-(--text-secondary)">{m.portal_usage_my_limits()}</div>
          <p class="text-xs text-(--text-secondary)">{m.portal_usage_my_limits_blurb()}</p>
        </div>
        <div class="p-4 grid grid-cols-1 lg:grid-cols-2 gap-4">
          {#each myLimits as w (w.id)}
            <div class="space-y-2">
              <div class="text-sm font-medium text-(--text-primary)">{m.portal_usage_my_limits_in({ ws: w.name })}</div>
              <EffectiveLimitStack stack={w.stack} />
            </div>
          {/each}
        </div>
      </div>
    {/if}

    <!-- Per-key breakdown -->
    {#if stats.per_key.length > 0}
      <div class="rounded-xl border border-(--border) bg-(--bg-card) overflow-hidden">
        <div class="px-4 py-2.5 border-b border-(--border) text-xs font-semibold uppercase tracking-wider text-(--text-secondary)">{m.portal_usage_by_key()}</div>
        <table class="w-full text-sm">
          <thead>
            <tr class="text-[10px] uppercase tracking-wider text-(--text-secondary) border-b border-(--border)">
              <th class="text-left font-medium px-4 py-2">{m.portal_usage_col_key()}</th>
              <th class="text-left font-medium px-4 py-2">{m.portal_usage_col_workspace()}</th>
              <th class="text-right font-medium px-4 py-2">{m.portal_usage_requests()}</th>
              <th class="text-right font-medium px-4 py-2">{m.portal_usage_tokens()}</th>
              <th class="text-right font-medium px-4 py-2">{m.portal_usage_cost()}</th>
              <th class="text-right font-medium px-4 py-2">{m.portal_usage_col_last_used()}</th>
            </tr>
          </thead>
          <tbody>
            {#each stats.per_key as k (k.key_id)}
              <tr class="border-b border-(--border) last:border-0">
                <td class="px-4 py-2 font-mono text-(--text-primary)">{k.name || ''} <code class="text-[10px] bg-(--bg-secondary) px-1 rounded-sm">{k.prefix}...</code></td>
                <td class="px-4 py-2 text-(--text-secondary)">{k.workspace}</td>
                <td class="px-4 py-2 text-right tabular-nums">{k.requests.toLocaleString()}</td>
                <td class="px-4 py-2 text-right font-mono">{formatTokens(k.tokens)}</td>
                <td class="px-4 py-2 text-right font-mono">{formatSpend(k.spend)}</td>
                <td class="px-4 py-2 text-right text-(--text-secondary)">{k.last_used ? formatTimeAgo(k.last_used) : '--'}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  {/if}
</Page>
