<script lang="ts">
  /**
   * Portal — Team.
   *
   * Scopes to the header-selected workspace. A `manager` of that workspace
   * sees the roster with per-member usage and can mint / revoke a member's
   * keys — always acting as themselves (audited as the manager, the member is
   * the target). A plain `member` sees the read-only roster of their own
   * memberships.
   */
  import type {
    WorkspaceMemberInfo,
    WorkspaceMemberUsage,
    PortalKey,
  } from '#lib/api-types.js';
  import { untrack } from 'svelte';
  import { onRefresh } from '#lib/hooks.svelte.js';
  import { portalApi } from '#lib/portal-client.js';
  import { extractError, fetchAllPages } from '#lib/api-helpers.js';
  import { formatTokens, formatCost, formatSpend } from '#lib/formatters.js';
  import { portalScope } from '#lib/scope.svelte.js';
  import Icon from '#lib/components/Icon.svelte';
  import EmptyState from '#lib/components/EmptyState.svelte';
  import Modal from '#lib/components/Modal.svelte';
  import ConfirmDialog from '#lib/components/ConfirmDialog.svelte';
  import CreateKeyForm from '#lib/components/CreateKeyForm.svelte';
  import KeyBudgetModal from '#lib/components/KeyBudgetModal.svelte';
  import WorkspaceAutomationPanel from '#lib/components/WorkspaceAutomationPanel.svelte';
  import { budgetSummary, type KeyBudget } from '#lib/keyBudget.js';
  import { toast } from '#lib/toast.svelte.js';
  import { m as msg } from '#lib/paraglide/messages.js';
  import { page } from '$app/state';
  import type { components } from '#lib/generated/api-types.js';
  import TagBadge from '#lib/components/TagBadge.svelte';
  import EffectiveLimitStack from '#lib/components/limits/EffectiveLimitStack.svelte';
  import MemberExceptionModal from '#lib/components/limits/MemberExceptionModal.svelte';
  import { decodeLimit, effectiveCap, exceptionDirections } from '#lib/limits.js';
  import { formatAmount } from '#lib/formatters.js';
  import { useDirtyForm } from '#lib/hooks.svelte.js';
  import { accountingCurrency } from '#lib/currency.svelte.js';

  type LimitsOverview = components['schemas']['WorkspaceLimitsOverview'];
  type MemberException = components['schemas']['UserRateLimitOverride'];
  type LimitStack = components['schemas']['EffectiveLimitStack'];

  const activeWsId = $derived(portalScope.activeWorkspace);
  const activeMembership = $derived(portalScope.activeMembership);
  const isManager = $derived(activeMembership?.role === 'manager');

  // BYOK pass-through downstreams a minted vk- key can bind to, scoped to the
  // workspace the key is pinned to (validated backend-side against it).
  async function loadByokProviders(workspaceId: string): Promise<{ id: string; name: string }[]> {
    const { data } = await portalApi.GET('/api/v1/portal/auth/me', {
      params: { query: { workspace_id: workspaceId } },
    });
    return (data?.downstream_providers ?? [])
      .filter((p) => p.byok)
      .map((p) => ({ id: p.id, name: p.name }));
  }

  let loading = $state(true);
  let members = $state<WorkspaceMemberInfo[]>([]);
  let usageByUser = $state<Record<string, WorkspaceMemberUsage>>({});
  let search = $state('');

  // Selected member detail (keys), lazily loaded on expand.
  let selectedMemberId = $state<string | null>(null);
  let memberKeys = $state<PortalKey[]>([]);
  let keysLoading = $state(false);

  let showMint = $state(false);
  let revokeKeyId = $state<string | null>(null);
  let budgetKey = $state<PortalKey | null>(null);

  async function saveMemberKeyBudget(budget: KeyBudget | null) {
    if (!budgetKey || !activeWsId || !selectedMemberId) return;
    const { error: err } = await portalApi.PUT(
      '/api/v1/portal/workspaces/{id}/members/{uid}/keys/{key_id}/budget',
      {
        params: { path: { id: activeWsId, uid: selectedMemberId, key_id: budgetKey.id } },
        body: { budget: budget ?? undefined },
      },
    );
    if (err) throw new Error(extractError(err, msg.portal_team_err_budget()));
    toast.success(msg.portal_team_toast_budget());
    if (selectedMemberId) await loadMemberKeys(selectedMemberId);
  }

  // ── Member limits (manager): the pool and member default are the
  // administrator's; a manager edits one member's exception inside the pool,
  // never their own (the server refuses that too).
  const selfId = $derived(page.data.portalUser?.id ?? '');
  let limits = $state<LimitsOverview | null>(null);
  let exceptions = $state<MemberException[]>([]);
  // Every exception, or none: the exception modal seeds from this list, and a
  // member missing from a partial one would open blank and the save would
  // overwrite their exception. Adding/editing waits for a complete list.
  let exceptionsComplete = $state(false);
  // A failed load says so (with Retry) — never "no exceptions".
  let exceptionsFailed = $state(false);
  // A limits read that failed with nothing loaded yet shows a Retry, not an
  // absent card.
  let limitsFailed = $state(false);
  // The exception actions need the WHOLE roster (manager check, emails,
  // picker) as well as the whole exception list.
  let rosterFailed = $state(false);
  const canEditExceptions = $derived(exceptionsComplete && !rosterFailed);
  let memberStack = $state<LimitStack | null>(null);
  const exceptionForm = useDirtyForm();
  let exceptionOpen = $state(false);
  let exceptionUserId = $state<string | null>(null);
  let savingException = $state(false);
  let exceptionError = $state<string | null>(null);
  let removeExceptionFor = $state<string | null>(null);

  // Only the latest load may land, and a workspace switch clears what the
  // previous workspace showed at once: its exception rows under the new
  // workspace's heading would send Remove to the wrong workspace.
  let limitsGen = 0;
  let limitsWs: string | null = null;
  async function loadLimits() {
    const ws = activeWsId;
    const gen = ++limitsGen;
    if (ws !== limitsWs) {
      limits = null;
      exceptions = [];
      exceptionsComplete = false;
      limitsWs = ws ?? null;
      // Nothing opened for the previous workspace survives into this one.
      exceptionOpen = false;
      exceptionUserId = null;
      removeExceptionFor = null;
      exceptionForm.markClean();
    }
    if (!ws || !isManager) return;
    const [l, e] = await Promise.all([
      portalApi.GET('/api/v1/portal/workspaces/{id}/limits', { params: { path: { id: ws } } }),
      fetchAllPages<MemberException>((offset, limit) =>
        portalApi.GET('/api/v1/portal/workspaces/{id}/member-exceptions', {
          params: { path: { id: ws }, query: { offset, limit } },
        }),
      ).then(
        (items) => ({ items, err: null }),
        (err: unknown) => ({ items: null, err }),
      ),
    ]);
    if (gen !== limitsGen) return;
    // A failed re-read keeps what this workspace already showed.
    if (!l.error) limits = l.data ?? null;
    limitsFailed = !!l.error && limits == null;
    // A workspace switch cleared the rows above, so rows kept here are this
    // workspace's; the failure still says so and disables editing.
    if (e.items != null) exceptions = e.items;
    exceptionsComplete = e.items != null;
    exceptionsFailed = e.items == null;
    if (l.error) toast.error(msg.portal_team_err_limits(), { body: extractError(l.error) });
    else if (e.err) toast.error(msg.portal_team_err_limits(), { body: e.err instanceof Error ? e.err.message : String(e.err) });
  }

  let stackGen = 0;
  /** `silent` (a refresh) keeps the stack shown until the new one lands. */
  async function loadMemberStack(memberId: string, silent = false) {
    if (!silent) memberStack = null;
    const ws = activeWsId;
    const gen = ++stackGen;
    if (!ws) return;
    const { data, error: err } = await portalApi.GET('/api/v1/portal/workspaces/{id}/members/{uid}/limits', {
      params: { path: { id: ws, uid: memberId } },
    });
    if (gen !== stackGen) return;
    // A failed silent re-read keeps the stack shown.
    if (data || !silent) memberStack = data ?? null;
    if (err) toast.error(msg.portal_team_err_member_limits(), { body: extractError(err) });
  }

  const poolCaps = $derived({
    rpm: effectiveCap(decodeLimit(limits?.pool.requests_per_minute, 'pool_rate'), null),
    tpm: effectiveCap(decodeLimit(limits?.pool.tokens_per_minute, 'pool_rate'), null),
    daily: effectiveCap(decodeLimit(limits?.pool.daily_budget, 'pool_budget'), limits?.tenant_default_daily_budget),
    monthly: effectiveCap(decodeLimit(limits?.pool.monthly_budget, 'pool_budget'), limits?.tenant_default_monthly_budget),
  });

  // The default member limit, decoded like the pool: a stored 0 is "no
  // default", never a cap of zero.
  const defaultCaps = $derived({
    rpm: effectiveCap(decodeLimit(limits?.member_defaults.requests_per_minute, 'member_default'), null),
    tpm: effectiveCap(decodeLimit(limits?.member_defaults.tokens_per_minute, 'member_default'), null),
    daily: effectiveCap(decodeLimit(limits?.member_defaults.daily_budget, 'member_default'), null),
    monthly: effectiveCap(decodeLimit(limits?.member_defaults.monthly_budget, 'member_default'), null),
  });

  const money = (n: number) => formatAmount(n, accountingCurrency());
  const capText = (v: number | null) => (v == null ? msg.limits_state_unlimited() : v.toLocaleString());
  const moneyCap = (v: number | null) => (v == null ? msg.limits_state_unlimited() : money(v));

  function openException(userId: string | null) {
    exceptionUserId = userId;
    exceptionError = null;
    exceptionOpen = true;
  }

  async function saveException(userId: string, body: components['schemas']['PutRateLimitOverrideRequest']) {
    if (!activeWsId) return;
    savingException = true;
    const { error: err } = await portalApi.PUT('/api/v1/portal/workspaces/{id}/members/{uid}/limits', {
      params: { path: { id: activeWsId, uid: userId } },
      body,
    });
    savingException = false;
    if (err) {
      exceptionError = extractError(err, msg.portal_team_err_exception());
      return;
    }
    exceptionForm.markClean();
    exceptionOpen = false;
    await loadLimits();
    if (selectedMemberId) await loadMemberStack(selectedMemberId);
  }

  async function confirmRemoveException() {
    const userId = removeExceptionFor;
    removeExceptionFor = null;
    if (!userId || !activeWsId) return;
    const { error: err } = await portalApi.DELETE('/api/v1/portal/workspaces/{id}/members/{uid}/limits', {
      params: { path: { id: activeWsId, uid: userId } },
    });
    if (err) toast.error(msg.portal_team_err_remove_exception(), { body: extractError(err) });
    else {
      await loadLimits();
      if (selectedMemberId) await loadMemberStack(selectedMemberId);
    }
  }

  function memberEmail(userId: string): string {
    return members.find((x) => x.user_id === userId)?.email ?? userId;
  }

  // A manager's limit — the caller's own or a co-manager's — is the
  // administrator's to change; the server refuses it as well.
  function isManagerMember(userId: string): boolean {
    return members.some((x) => x.user_id === userId && x.role === 'manager');
  }

  const selectedMember = $derived(members.find((m) => m.user_id === selectedMemberId) ?? null);
  const filteredMembers = $derived(
    search.trim()
      ? members.filter(
          (m) =>
            m.email.toLowerCase().includes(search.toLowerCase()) ||
            (m.display_name ?? '').toLowerCase().includes(search.toLowerCase())
        )
      : members
  );

  // `silent` skips the full-page spinner — used for in-place refreshes after a
  // mutation (mint/revoke, automation-panel changes) so open panels/modals
  // aren't unmounted mid-action.
  let managerGen = 0;
  async function loadManagerData(silent = false) {
    if (!activeWsId || !isManager) return;
    if (!silent) loading = true;
    const ws = activeWsId;
    const gen = ++managerGen;
    const [rosterRes, statsRes] = await Promise.all([
      // The whole roster: the exception list is complete, and a member beyond
      // a page would lose their email, the manager check and the picker.
      fetchAllPages<WorkspaceMemberInfo>((offset, limit) =>
        portalApi.GET('/api/v1/portal/workspaces/{id}/members', { params: { path: { id: ws }, query: { offset, limit } } }),
      ).then(
        (items) => ({ data: { items }, error: null }),
        (error: unknown) => ({ data: null, error }),
      ),
      portalApi.GET('/api/v1/portal/workspaces/{id}/stats', {
        params: { path: { id: activeWsId }, query: {} },
      }),
    ]);
    // Only the latest load lands — a slower reply for a workspace since left
    // must not replace this one's roster.
    if (gen !== managerGen) return;
    // A failed silent re-read keeps the roster shown (and the open member);
    // the failure is still said, and still disables the exception actions.
    if (rosterRes.data || !silent) members = rosterRes.data?.items ?? [];
    rosterFailed = rosterRes.error != null;
    if (rosterRes.error) {
      toast.error(msg.portal_team_err_roster(), {
        body: rosterRes.error instanceof Error ? rosterRes.error.message : String(rosterRes.error),
      });
    }
    // If the expanded member left the roster (e.g. its automation account was
    // revoked), drop the selection so a later re-add doesn't render stale keys.
    if (selectedMemberId && !members.some((m) => m.user_id === selectedMemberId)) {
      selectedMemberId = null;
      memberKeys = [];
    }
    if (statsRes.data || !silent) {
      const map: Record<string, WorkspaceMemberUsage> = {};
      for (const u of statsRes.data?.members ?? []) map[u.user_id] = u;
      usageByUser = map;
    }
    loading = false;
  }

  /** `silent` (a refresh) keeps the keys shown until the new ones land. A
   *  reply for a member no longer selected is dropped. */
  let memberKeysGen = 0;
  async function loadMemberKeys(memberId: string, silent = false) {
    if (!activeWsId) return;
    // Only the latest read lands: a refresh read before a mint or revoke must
    // not put the old list back after it.
    const gen = ++memberKeysGen;
    if (!silent) {
      keysLoading = true;
      memberKeys = [];
    }
    const { data } = await portalApi.GET(
      '/api/v1/portal/workspaces/{id}/members/{uid}/keys',
      { params: { path: { id: activeWsId, uid: memberId }, query: { limit: 200 } } }
    );
    if (gen !== memberKeysGen) return;
    if (selectedMemberId !== memberId) {
      keysLoading = false;
      return;
    }
    // A failed refresh keeps the keys shown.
    if (data || !silent) memberKeys = data?.items ?? [];
    keysLoading = false;
  }

  function toggleMember(memberId: string) {
    if (selectedMemberId === memberId) {
      selectedMemberId = null;
      memberKeys = [];
      memberStack = null;
    } else {
      selectedMemberId = memberId;
      loadMemberKeys(memberId);
      loadMemberStack(memberId);
    }
  }

  async function handleMintForMember(body: {
    name: string;
    workspace_id: string;
    forward_auth: boolean;
    expires_at?: string;
    budget?: { daily_budget?: number | null; monthly_budget?: number | null; budget_mode: string };
    downstream_provider_id?: string;
  }): Promise<{ id: string; key: string; name: string | null; proxy_base_url?: string | null }> {
    if (!activeWsId || !selectedMemberId) throw new Error(msg.portal_team_err_no_member());
    const { data, error: err } = await portalApi.POST(
      '/api/v1/portal/workspaces/{id}/members/{uid}/keys',
      {
        params: { path: { id: activeWsId, uid: selectedMemberId } },
        body: {
          name: body.name,
          expires_at: body.expires_at,
          forward_auth: body.forward_auth || undefined,
          downstream_provider_id: body.downstream_provider_id,
          budget: body.budget,
        },
      }
    );
    if (err || !data) throw new Error(extractError(err, msg.portal_team_err_mint()));
    await Promise.all([loadMemberKeys(selectedMemberId), loadManagerData(true)]);
    return { id: data.id, key: data.key, name: data.name ?? null, proxy_base_url: data.proxy_base_url };
  }

  async function confirmRevoke() {
    const keyId = revokeKeyId;
    const memberId = selectedMemberId;
    revokeKeyId = null;
    if (!keyId || !memberId || !activeWsId) return;
    const { error: err } = await portalApi.POST(
      '/api/v1/portal/workspaces/{id}/members/{uid}/keys/{key_id}/actions/revoke',
      { params: { path: { id: activeWsId, uid: memberId, key_id: keyId } } }
    );
    if (err) {
      toast.error(msg.portal_team_err_revoke(), { body: extractError(err) });
    } else {
      await Promise.all([loadMemberKeys(memberId), loadManagerData(true)]);
    }
  }

  function keyLive(k: PortalKey): boolean {
    return !k.revoked_at && (!k.expires_at || new Date(k.expires_at) > new Date());
  }

  // A new workspace or role starts over: nothing selected, the spinner.
  $effect(() => {
    void activeWsId;
    const manager = isManager;
    untrack(() => {
      selectedMemberId = null;
      memberKeys = [];
      keysLoading = false;
      memberStack = null;
      stackGen++;
      if (manager) {
        loadManagerData();
        loadLimits();
      } else {
        loading = false;
      }
    });
  });

  // A refresh re-reads in place: the selected member stays open and nothing
  // is blanked, so an auto-refresh tick never moves the page. Not while a
  // workspace's own load is under way: a silent re-read would supersede it,
  // and on failure keep the previous workspace's roster under the new one.
  onRefresh(() => {
    if (!isManager || loading) return;
    void loadManagerData(true);
    void loadLimits();
    const member = selectedMemberId;
    if (member) {
      void loadMemberKeys(member, true);
      void loadMemberStack(member, true);
    }
  });
</script>

<div class="space-y-1 mb-6">
  <h1 class="text-2xl font-bold text-(--text-primary)">{msg.portal_team_title()}</h1>
  <p class="text-sm text-(--text-secondary)">
    {#if activeMembership}
      <span class="text-(--text-primary) font-medium">{activeMembership.name}</span> — {msg.portal_team_role_line({ role: activeMembership.role === 'manager' ? msg.portal_team_role_manager() : msg.portal_team_role_member() })}
      {#if isManager}
        {msg.portal_team_manager_blurb()}
      {:else}
        {msg.portal_team_member_blurb()}
      {/if}
    {:else}
      {msg.portal_team_no_ws()}
    {/if}
  </p>
</div>

{#if loading}
  <div class="flex items-center justify-center py-20">
    <div class="w-6 h-6 border-2 border-(--accent) border-t-transparent rounded-full animate-spin"></div>
  </div>
{:else if !activeMembership}
  <EmptyState
    title={msg.portal_team_empty_title()}
    body={msg.portal_team_no_ws()}
  >
    {#snippet icon()}<Icon name="building" size="lg" tone="neutral" />{/snippet}
  </EmptyState>
{:else if !isManager}
  <!-- Member view: read-only roster of the user's own memberships. -->
  <div class="bg-(--bg-card) rounded-xl border border-(--border)">
    <div class="px-6 py-4 border-b border-(--border)">
      <h2 class="text-sm font-semibold text-(--text-primary)">{msg.portal_team_my_workspaces()}</h2>
    </div>
    <table class="w-full text-sm">
      <thead>
        <tr class="border-b border-(--border) bg-(--bg-primary)/30">
          <th class="px-6 py-2.5 text-left text-xs text-(--text-secondary) uppercase tracking-wider">{msg.portal_team_col_workspace()}</th>
          <th class="px-6 py-2.5 text-right text-xs text-(--text-secondary) uppercase tracking-wider">{msg.portal_team_col_role()}</th>
        </tr>
      </thead>
      <tbody>
        {#each portalScope.workspaces as ws (ws.id)}
          <tr class="border-b border-(--border) hover:bg-(--bg-elevated)">
            <td class="px-6 py-3 text-(--text-primary)">
              <span class="inline-flex items-center gap-2">
                <Icon name="building" size="sm" tone="neutral" />
                {ws.name}
              </span>
            </td>
            <td class="px-6 py-3 text-right">
              <span class="px-2 py-0.5 text-[10px] font-medium rounded-full {ws.role === 'manager' ? 'text-(--warning) bg-(--warning-bg)' : 'text-(--text-secondary) bg-(--bg-primary) border border-(--border)'}">{ws.role === 'manager' ? msg.portal_team_role_manager() : msg.portal_team_role_member()}</span>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{:else}
  <!-- Manager view: roster + per-member usage, expand to manage keys. -->
  <div class="bg-(--bg-card) rounded-xl border border-(--border)">
    <div class="flex items-center justify-between px-6 py-4 border-b border-(--border) gap-3">
      <h2 class="text-sm font-semibold text-(--text-primary)">{msg.portal_team_members()}</h2>
      {#if members.length > 8}
        <input
          type="text"
          bind:value={search}
          placeholder={msg.portal_team_search_placeholder()}
          class="px-3 py-1.5 bg-(--bg-primary) border border-(--border) rounded-lg text-sm text-(--text-primary) placeholder:text-(--text-secondary) focus:outline-hidden focus:border-(--accent) w-56"
        />
      {/if}
    </div>

    {#if filteredMembers.length === 0}
      <div class="px-6 py-8 text-center text-sm text-(--text-secondary)">
        {members.length === 0 ? msg.portal_team_no_members() : msg.portal_team_no_search_match()}
      </div>
    {:else}
      <table class="w-full text-sm">
        <thead>
          <tr class="border-b border-(--border) bg-(--bg-primary)/30">
            <th class="px-6 py-2.5 text-left text-xs text-(--text-secondary) uppercase tracking-wider">{msg.portal_team_col_member()}</th>
            <th class="px-6 py-2.5 text-center text-xs text-(--text-secondary) uppercase tracking-wider">{msg.portal_team_col_role()}</th>
            <th class="px-6 py-2.5 text-right text-xs text-(--text-secondary) uppercase tracking-wider">{msg.portal_team_col_requests()}</th>
            <th class="px-6 py-2.5 text-right text-xs text-(--text-secondary) uppercase tracking-wider">{msg.portal_team_col_tokens()}</th>
            <th class="px-6 py-2.5 text-right text-xs text-(--text-secondary) uppercase tracking-wider">{msg.portal_team_col_cost()}</th>
            <th class="px-6 py-2.5 text-center text-xs text-(--text-secondary) uppercase tracking-wider">{msg.portal_team_col_keys()}</th>
            <th class="px-6 py-2.5 text-right text-xs text-(--text-secondary) uppercase tracking-wider"></th>
          </tr>
        </thead>
        <tbody>
          {#each filteredMembers as m (m.user_id)}
            {@const usage = usageByUser[m.user_id]}
            <tr class="border-b border-(--border) hover:bg-(--bg-elevated)">
              <td class="px-6 py-3 text-(--text-primary)">
                {m.display_name || m.email}
                {#if m.display_name}<span class="text-(--text-secondary) text-xs ml-1">{m.email}</span>{/if}
              </td>
              <td class="px-6 py-3 text-center">
                <span class="px-2 py-0.5 text-[10px] font-medium rounded-full {m.role === 'manager' ? 'text-(--warning) bg-(--warning-bg)' : 'text-(--text-secondary) bg-(--bg-primary) border border-(--border)'}">{m.role === 'manager' ? msg.portal_team_role_manager() : msg.portal_team_role_member()}</span>
              </td>
              <td class="px-6 py-3 text-right text-(--text-secondary)">{usage?.requests ?? 0}</td>
              <td class="px-6 py-3 text-right text-(--text-secondary)">{formatTokens(usage?.tokens)}</td>
              <td class="px-6 py-3 text-right text-(--text-secondary)">{usage ? formatSpend(usage.spend) : formatCost(0, accountingCurrency())}</td>
              <td class="px-6 py-3 text-center text-(--text-secondary)">{m.active_keys}</td>
              <td class="px-6 py-3 text-right">
                <button
                  onclick={() => toggleMember(m.user_id)}
                  class="text-xs text-(--accent) hover:underline"
                >{selectedMemberId === m.user_id ? msg.portal_team_hide_keys() : msg.portal_team_manage_keys()}</button>
              </td>
            </tr>
            {#if selectedMemberId === m.user_id}
              <tr class="bg-(--bg-primary)/30">
                <td colspan="7" class="px-6 py-4">
                  <div class="flex items-center justify-between mb-3">
                    <span class="text-xs font-semibold text-(--text-secondary) uppercase tracking-wider">{msg.portal_team_keys_in({ ws: activeMembership.name })}</span>
                    <button
                      onclick={() => showMint = true}
                      class="px-3 py-1.5 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-xs font-medium transition-colors"
                    >{msg.portal_team_mint_for_button({ email: m.email })}</button>
                  </div>
                  {#if keysLoading}
                    <div class="py-4 text-center text-xs text-(--text-secondary)">{msg.portal_team_loading()}</div>
                  {:else if memberKeys.length === 0}
                    <div class="py-4 text-center text-xs text-(--text-secondary)">{msg.portal_team_no_keys_yet()}</div>
                  {:else}
                    <div class="space-y-1.5">
                      {#each memberKeys as key (key.id)}
                        <div class="flex items-center justify-between px-3 py-2 rounded-lg bg-(--bg-card) border border-(--border)">
                          <span class="flex items-center gap-3">
                            <span class="text-sm text-(--text-primary)">{key.name || '--'}</span>
                            <span class="font-mono text-xs text-(--text-secondary)">{key.key_prefix}…</span>
                            {#if key.forward_auth}<span class="px-1.5 py-0.5 text-[10px] rounded-full bg-(--warning-bg) text-(--warning)">BYOK</span>{/if}
                            {#if budgetSummary(key.daily_budget, key.monthly_budget)}<span class="text-[10px] text-(--text-secondary) tabular-nums">{budgetSummary(key.daily_budget, key.monthly_budget)}{#if key.budget_mode === 'alert_only'} <span class="text-(--warning)">{msg.portal_team_alert_only()}</span>{/if}</span>{/if}
                          </span>
                          <span class="flex items-center gap-3">
                            {#if keyLive(key)}
                              <span class="px-2 py-0.5 text-[10px] rounded-full text-(--success) bg-(--success-bg)">{msg.portal_team_status_active()}</span>
                              <button onclick={() => budgetKey = key} class="text-xs text-(--text-secondary) hover:text-(--text-primary) hover:underline">{msg.portal_team_budget()}</button>
                              <button onclick={() => revokeKeyId = key.id} class="text-xs text-(--error) hover:underline">{msg.portal_team_revoke()}</button>
                            {:else}
                              <span class="px-2 py-0.5 text-[10px] rounded-full text-(--error) bg-(--error-bg)">{key.revoked_at ? msg.portal_team_status_revoked() : msg.portal_team_status_expired()}</span>
                            {/if}
                          </span>
                        </div>
                      {/each}
                    </div>
                  {/if}
                  {#if memberStack}
                    <div class="mt-4 pt-4 border-t border-(--border)">
                      <span class="block mb-2 text-xs font-semibold text-(--text-secondary) uppercase tracking-wider">{msg.portal_team_view_limits()}</span>
                      <EffectiveLimitStack stack={memberStack} />
                    </div>
                  {/if}
                </td>
              </tr>
            {/if}
          {/each}
        </tbody>
      </table>
    {/if}
  </div>

  {#if limits}
    {@const l = limits}
    <div class="mt-6 bg-(--bg-card) rounded-xl border border-(--border)" data-testid="team-limits">
      <div class="px-6 py-4 border-b border-(--border) space-y-1">
        <h2 class="text-sm font-semibold text-(--text-primary)">{msg.portal_team_limits()}</h2>
        <p class="text-xs text-(--text-secondary)">{msg.portal_team_limits_blurb()}</p>
      </div>
      <div class="px-6 py-4 grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
        <div class="space-y-1">
          <div class="text-xs font-semibold text-(--text-secondary) uppercase tracking-wider">{msg.portal_team_pool()} <span class="normal-case font-normal">· {msg.portal_team_set_by_admin()}</span></div>
          <div class="text-(--text-primary)">{msg.limits_rpm_short()} {capText(poolCaps.rpm)} · {msg.limits_tpm_short()} {capText(poolCaps.tpm)}</div>
          <div class="text-(--text-primary)">{msg.limits_daily_short()} {moneyCap(poolCaps.daily)} · {msg.limits_monthly_short()} {moneyCap(poolCaps.monthly)}</div>
        </div>
        <div class="space-y-1">
          <div class="text-xs font-semibold text-(--text-secondary) uppercase tracking-wider">{msg.portal_team_member_default()} <span class="normal-case font-normal">· {msg.portal_team_set_by_admin()}</span></div>
          <div class="text-(--text-primary)">{msg.limits_rpm_short()} {capText(defaultCaps.rpm)} · {msg.limits_tpm_short()} {capText(defaultCaps.tpm)}</div>
          <div class="text-(--text-primary)">{msg.limits_daily_short()} {moneyCap(defaultCaps.daily)} · {msg.limits_monthly_short()} {moneyCap(defaultCaps.monthly)}</div>
        </div>
      </div>
      <div class="px-6 py-4 border-t border-(--border) space-y-3">
        <div class="flex items-center justify-between">
          <h3 class="text-xs font-semibold text-(--text-secondary) uppercase tracking-wider">{msg.portal_team_exceptions()}</h3>
          <button onclick={() => openException(null)} disabled={!canEditExceptions} class="px-3 py-1.5 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-xs font-medium transition-colors disabled:opacity-50">{msg.portal_team_add_exception()}</button>
        </div>
        {#if exceptionsFailed}
          <p class="text-sm text-(--text-secondary)">
            {msg.portal_team_err_limits()}
            <button onclick={loadLimits} class="text-(--accent) hover:underline">{msg.portal_team_retry()}</button>
          </p>
        {:else if exceptions.length === 0}
          <p class="text-sm text-(--text-secondary)">{msg.portal_team_no_exceptions()}</p>
        {:else}
          <div class="space-y-1.5">
            {#each exceptions as ex (ex.user_id)}
              {@const dir = exceptionDirections(ex, l.member_defaults)}
              <div class="flex items-center justify-between gap-3 px-3 py-2 rounded-lg border border-(--border)">
                <span class="flex items-center gap-2 min-w-0">
                  <span class="text-sm text-(--text-primary) truncate">{memberEmail(ex.user_id)}</span>
                  {#if dir.raised}<TagBadge color="teal">▲ {msg.limits_raised()}</TagBadge>{/if}
                  {#if dir.lowered}<TagBadge color="amber">▼ {msg.limits_lowered()}</TagBadge>{/if}
                </span>
                {#if ex.user_id === selfId}
                  <span class="text-xs text-(--text-secondary)">{msg.portal_team_self_exception()}</span>
                {:else if isManagerMember(ex.user_id)}
                  <span class="text-xs text-(--text-secondary)">{msg.portal_team_manager_exception()}</span>
                {:else}
                  <span class="flex items-center gap-3 shrink-0">
                    <button onclick={() => openException(ex.user_id)} disabled={!canEditExceptions} class="text-xs text-(--accent) hover:underline disabled:opacity-50">{msg.portal_team_edit()}</button>
                    <button onclick={() => (removeExceptionFor = ex.user_id)} disabled={!canEditExceptions} class="text-xs text-(--error) hover:underline disabled:opacity-50">{msg.limits_remove()}</button>
                  </span>
                {/if}
              </div>
            {/each}
          </div>
        {/if}
      </div>
    </div>

    <MemberExceptionModal
      open={exceptionOpen && canEditExceptions}
      form={exceptionForm}
      members={members.filter((x) => x.user_id !== selfId && x.role !== 'manager')}
      userId={exceptionUserId}
      {exceptions}
      defaults={l.member_defaults}
      pool={poolCaps}
      currency={accountingCurrency()}
      saving={savingException}
      error={exceptionError}
      onclose={() => {
        exceptionOpen = false;
        exceptionForm.markClean();
      }}
      onsave={saveException}
    />

    <ConfirmDialog
      open={removeExceptionFor !== null}
      title={msg.limits_confirm_remove_title()}
      message={removeExceptionFor ? msg.limits_confirm_remove_body({ email: memberEmail(removeExceptionFor) }) : ''}
      confirmLabel={msg.limits_remove()}
      destructive
      onconfirm={confirmRemoveException}
      oncancel={() => (removeExceptionFor = null)}
    />
  {:else if isManager && limitsFailed}
    <div class="mt-6 bg-(--bg-card) rounded-xl border border-(--border) px-6 py-4 text-sm text-(--text-secondary)">
      {msg.portal_team_err_limits()}
      <button onclick={loadLimits} class="text-(--accent) hover:underline">{msg.portal_team_retry()}</button>
    </div>
  {/if}

  {#if activeWsId}
    <div class="mt-6">
      <WorkspaceAutomationPanel
        workspaceId={activeWsId}
        onChanged={() => loadManagerData(true)}
      />
    </div>
  {/if}

  {#if selectedMember}
    <Modal open={showMint} title={msg.portal_team_mint_for({ email: selectedMember.email })} onclose={() => showMint = false} maxWidth="max-w-lg">
      <CreateKeyForm
        workspaces={activeMembership ? [{ id: activeMembership.id, name: activeMembership.name }] : []}
        defaultWorkspaceId={activeWsId ?? undefined}
        allowBudget={true}
        {loadByokProviders}
        onSubmit={handleMintForMember}
        onDone={() => showMint = false}
      />
    </Modal>
  {/if}

  <KeyBudgetModal
    open={budgetKey !== null}
    keyId={budgetKey?.id ?? null}
    keyName={budgetKey?.name ?? null}
    daily={budgetKey?.daily_budget}
    monthly={budgetKey?.monthly_budget}
    mode={budgetKey?.budget_mode}
    dailySpent={budgetKey?.daily_spent}
    monthlySpent={budgetKey?.monthly_spent}
    onSave={saveMemberKeyBudget}
    onClose={() => { budgetKey = null; }}
  />

  <ConfirmDialog
    open={revokeKeyId !== null}
    title={msg.portal_team_confirm_revoke_title()}
    message={msg.portal_team_confirm_revoke_body()}
    confirmLabel={msg.portal_team_revoke()}
    destructive
    onconfirm={confirmRevoke}
    oncancel={() => revokeKeyId = null}
  />
{/if}
