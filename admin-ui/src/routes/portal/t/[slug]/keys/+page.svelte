<script lang="ts">
  /**
   * Portal — API Keys.
   *
   * One unified key per (user, workspace). The key authenticates LLM
   * (`/v1/*`), MCP (`/mcp/<slug>`), and — when forward-auth — the BYOK
   * `/fwd/{key}/…` mount. The workspace allowlist gates which providers and
   * MCP servers the key reaches; there is no per-protocol or per-provider key.
   */
  import { onMount } from 'svelte';
  import { onRefresh } from '#lib/hooks.svelte.js';
  import type { PortalMe, PortalKey, PortalStats } from '#lib/api-types.js';
  import { portalApi } from '#lib/portal-client.js';
  import { extractError } from '#lib/api-helpers.js';
  import { portalScope } from '#lib/scope.svelte.js';
  import Icon from '#lib/components/Icon.svelte';
  import Page from '#lib/components/page/Page.svelte';
  import ConfirmDialog from '#lib/components/ConfirmDialog.svelte';
  import Modal from '#lib/components/Modal.svelte';
  import CreateKeyForm from '#lib/components/CreateKeyForm.svelte';
  import ByokBadge from '#lib/components/ByokBadge.svelte';
  import { budgetSummary, spendVsCap } from '#lib/keyBudget.js';
  import Panel from '#lib/components/dashboard/Panel.svelte';
  import SegmentedControl from '#lib/components/forms/SegmentedControl.svelte';
  import { formatCount, formatKeyLabel, formatSpend, formatTimeAgo, formatTokens } from '#lib/formatters.js';
  import { keyUsageStart, type KeyUsagePeriod } from '#lib/portalKeyUsage.js';
  import { toast } from '#lib/toast.svelte.js';
  import { m } from '#lib/paraglide/messages.js';

  let me = $state<PortalMe | null>(null);
  let keys = $state<PortalKey[]>([]);
  let loading = $state(true);
  let showCreate = $state(false);
  const workspaces = $derived(me?.workspaces ?? []);
  // BYOK pass-through downstreams a vk- key can bind to, scoped to the SELECTED
  // workspace (the binding is validated against it, so the caller's whole union
  // would offer providers that then 400).
  async function loadByokProviders(workspaceId: string): Promise<{ id: string; name: string }[]> {
    const { data } = await portalApi.GET('/api/v1/portal/auth/me', {
      params: { query: { workspace_id: workspaceId } },
    });
    return (data?.downstream_providers ?? [])
      .filter((p) => p.byok)
      .map((p) => ({ id: p.id, name: p.name }));
  }

  // The portal operates within the header-selected workspace. Keys and the
  // create-key default scope to it. With a single
  // membership the selector self-hides and this is simply that workspace.
  const activeWsId = $derived(portalScope.activeWorkspace);
  const activeWsName = $derived(portalScope.activeMembership?.name ?? null);
  const visibleKeys = $derived(
    activeWsId ? keys.filter((k) => k.workspace_id === activeWsId) : keys
  );

  // Only the latest load writes: a refresh never lands under a newer one.
  let loadGen = 0;

  /** A `reload` (a refresh) keeps the page shown until the new data lands,
   *  and a part that fails to re-read keeps what it showed (`keep`): an
   *  auto-refresh tick never blanks it. */
  async function loadData(reload = false, keep = reload) {
    const gen = ++loadGen;
    if (!reload) loading = true;
    try {
      const [meRes, keysRes] = await Promise.all([
        portalApi.GET('/api/v1/portal/auth/me'),
        portalApi.GET('/api/v1/portal/keys'),
      ]);
      if (gen !== loadGen) return;
      if (meRes.data) me = meRes.data;
      if (keysRes.data || !keep) keys = keysRes.data?.items ?? [];
      if (keysRes.error) toast.error(extractError(keysRes.error));
    } catch (e) {
      if (gen === loadGen) toast.error(extractError(e));
    } finally {
      if (gen === loadGen) loading = false;
    }
  }

  // Each live key's traffic over the picked period: the caller's own rows
  // (`/portal/stats` without a workspace never widens to a team), shown for
  // the keys of the header workspace like the list above.
  let period = $state<KeyUsagePeriod>('last_7_days');
  let usage = $state<PortalStats['per_key'] | null>(null);
  let usageLoading = $state(true);
  let usageError = $state('');
  let usageGen = 0;
  const periodOptions = $derived<{ value: KeyUsagePeriod; label: string }[]>([
    { value: 'today', label: m.portal_keys_usage_today() },
    { value: 'last_7_days', label: m.portal_keys_usage_7d() },
    { value: 'last_30_days', label: m.portal_keys_usage_30d() },
  ]);
  const visibleIds = $derived(new Set(visibleKeys.map((k) => k.id)));
  const visibleUsage = $derived((usage ?? []).filter((u) => visibleIds.has(u.key_id)));

  /** A `reload` keeps the rows shown until the new ones land, and a failed
   *  one keeps them too, saying so in a toast; a period change shows the
   *  skeleton, and its failure in the panel. */
  async function loadUsage(reload = false) {
    const gen = ++usageGen;
    if (!reload) {
      usageLoading = true;
      usage = null;
    }
    const { data, error: err } = await portalApi.GET('/api/v1/portal/stats', {
      params: { query: { start: keyUsageStart(period, new Date()) } },
    });
    if (gen !== usageGen) return;
    if (err && reload) {
      toast.error(extractError(err, m.portal_keys_usage_err()));
    } else if (err) {
      usageError = extractError(err, m.portal_keys_usage_err());
    } else {
      usageError = '';
      usage = data.per_key;
    }
    usageLoading = false;
  }

  onMount(() => {
    void loadData();
    void loadUsage();
  });
  // Every refresh re-reads in place (`loadData(true)`) — not while the page's
  // own load is under way, which it would supersede.
  onRefresh(() => {
    if (!loading) void loadData(true);
    if (!usageLoading) void loadUsage(true);
  });

  /** After a mint or revoke: the page's own latest-wins re-read, so a refresh
   *  read before the change never lands after it, and a superseded first load
   *  still ends the spinner. Nothing kept on failure: the list shown before
   *  the change is known to be wrong. */
  async function refreshKeys() {
    await Promise.all([loadData(true, false), loadUsage(true)]);
  }

  async function handleCreateKeySubmit(body: {
    name: string;
    workspace_id: string;
    forward_auth: boolean;
    expires_at?: string;
    downstream_provider_id?: string;
  }): Promise<{ id: string; key: string; name: string | null; proxy_base_url?: string | null }> {
    const { data, error: err } = await portalApi.POST('/api/v1/portal/keys', {
      body: {
        workspace_id: body.workspace_id,
        name: body.name,
        expires_at: body.expires_at,
        forward_auth: body.forward_auth || undefined,
        downstream_provider_id: body.downstream_provider_id,
      },
    });
    if (err || !data) throw new Error(extractError(err, m.portal_keys_err_create()));
    await refreshKeys();
    return { id: data.id, key: data.key, name: data.name ?? null, proxy_base_url: data.proxy_base_url };
  }

  let revokeKeyId = $state<string | null>(null);

  async function confirmRevokeKey() {
    const keyId = revokeKeyId;
    revokeKeyId = null;
    if (!keyId) return;
    try {
      const { error: err } = await portalApi.POST('/api/v1/portal/keys/{id}/actions/revoke', {
        params: { path: { id: keyId } },
      });
      if (err) {
        toast.error(extractError(err, m.portal_keys_err_revoke()));
      } else {
        toast.success(m.portal_keys_toast_revoked());
        await refreshKeys();
      }
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : m.portal_keys_err_revoke_retry());
    }
  }

  function keyStatus(key: PortalKey): { label: string; color: string } {
    if (key.revoked_at) return { label: m.portal_keys_status_revoked(), color: 'text-(--error) bg-(--error-bg)' };
    if (key.expires_at && new Date(key.expires_at) < new Date()) return { label: m.portal_keys_status_expired(), color: 'text-(--error) bg-(--error-bg)' };
    if (key.expires_at) {
      const daysLeft = Math.ceil((new Date(key.expires_at).getTime() - Date.now()) / 86400000);
      if (daysLeft <= 7) return { label: m.portal_keys_status_days_left({ days: daysLeft }), color: 'text-(--warning) bg-(--warning-bg)' };
    }
    return { label: m.portal_keys_status_active(), color: 'text-(--success) bg-(--success-bg)' };
  }
</script>

<Page title={m.portal_keys_title()}>
  {#snippet description()}
    {m.portal_keys_desc_pre()}<code class="font-mono">/v1/*</code>{m.portal_keys_desc_mid()}<code class="font-mono">/mcp/&lt;slug&gt;</code>{m.portal_keys_desc_post()}
  {/snippet}
<div>

{#if loading}
  <div class="flex items-center justify-center py-20">
    <div class="w-6 h-6 border-2 border-(--accent) border-t-transparent rounded-full animate-spin"></div>
  </div>
{:else if me}
  {#if activeWsName}
    <p class="text-xs text-(--text-secondary) mb-3">
      {m.portal_keys_showing()} <span class="text-(--text-primary) font-medium">{activeWsName}</span>{#if workspaces.length > 1} {m.portal_keys_showing_switch()}{/if}
    </p>
  {/if}

  <!-- My Keys -->
  <div class="bg-(--bg-card) rounded-xl border border-(--border) mb-6">
    <div class="flex items-center justify-between px-6 py-4 border-b border-(--border)">
      <h2 class="text-sm font-semibold text-(--text-primary)">{m.portal_keys_my_keys()}</h2>
      <button
        onclick={() => showCreate = true}
        disabled={workspaces.length === 0}
        class="px-3 py-1.5 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-xs font-medium transition-colors disabled:opacity-50"
      >
        {m.portal_keys_create_button()}
      </button>
    </div>

    {#if visibleKeys.length > 0}
      <table class="w-full text-sm">
        <thead>
          <tr class="border-b border-(--border) bg-(--bg-primary)/30">
            <th class="px-6 py-2.5 text-left text-xs text-(--text-secondary) uppercase tracking-wider">{m.portal_keys_col_name()}</th>
            <th class="px-6 py-2.5 text-left text-xs text-(--text-secondary) uppercase tracking-wider">{m.portal_keys_col_workspace()}</th>
            <th class="px-6 py-2.5 text-left text-xs text-(--text-secondary) uppercase tracking-wider">{m.portal_keys_col_prefix()}</th>
            <th class="px-6 py-2.5 text-center text-xs text-(--text-secondary) uppercase tracking-wider">{m.portal_keys_col_type()}</th>
            <th class="px-6 py-2.5 text-center text-xs text-(--text-secondary) uppercase tracking-wider">{m.portal_keys_col_status()}</th>
            <th class="px-6 py-2.5 text-right text-xs text-(--text-secondary) uppercase tracking-wider">{m.portal_keys_col_actions()}</th>
          </tr>
        </thead>
        <tbody>
          {#each visibleKeys as key (key.id)}
            {@const status = keyStatus(key)}
            <tr class="border-b border-(--border) hover:bg-(--bg-elevated)">
              <td class="px-6 py-3 text-(--text-primary)">
                {key.name || '--'}
                <!-- Read-only: members see their own cap but can't set it. -->
                {#if budgetSummary(key.daily_budget, key.monthly_budget)}
                  <span class="flex items-center gap-1 mt-0.5 text-[10px] text-(--text-secondary)">
                    <Icon name="cost" size="sm" tone={key.budget_mode === 'alert_only' ? 'warning' : 'neutral'} />
                    <span class="tabular-nums">{budgetSummary(key.daily_budget, key.monthly_budget)}</span>
                    {#if key.budget_mode === 'alert_only'}<span class="text-(--warning)">{m.portal_keys_alert_only()}</span>{/if}
                  </span>
                  {#if spendVsCap(key.daily_budget, key.daily_spent) || spendVsCap(key.monthly_budget, key.monthly_spent)}
                    <span class="block mt-0.5 text-[10px] text-(--text-secondary) tabular-nums">
                      {#if spendVsCap(key.daily_budget, key.daily_spent)}{m.portal_keys_spend_day()} {spendVsCap(key.daily_budget, key.daily_spent)}{/if}
                      {#if spendVsCap(key.monthly_budget, key.monthly_spent)} · {m.portal_keys_spend_month()} {spendVsCap(key.monthly_budget, key.monthly_spent)}{/if}
                    </span>
                  {/if}
                {/if}
              </td>
              <td class="px-6 py-3">
                <span class="inline-flex items-center gap-1.5 text-(--text-secondary)">
                  <Icon name="building" size="sm" tone="neutral" />
                  <span>{key.workspace_name}</span>
                </span>
              </td>
              <td class="px-6 py-3 font-mono text-(--text-secondary)">{key.key_prefix}…</td>
              <td class="px-6 py-3 text-center">
                {#if key.forward_auth}
                  <ByokBadge testid="byok-badge" />
                {:else}
                  <span class="px-2 py-0.5 text-[10px] font-medium rounded-full bg-(--accent)/10 text-(--accent) border border-(--accent)">{m.portal_keys_type_standard()}</span>
                {/if}
              </td>
              <td class="px-6 py-3 text-center">
                <span class="px-2 py-0.5 text-[10px] font-medium rounded-full {status.color}">{status.label}</span>
              </td>
              <td class="px-6 py-3 text-right">
                {#if !key.revoked_at}
                  <button onclick={() => revokeKeyId = key.id} class="text-xs text-(--error) hover:underline">{m.portal_keys_revoke()}</button>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {:else}
      <div class="px-6 py-8 text-center text-sm text-(--text-secondary)">
        {m.portal_keys_empty({ ws: activeWsName ?? m.portal_keys_this_workspace() })}
      </div>
    {/if}
  </div>

  <!-- Usage by key, over the picked period -->
  <div class="mb-6" data-testid="key-usage">
    <Panel
      title={m.portal_keys_usage_title()}
      flush
      loading={usageLoading}
      error={usageError}
      empty={!usageLoading && visibleUsage.length === 0}
      emptyMessage={m.portal_keys_usage_empty()}>
      {#snippet headerExtra()}
        <SegmentedControl
          options={periodOptions}
          bind:value={period}
          label={m.portal_keys_usage_period()}
          size="xs"
          onchange={() => void loadUsage()} />
      {/snippet}
      <table class="w-full text-sm">
        <thead>
          <tr class="text-[10px] uppercase tracking-wider text-(--text-secondary) border-b border-(--border)">
            <th class="text-left font-medium px-5 py-2">{m.portal_keys_usage_col_key()}</th>
            <th class="text-left font-medium px-5 py-2">{m.portal_keys_col_workspace()}</th>
            <th class="text-right font-medium px-5 py-2">{m.portal_keys_usage_col_requests()}</th>
            <th class="text-right font-medium px-5 py-2">{m.portal_keys_usage_col_tokens()}</th>
            <th class="text-right font-medium px-5 py-2">{m.portal_keys_usage_col_spend()}</th>
            <th class="text-right font-medium px-5 py-2">{m.portal_keys_usage_col_last_used()}</th>
          </tr>
        </thead>
        <tbody>
          {#each visibleUsage as k (k.key_id)}
            <tr class="border-b border-(--border) last:border-0" data-testid="key-usage-row" data-key-id={k.key_id}>
              <td class="px-5 py-2 text-(--text-primary)">{formatKeyLabel(k.name, k.prefix)}</td>
              <td class="px-5 py-2 text-(--text-secondary)">{k.workspace}</td>
              <td class="px-5 py-2 text-right tabular-nums" data-testid="key-usage-requests">{formatCount(k.requests)}</td>
              <td class="px-5 py-2 text-right font-mono">{formatTokens(k.tokens)}</td>
              <td class="px-5 py-2 text-right font-mono">{formatSpend(k.spend)}</td>
              <td class="px-5 py-2 text-right text-(--text-secondary)">{k.last_used ? formatTimeAgo(k.last_used) : '--'}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </Panel>
  </div>

  <!-- My Workspaces -->
  <div class="bg-(--bg-card) rounded-xl border border-(--border)">
    <div class="px-6 py-4 border-b border-(--border)">
      <h2 class="text-sm font-semibold text-(--text-primary)">{m.portal_keys_my_workspaces()}</h2>
    </div>
    {#if workspaces.length > 0}
      <div class="divide-y divide-(--border)">
        {#each workspaces as ws (ws.id)}
          <div class="px-6 py-3 flex items-center justify-between">
            <span class="inline-flex items-center gap-2 text-sm text-(--text-primary)">
              <Icon name="building" size="sm" tone="neutral" />
              {ws.name}
            </span>
            <span class="px-2 py-0.5 text-[10px] font-medium rounded-full {ws.role === 'manager' ? 'text-(--warning) bg-(--warning-bg)' : 'text-(--text-secondary) bg-(--bg-primary) border border-(--border)'}">{ws.role === 'manager' ? m.portal_keys_role_manager() : m.portal_keys_role_member()}</span>
          </div>
        {/each}
      </div>
    {:else}
      <div class="px-6 py-6 text-center text-sm text-(--text-secondary)">
        {m.portal_keys_no_workspaces()}
      </div>
    {/if}
  </div>

  <Modal open={showCreate} title={m.portal_keys_modal_create()} onclose={() => showCreate = false} maxWidth="max-w-lg">
    <CreateKeyForm
      {workspaces}
      {loadByokProviders}
      defaultWorkspaceId={activeWsId ?? undefined}
      onSubmit={handleCreateKeySubmit}
      onDone={() => showCreate = false}
    />
  </Modal>

  <ConfirmDialog
    open={revokeKeyId !== null}
    title={m.portal_keys_confirm_revoke_title()}
    message={m.portal_keys_confirm_revoke_body()}
    confirmLabel={m.portal_keys_revoke()}
    destructive
    onconfirm={confirmRevokeKey}
    oncancel={() => revokeKeyId = null}
  />
{/if}
</div>
</Page>
