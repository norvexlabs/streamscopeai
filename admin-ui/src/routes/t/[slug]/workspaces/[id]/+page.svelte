<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import { extractError, fetchAllPages, keysRevoked } from '#lib/api-helpers.js';
  import { goto } from '$app/navigation';
  import { thref } from '#lib/tenant.js';
  import { profileLists } from '#lib/scope.svelte.js';
  import { formatAmount } from '#lib/formatters.js';
  import { accountingCurrency } from '#lib/currency.svelte.js';
  import WorkspaceProfilePicker from '#lib/components/workspaces/WorkspaceProfilePicker.svelte';
  import type {
    WorkspaceDetail,
    WorkspaceMemberRow,
    WorkspaceProvider,
    WorkspaceMcpServer,
    WorkspaceA2aAgent,
    A2aAgentRow,
    DownstreamProvider,
  } from '#lib/api-types.js';
  import type { components } from '#lib/generated/api-types.js';
  import { useTabState } from '#lib/hooks.svelte.js';
  import { toast } from '#lib/toast.svelte.js';
  import TabbedPage from '#lib/components/page/TabbedPage.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import ConfirmDialog from '#lib/components/ConfirmDialog.svelte';
  import FormField from '#lib/components/forms/FormField.svelte';
  import TextInput from '#lib/components/forms/TextInput.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import NumberInput from '#lib/components/forms/NumberInput.svelte';
  import EmptyState from '#lib/components/EmptyState.svelte';
  import EntityPicker, { type PickerItem } from '#lib/components/EntityPicker.svelte';
  import ToggleSetting from '#lib/components/forms/ToggleSetting.svelte';
  import BudgetModeToggle from '#lib/components/BudgetModeToggle.svelte';
  import GrantList, { type GrantEntry } from '#lib/components/GrantList.svelte';
  import { isOffPassthrough } from '#lib/endpoints.js';
  import TagBadge from '#lib/components/TagBadge.svelte';
  import Callout from '#lib/components/Callout.svelte';
  import LimitField from '#lib/components/limits/LimitField.svelte';
  import LimitMeter from '#lib/components/limits/LimitMeter.svelte';
  import EffectiveLimitStack from '#lib/components/limits/EffectiveLimitStack.svelte';
  import MemberExceptionModal from '#lib/components/limits/MemberExceptionModal.svelte';
  import { compareToDefault, decodeLimit, effectiveCap, encodeLimit, isValidLimit, type LimitState } from '#lib/limits.js';
  import { formatTokens } from '#lib/formatters.js';
  import { useDirtyForm } from '#lib/hooks.svelte.js';
  import type { PageProps } from './$types';

  let { params }: PageProps = $props();

  type McpVirtualServer = components['schemas']['McpVirtualServerRow'];
  type UserOverride = components['schemas']['UserRateLimitOverride'];
  type LimitsOverview = components['schemas']['WorkspaceLimitsOverview'];
  type LimitStack = components['schemas']['EffectiveLimitStack'];

  const id = $derived(params.id);
  let slug = $derived(params.slug);

  let detail = $state<WorkspaceDetail | null>(null);
  let members = $state<WorkspaceMemberRow[]>([]);
  let providers = $state<WorkspaceProvider[]>([]);
  let mcpServers = $state<WorkspaceMcpServer[]>([]);
  let a2aAgents = $state<WorkspaceA2aAgent[]>([]);
  let overrides = $state<UserOverride[]>([]);
  // Every exception, or none: the exception modal seeds from this list, and a
  // member missing from a partial one would open blank and the save would
  // overwrite their exception. Adding/editing waits for a complete list.
  let overridesComplete = $state(false);
  let limits = $state<LimitsOverview | null>(null);
  let loading = $state(true);
  let loadError = $state('');

  // Reference data (whole tenant pool — toggled against the workspace allowlist).
  let allProviders = $state<DownstreamProvider[]>([]);
  let allMcp = $state<McpVirtualServer[]>([]);
  let allA2a = $state<A2aAgentRow[]>([]);

  const isDefault = $derived(detail?.role === 'default');
  const isAgent = $derived(detail?.role === 'agent');
  const isInlineAi = $derived(detail?.role === 'inline');
  const allowedProviderIds = $derived(new Set(providers.map((p) => p.id)));
  const allowedMcpIds = $derived(new Set(mcpServers.map((s) => s.id)));
  const allowedA2aIds = $derived(new Set(a2aAgents.map((a) => a.id)));

  type WsTab = 'overview' | 'members' | 'access' | 'limits';
  const WS_TABS = ['overview', 'members', 'access', 'limits'] as const satisfies readonly WsTab[];
  const wsTab = useTabState<WsTab>(WS_TABS, 'overview');

  async function loadDetail() {
    const { data, error } = await adminApi.GET('/api/v1/admin/workspaces/{id}', { params: { path: { id } } });
    if (error) {
      loadError = extractError(error, 'Failed to load workspace');
      return;
    }
    detail = data ?? null;
    providers = data?.providers ?? [];
    mcpServers = data?.mcp_servers ?? [];
    a2aAgents = data?.a2a_agents ?? [];
  }

  let membersFor = '';
  let membersGen = 0;
  async function loadMembers() {
    const forId = id;
    const gen = ++membersGen;
    // Another workspace's roster is never shown (or acted on) under this one.
    if (membersFor !== forId) {
      members = [];
      membersFor = forId;
    }
    try {
      const all = await fetchAllPages<WorkspaceMemberRow>((offset, limit) =>
        adminApi.GET('/api/v1/admin/workspaces/{id}/members', { params: { path: { id: forId }, query: { offset, limit } } }),
      );
      if (gen === membersGen && forId === id) members = all;
    } catch (e: unknown) {
      if (gen !== membersGen || forId !== id) return;
      members = [];
      toast.error('Failed to load members', { body: e instanceof Error ? e.message : String(e) });
    }
  }

  let overridesFor = '';
  let overridesGen = 0;
  // A failed load says so (with Retry) — never "no exceptions".
  let overridesFailed = $state(false);
  async function loadOverrides() {
    const forId = id;
    const gen = ++overridesGen;
    overridesComplete = false;
    // Another workspace's rows are never shown under this one — Remove on one
    // would delete this workspace's exception for that user.
    if (overridesFor !== forId) {
      overrides = [];
      overridesFor = forId;
    }
    try {
      const all = await fetchAllPages<UserOverride>((offset, limit) =>
        adminApi.GET('/api/v1/admin/workspaces/{id}/rate-limit-overrides', {
          params: { path: { id: forId }, query: { offset, limit } },
        }),
      );
      if (gen !== overridesGen || forId !== id) return;
      overrides = all;
      overridesComplete = true;
      overridesFailed = false;
    } catch (e: unknown) {
      if (gen !== overridesGen || forId !== id) return;
      overrides = [];
      overridesComplete = false;
      overridesFailed = true;
      toast.error('Failed to load member exceptions', { body: e instanceof Error ? e.message : String(e) });
    }
  }

  // Pool, inherited tenant default, member default — seeds the Limits tab's
  // fields (once per workspace, like the overview fields) and resolves every
  // "Inherit (…)" label.
  // The workspace `limits` was loaded for. A reply for a workspace the page
  // has since left is dropped, and a new workspace starts with none — so the
  // fields are never seeded (and saved) from another workspace's limits.
  // `limitsFor` (reactive) drives the seeding effect and is written only after
  // the reply; the check before the request reads the plain `limitsLoadedFor`,
  // because a state read there would make the page's load effect depend on it
  // and reload the page each time it changed.
  let limitsFor = $state('');
  let limitsLoadedFor = '';
  let limitsGen = 0;
  async function loadLimits() {
    const forId = id;
    const gen = ++limitsGen;
    if (limitsLoadedFor !== forId) {
      limits = null;
      limitsFor = '';
      limitsLoadedFor = '';
    }
    const { data, error } = await adminApi.GET('/api/v1/admin/workspaces/{id}/limits', { params: { path: { id: forId } } });
    // Only the latest load lands — an earlier reply, even for this workspace,
    // may predate a save the later one reflects.
    if (gen !== limitsGen || forId !== id) return;
    if (error) {
      toast.error('Failed to load limits', { body: extractError(error) });
      return;
    }
    limits = data ?? null;
    limitsFor = forId;
    limitsLoadedFor = forId;
  }

  async function loadReference() {
    const [p, m, a] = await Promise.all([
      adminApi.GET('/api/v1/admin/downstream-providers', { params: { query: { offset: 0, limit: 500 } } }),
      adminApi.GET('/api/v1/admin/mcp/virtual-servers', { params: { query: { offset: 0, limit: 500 } } }),
      adminApi.GET('/api/v1/admin/a2a/agents', { params: { query: { offset: 0, limit: 500 } } }),
    ]);
    allProviders = p.data?.items ?? [];
    allMcp = m.data?.items ?? [];
    allA2a = a.data?.items ?? [];
  }

  async function loadAll() {
    loading = true;
    loadError = '';
    openMemberId = '';
    testStack = null;
    testGen++;
    // Nothing opened for the previous workspace survives into this one: a
    // modal seeded there would save here.
    exceptionOpen = false;
    exceptionUserId = null;
    removeTarget = null;
    exceptionForm.markClean();
    await Promise.all([loadDetail(), loadMembers(), loadOverrides(), loadLimits(), loadReference(), loadQosClasses()]);
    loading = false;
  }

  $effect(() => {
    if (id) loadAll();
  });

  // ---------- Overview (name + description + delete) ----------
  let editName = $state('');
  let editDescription = $state('');
  // Whether members of this workspace see each other's usage, sessions and
  // audit in the portal. Saved on flip rather than with the name/description,
  // because it changes who can see what and should not ride a text edit.
  let sharesWithMembers = $state(false);
  let savingVisibility = $state(false);
  let countsTowardTenantBudget = $state(true);
  let savingTenantBudgetFlag = $state(false);
  let savingName = $state(false);

  // Seed edit fields once per workspace, NOT on every `detail` reassign — a
  // sibling-tab mutation reloads `detail` and would otherwise clobber unsaved
  // edits. After a save the form already holds the saved values.
  let seededId = $state('');
  $effect(() => {
    if (detail && seededId !== detail.id) {
      seededId = detail.id;
      editName = detail.name;
      editDescription = detail.description ?? '';
      editClaimName = detail.oidc_claim_name ?? '';
      editClaimPattern = detail.oidc_claim_pattern ?? '';
      sharesWithMembers = detail.member_visibility === 'members';
      countsTowardTenantBudget = detail.counts_toward_tenant_budget;
      editQosClassId = detail.qos_class_id ?? '';
      editFairnessWeight = detail.fairness_weight;
    }
  });

  // ── Priority under load ──
  let qosClasses = $state<components['schemas']['QosClass'][]>([]);
  let editQosClassId = $state('');
  let editFairnessWeight = $state(1);
  let savingQos = $state(false);

  async function loadQosClasses() {
    const { data, error } = await adminApi.GET('/api/v1/admin/qos-classes', {});
    if (error) return; // the card falls back to "inherit the tenant default"
    qosClasses = data?.items ?? [];
  }

  async function saveQos() {
    savingQos = true;
    const { error } = await adminApi.PATCH('/api/v1/admin/workspaces/{id}', {
      params: { path: { id } },
      body: {
        qos_class_id: editQosClassId === '' ? null : editQosClassId,
        fairness_weight: editFairnessWeight,
      },
    });
    if (error) toast.error('Failed to save', { body: extractError(error) });
    else { toast.success('Priority saved'); await loadDetail(); }
    savingQos = false;
  }

  let limitsSeededId = $state('');
  $effect(() => {
    if (limits && detail && limitsFor === detail.id && limitsSeededId !== detail.id) {
      limitsSeededId = detail.id;
      seedLimitFields(limits);
    }
  });

  async function saveOverview() {
    savingName = true;
    const { error } = await adminApi.PATCH('/api/v1/admin/workspaces/{id}', {
      params: { path: { id } },
      body: { name: editName.trim(), description: editDescription.trim() || null },
    });
    if (error) toast.error('Failed to save', { body: extractError(error) });
    else { toast.success('Workspace updated'); await loadDetail(); }
    savingName = false;
  }

  async function saveMemberVisibility(next: boolean) {
    savingVisibility = true;
    const { error } = await adminApi.PATCH('/api/v1/admin/workspaces/{id}', {
      params: { path: { id } },
      body: { member_visibility: next ? 'members' : 'private' },
    });
    if (error) {
      toast.error('Failed to save', { body: extractError(error) });
      sharesWithMembers = !next;
    } else {
      toast.success(next ? 'Members can now see this workspace\u2019s activity' : 'Activity is private to each member again');
      await loadDetail();
    }
    savingVisibility = false;
  }

  async function saveTenantBudgetFlag(next: boolean) {
    savingTenantBudgetFlag = true;
    const { error } = await adminApi.PATCH('/api/v1/admin/workspaces/{id}', {
      params: { path: { id } },
      body: { counts_toward_tenant_budget: next },
    });
    if (error) {
      toast.error('Failed to save', { body: extractError(error) });
      countsTowardTenantBudget = !next;
    } else {
      toast.success(next
        ? 'This workspace now counts against the organisation budget'
        : 'This workspace no longer counts against the organisation budget');
      await loadDetail();
    }
    savingTenantBudgetFlag = false;
  }

  let confirmDelete = $state(false);
  async function deleteWorkspace() {
    confirmDelete = false;
    const { error } = await adminApi.DELETE('/api/v1/admin/workspaces/{id}', { params: { path: { id } } });
    if (error) toast.error('Failed to delete', { body: extractError(error) });
    else { toast.success('Workspace deleted'); await goto(thref(slug, '/workspaces')); }
  }

  // ---------- Members ----------
  let pickedUser = $state<PickerItem | null>(null);
  let addMemberRole = $state<'member' | 'manager'>('member');

  // Server-backed search excluding current members.
  async function searchUsers(q: string): Promise<PickerItem[]> {
    const { data } = await adminApi.GET('/api/v1/admin/users', {
      params: { query: { q: q || undefined, limit: 20 } },
    });
    const memberIds = new Set(members.map((m) => m.user_id));
    return (data?.items ?? [])
      .filter((u) => !memberIds.has(u.id))
      .map((u) => ({ id: u.id, label: u.email, sublabel: u.display_name ?? undefined }));
  }

  async function addMember() {
    if (!pickedUser) return;
    const { error } = await adminApi.POST('/api/v1/admin/workspaces/{id}/members', {
      params: { path: { id } },
      body: { user_id: pickedUser.id, role: addMemberRole },
    });
    if (error) toast.error('Failed to add member', { body: extractError(error) });
    else {
      pickedUser = null;
      addMemberRole = 'member';
      await Promise.all([loadMembers(), loadDetail(), loadOverrides(), loadLimits()]);
    }
  }

  async function changeMemberRole(userId: string, role: string) {
    const { error } = await adminApi.PATCH('/api/v1/admin/workspaces/{id}/members/{user_id}', {
      params: { path: { id, user_id: userId } },
      body: { role },
    });
    if (error) { toast.error('Failed to update role', { body: extractError(error) }); await loadMembers(); }
  }

  async function removeMember(userId: string) {
    const { data, error } = await adminApi.DELETE('/api/v1/admin/workspaces/{id}/members/{user_id}', {
      params: { path: { id, user_id: userId } },
    });
    if (error) toast.error('Failed to remove member', { body: extractError(error) });
    else {
      const revoked = keysRevoked(data);
      if (revoked > 0) toast.success(`Member removed — ${revoked} key${revoked === 1 ? '' : 's'} revoked`);
      // A removed member takes their exception with them: every limits view
      // re-reads, and an expanded row lets go of them.
      if (openMemberId === userId) void loadTestStack('');
      await Promise.all([loadMembers(), loadDetail(), loadOverrides(), loadLimits()]);
      refreshTestStack();
    }
  }

  // OIDC auto-membership (lives under Members).
  let editClaimName = $state('');
  let editClaimPattern = $state('');
  let savingOidc = $state(false);
  async function saveOidc() {
    savingOidc = true;
    const { error } = await adminApi.PATCH('/api/v1/admin/workspaces/{id}', {
      params: { path: { id } },
      body: {
        oidc_claim_name: editClaimName.trim() || null,
        oidc_claim_pattern: editClaimPattern.trim() || null,
      },
    });
    if (error) toast.error('Failed to save', { body: extractError(error) });
    else { toast.success('OIDC mapping saved'); await loadDetail(); }
    savingOidc = false;
  }

  // ---------- Access: what the workspace is granted ----------
  // Each list shows the grants; "+ Add" offers what is not granted and can be.
  // An off pass-through is not offered (it reaches nothing), but a grant of one
  // stays listed, marked Off, so it can be seen and removed.
  const grantedProviders = $derived<GrantEntry[]>(
    providers.map((p) => ({ id: p.id, label: p.name, byok: p.byok, off: isOffPassthrough(p) })),
  );
  const providerCandidates = $derived<GrantEntry[]>(
    allProviders
      .filter((p) => !allowedProviderIds.has(p.id) && !isOffPassthrough(p))
      .map((p) => ({ id: p.id, label: p.name, sublabel: p.byok ? 'pass-through' : undefined, byok: p.byok })),
  );
  const offPassthroughsHidden = $derived(
    allProviders.filter((p) => !allowedProviderIds.has(p.id) && isOffPassthrough(p)).length,
  );
  const grantedMcp = $derived<GrantEntry[]>(
    mcpServers.map((s) => ({
      id: s.id,
      label: s.name,
      sublabel: s.slug,
      warning: allMcp.find((vs) => vs.id === s.id)?.oauth_incomplete
        ? 'OAuth client incomplete — set the Client ID and Secret on the upstream; members cannot connect until then.'
        : undefined,
    })),
  );
  const mcpCandidates = $derived<GrantEntry[]>(
    allMcp
      .filter((vs) => !allowedMcpIds.has(vs.id) && !vs.oauth_incomplete)
      .map((vs) => ({ id: vs.id, label: vs.name, sublabel: vs.slug })),
  );
  const mcpOauthIncomplete = $derived(
    allMcp.filter((vs) => !allowedMcpIds.has(vs.id) && vs.oauth_incomplete).length,
  );
  const grantedA2a = $derived<GrantEntry[]>(
    a2aAgents.map((a) => ({ id: a.id, label: a.name, sublabel: a.slug })),
  );
  const a2aCandidates = $derived<GrantEntry[]>(
    allA2a.filter((a) => !allowedA2aIds.has(a.id)).map((a) => ({ id: a.id, label: a.name, sublabel: a.slug })),
  );

  /** Removing a pass-through grant refuses every key bound to it here until it
   *  is granted again, so that removal asks first. */
  function confirmProviderRemoval(entry: GrantEntry): string | null {
    const p = providers.find((x) => x.id === entry.id);
    // Nothing bound, nothing refused: removed at once, like any grant.
    if (!p?.byok || p.bound_keys === 0) return null;
    const keys = p.bound_keys === 1 ? 'The 1 key' : `The ${p.bound_keys} keys`;
    return `Remove "${p.name}" from this workspace? ${keys} bound to this pass-through will be refused until it is granted again.`;
  }

  async function grantChange(req: Promise<{ error?: unknown }>): Promise<boolean> {
    const { error } = await req;
    if (error) toast.error('Failed to update access', { body: extractError(error) });
    await loadDetail();
    return !error;
  }

  const addProvider = (providerId: string) =>
    grantChange(adminApi.POST('/api/v1/admin/workspaces/{id}/providers', { params: { path: { id } }, body: { provider_id: providerId } }));
  const removeProvider = (providerId: string) =>
    grantChange(adminApi.DELETE('/api/v1/admin/workspaces/{id}/providers/{provider_id}', { params: { path: { id, provider_id: providerId } } }));
  const addMcp = (serverId: string) =>
    grantChange(adminApi.POST('/api/v1/admin/workspaces/{id}/mcp-servers', { params: { path: { id } }, body: { virtual_server_id: serverId } }));
  const removeMcp = (serverId: string) =>
    grantChange(adminApi.DELETE('/api/v1/admin/workspaces/{id}/mcp-servers/{server_id}', { params: { path: { id, server_id: serverId } } }));
  const addA2a = (agentId: string) =>
    grantChange(adminApi.POST('/api/v1/admin/workspaces/{id}/a2a-agents', { params: { path: { id } }, body: { agent_id: agentId } }));
  const removeA2a = (agentId: string) =>
    grantChange(adminApi.DELETE('/api/v1/admin/workspaces/{id}/a2a-agents/{agent_id}', { params: { path: { id, agent_id: agentId } } }));

  // ---------- Access: per-kind profile assignment ----------
  // Resolve a kind's three-state assignment from the workspace detail:
  //   no entry            → 'inherit' (tenant default)
  //   entry, profile_id null → 'off' (policy disabled)
  //   entry with a profile_id → that id
  function assignmentState(kind: string): string {
    const entry = detail?.assigned_profiles?.find((p) => p.kind === kind);
    if (!entry) return 'inherit';
    return entry.profile_id ?? 'off';
  }

  // ---------- Limits ----------
  // Every field is tri-state (Inherit · Unlimited · a value); `#lib/limits.js`
  // owns how each column encodes that, so nothing here reads null or 0.
  let poolRpm = $state<LimitState>({ kind: 'unlimited' });
  let poolTpm = $state<LimitState>({ kind: 'unlimited' });
  let poolDaily = $state<LimitState>({ kind: 'inherit' });
  let poolMonthly = $state<LimitState>({ kind: 'inherit' });
  let poolMode = $state<'enforce' | 'alert_only'>('enforce');
  let defRpm = $state<LimitState>({ kind: 'unlimited' });
  let defTpm = $state<LimitState>({ kind: 'unlimited' });
  let defDaily = $state<LimitState>({ kind: 'unlimited' });
  let defMonthly = $state<LimitState>({ kind: 'unlimited' });
  let defMode = $state<'enforce' | 'alert_only'>('enforce');
  let savingPool = $state(false);
  let savingDefaults = $state(false);

  function seedLimitFields(l: LimitsOverview) {
    poolRpm = decodeLimit(l.pool.requests_per_minute, 'pool_rate');
    poolTpm = decodeLimit(l.pool.tokens_per_minute, 'pool_rate');
    poolDaily = decodeLimit(l.pool.daily_budget, 'pool_budget');
    poolMonthly = decodeLimit(l.pool.monthly_budget, 'pool_budget');
    poolMode = l.pool.budget_mode === 'alert_only' ? 'alert_only' : 'enforce';
    defRpm = decodeLimit(l.member_defaults.requests_per_minute, 'member_default');
    defTpm = decodeLimit(l.member_defaults.tokens_per_minute, 'member_default');
    defDaily = decodeLimit(l.member_defaults.daily_budget, 'member_default');
    defMonthly = decodeLimit(l.member_defaults.monthly_budget, 'member_default');
    defMode = l.member_defaults.budget_mode === 'alert_only' ? 'alert_only' : 'enforce';
  }

  const money = (n: number) => formatAmount(n);
  const count = (n: number) => n.toLocaleString();
  // What an unset pool budget resolves to: the tenant default, or unlimited.
  const tenantDefaultLabel = (v: number | undefined) => (v && v > 0 ? money(v) : 'Unlimited');

  // The pool's EFFECTIVE caps (what the gateway enforces), for the meters and
  // the exception modal's "the pool still applies" note.
  const poolCaps = $derived({
    rpm: effectiveCap(decodeLimit(limits?.pool.requests_per_minute, 'pool_rate'), null),
    tpm: effectiveCap(decodeLimit(limits?.pool.tokens_per_minute, 'pool_rate'), null),
    daily: effectiveCap(decodeLimit(limits?.pool.daily_budget, 'pool_budget'), limits?.tenant_default_daily_budget),
    monthly: effectiveCap(decodeLimit(limits?.pool.monthly_budget, 'pool_budget'), limits?.tenant_default_monthly_budget),
  });

  async function savePool() {
    if (![poolRpm, poolTpm, poolDaily, poolMonthly].every(isValidLimit)) return;
    savingPool = true;
    const { error } = await adminApi.PUT('/api/v1/admin/workspaces/{id}/rate-limits', {
      params: { path: { id } },
      body: {
        requests_per_minute: encodeLimit(poolRpm, 'pool_rate'),
        tokens_per_minute: encodeLimit(poolTpm, 'pool_rate'),
        daily_budget: encodeLimit(poolDaily, 'pool_budget'),
        monthly_budget: encodeLimit(poolMonthly, 'pool_budget'),
        budget_mode: poolMode,
      },
    });
    if (error) toast.error('Failed to save the workspace pool', { body: extractError(error) });
    else {
      toast.success('Workspace pool saved');
      await Promise.all([loadDetail(), loadLimits()]);
      refreshTestStack();
    }
    savingPool = false;
  }

  async function saveMemberDefaults() {
    if (![defRpm, defTpm, defDaily, defMonthly].every(isValidLimit)) return;
    savingDefaults = true;
    const { error } = await adminApi.PUT('/api/v1/admin/workspaces/{id}/member-defaults', {
      params: { path: { id } },
      body: {
        requests_per_minute: encodeLimit(defRpm, 'member_default'),
        tokens_per_minute: encodeLimit(defTpm, 'member_default'),
        daily_budget: encodeLimit(defDaily, 'member_default'),
        monthly_budget: encodeLimit(defMonthly, 'member_default'),
        budget_mode: defMode,
      },
    });
    if (error) toast.error('Failed to save the member default', { body: extractError(error) });
    else {
      toast.success('Member default saved');
      await loadLimits();
      refreshTestStack();
    }
    savingDefaults = false;
  }

  // Member exceptions.
  const exceptionForm = useDirtyForm();
  let exceptionOpen = $state(false);
  let exceptionUserId = $state<string | null>(null);
  let savingException = $state(false);
  let exceptionError = $state<string | null>(null);
  let removeTarget = $state<string | null>(null);

  function memberEmail(userId: string): string {
    return members.find((m) => m.user_id === userId)?.email ?? userId;
  }

  function openException(userId: string | null) {
    exceptionUserId = userId;
    exceptionError = null;
    exceptionOpen = true;
  }

  async function saveException(userId: string, body: components['schemas']['PutRateLimitOverrideRequest']) {
    savingException = true;
    const { error } = await adminApi.PUT('/api/v1/admin/workspaces/{id}/rate-limit-overrides/{user_id}', {
      params: { path: { id, user_id: userId } },
      body,
    });
    savingException = false;
    if (error) {
      exceptionError = extractError(error, 'Failed to save the exception');
      return;
    }
    exceptionForm.markClean();
    exceptionOpen = false;
    await Promise.all([loadOverrides(), loadLimits()]);
    refreshTestStack();
  }

  async function removeException() {
    const userId = removeTarget;
    removeTarget = null;
    if (!userId) return;
    const { error } = await adminApi.DELETE('/api/v1/admin/workspaces/{id}/rate-limit-overrides/{user_id}', {
      params: { path: { id, user_id: userId } },
    });
    if (error) toast.error('Failed to remove the exception', { body: extractError(error) });
    else {
      await Promise.all([loadOverrides(), loadLimits()]);
      refreshTestStack();
    }
  }

  // One exception cell: the effective value and how it relates to the default.
  function cell(stored: number | null | undefined, def: number | null | undefined, fmt: (n: number) => string) {
    const state = decodeLimit(stored, 'exception');
    const cap = effectiveCap(state, def);
    return { text: cap == null ? 'Unlimited' : fmt(cap), relation: compareToDefault(state, def) };
  }

  // What actually limits one member, as the gateway sees it — read under that
  // member on the Members tab, where someone looking for a person looks. The
  // portal's team page presents the same stack the same way.
  let openMemberId = $state('');
  let testStack = $state<LimitStack | null>(null);
  // Only the latest pick may land: a slower reply for an earlier member must
  // not show their limits under the member now expanded.
  let testGen = 0;
  // Re-read the expanded member after a limit changed, so the panel never
  // shows the stack from before the save.
  function refreshTestStack() {
    if (openMemberId) void loadTestStack(openMemberId);
  }
  function toggleMember(userId: string) {
    void loadTestStack(openMemberId === userId ? '' : userId);
  }
  async function loadTestStack(userId: string) {
    const gen = ++testGen;
    openMemberId = userId;
    testStack = null;
    if (!userId) return;
    const { data, error } = await adminApi.GET('/api/v1/admin/workspaces/{id}/members/{user_id}/effective-limits', {
      params: { path: { id, user_id: userId } },
    });
    if (gen !== testGen) return;
    if (error) toast.error('Failed to load the member\'s limits', { body: extractError(error) });
    else testStack = data ?? null;
  }

  function memberException(userId: string): UserOverride | undefined {
    return overrides.find((o) => o.user_id === userId);
  }
</script>

<div class="mb-4">
  <a href={thref(slug, '/workspaces')} class="text-xs text-(--text-secondary) hover:text-(--text-primary)">‹ All workspaces</a>
</div>

{#if loading}
  <div class="text-sm text-(--text-secondary)">Loading…</div>
{:else if loadError}
  <div class="px-3 py-2 rounded-lg bg-(--error-bg) border border-(--error-border) text-sm text-(--error-text)">{loadError}</div>
{:else if detail}
  <TabbedPage
    title={detail.name}
    subtitle={isAgent
      ? 'Agent workspace — the internal analysis agent runs here. Grant it the providers its model needs; tool policy, guardrail, transforms, and expert analysis are off so it sees and forwards raw content.'
      : isInlineAi
        ? 'Inline AI workspace — external content analyzers authenticate here with the built-in inline-AI key (rotate it on the service account to reveal it). Grant the pass-through providers to intercept (turn them on in the LLM gateway first); the guardrail, tool-policy, and transform profiles assigned here are the inline analysis policy.'
        : detail.description || 'Workspace'}
    tabs={[
      { id: 'overview', label: 'Overview' },
      { id: 'members', label: 'Members' },
      { id: 'access', label: 'Access' },
      { id: 'limits', label: 'Limits' },
    ]}
    activeTab={wsTab.current}
    onTabChange={(t: WsTab) => (wsTab.current = t)}
  >
    {#snippet children(active: WsTab)}
      {#if active === 'overview'}
        <div class="max-w-xl space-y-4">
          <FormField label="Name">
            <TextInput bind:value={editName} />
          </FormField>
          <FormField label="Description">
            <TextInput bind:value={editDescription} placeholder="Optional" />
          </FormField>
          <ToggleSetting
            label="Share activity between members"
            description="Members see each other's usage, sessions and audit for this workspace in the portal. Off by default — each member sees only their own."
            warningWhenOn="Every member can read every other member's prompts and responses in this workspace."
            bind:value={sharesWithMembers}
            saving={savingVisibility}
            onValueChange={saveMemberVisibility}
          />
          <div class="flex items-center justify-between pt-2">
            <button
              onclick={saveOverview}
              disabled={savingName || !editName.trim()}
              class="px-4 py-1.5 text-sm rounded-lg bg-(--accent) text-(--accent-fg) hover:bg-(--accent-hover) disabled:opacity-50"
            >{savingName ? 'Saving…' : 'Save'}</button>
            {#if !isDefault && !isAgent && !isInlineAi}
              <button
                onclick={() => (confirmDelete = true)}
                class="px-4 py-1.5 text-sm rounded-lg text-(--error) hover:bg-(--error-bg) border border-(--error)/20"
              >Delete workspace</button>
            {/if}
          </div>
        </div>
      {:else if active === 'members'}
        <div class="space-y-6">
          <!-- Add member: searchable picker (scales past a long native select). -->
          <div class="flex flex-col sm:flex-row gap-2 sm:items-end max-w-2xl">
            <div class="flex-1">
              <FormField label="Add member">
                <EntityPicker search={searchUsers} bind:value={pickedUser} placeholder="Search users by email or name…" emptyText="No matching users" />
              </FormField>
            </div>
            <div class="w-40">
              <FormField label="Role">
                <SelectInput bind:value={addMemberRole}>
                  <option value="member">member</option>
                  <option value="manager">manager</option>
                </SelectInput>
              </FormField>
            </div>
            <button onclick={addMember} disabled={!pickedUser} class="px-4 py-2 text-sm rounded-lg bg-(--accent) text-(--accent-fg) hover:bg-(--accent-hover) disabled:opacity-50">Add</button>
          </div>

          {#if members.length === 0}
            <EmptyState title="No members" body="Add a user to this workspace." />
          {:else}
            <div class="bg-(--bg-card) rounded-xl border border-(--border) overflow-hidden">
              <table class="w-full text-sm">
                <thead><tr class="border-b border-(--border) bg-(--bg-primary)/30">
                  <th class="px-6 py-2.5 text-left text-xs text-(--text-secondary) uppercase tracking-wider">Email</th>
                  <th class="px-6 py-2.5 text-left text-xs text-(--text-secondary) uppercase tracking-wider">Role</th>
                  <th class="px-6 py-2.5 text-right text-xs text-(--text-secondary) uppercase tracking-wider">Actions</th>
                </tr></thead>
                <tbody>
                  {#each members as m (m.user_id)}
                    {@const exception = memberException(m.user_id)}
                    <tr class="border-b border-(--border) hover:bg-(--bg-elevated)">
                      <td class="px-6 py-3 text-(--text-primary)">
                        <!-- Expanding a member is how you find out why they
                             were throttled: the whole stack, under the person
                             it is about. -->
                        <button
                          onclick={() => toggleMember(m.user_id)}
                          class="inline-flex items-center gap-1.5 hover:text-(--accent)"
                          aria-expanded={openMemberId === m.user_id}
                          data-testid="member-expand"
                        >
                          <span class="inline-flex transition-transform {openMemberId === m.user_id ? 'rotate-90' : ''}"><Icon name="chevronRight" size="sm" tone="neutral" /></span>
                          {m.email}
                        </button>
                        {#if m.display_name}<span class="text-(--text-secondary) text-xs ml-1">({m.display_name})</span>{/if}
                        {#if exception}<TagBadge color="teal" class="ml-1.5" title="This member has a limit exception">exception</TagBadge>{/if}
                      </td>
                      <td class="px-6 py-3 w-40">
                        <SelectInput value={m.role} onchange={(e) => changeMemberRole(m.user_id, (e.currentTarget as HTMLSelectElement).value)}>
                          <option value="member">member</option>
                          <option value="manager">manager</option>
                        </SelectInput>
                      </td>
                      <td class="px-6 py-3 text-right whitespace-nowrap">
                        <a href={thref(slug, `/users?owner=${m.user_id}`)} class="text-xs text-(--accent) hover:underline mr-3" title="View this member's keys">Keys</a>
                        <button onclick={() => removeMember(m.user_id)} class="text-xs text-(--error) hover:underline">Remove</button>
                      </td>
                    </tr>
                    {#if openMemberId === m.user_id}
                      <tr class="border-b border-(--border) bg-(--bg-primary)/20">
                        <td colspan="3" class="px-6 py-4" data-testid="member-limits">
                          <div class="flex items-center justify-between mb-2">
                            <span class="text-xs font-semibold text-(--text-secondary) uppercase tracking-wider">What limits this member here</span>
                            <button
                              onclick={() => openException(m.user_id)}
                              disabled={!overridesComplete || !limits}
                              class="text-xs text-(--accent) hover:underline disabled:opacity-50"
                            >{exception ? 'Edit exception' : 'Add exception'}</button>
                          </div>
                          {#if testStack}
                            <EffectiveLimitStack stack={testStack} />
                          {:else}
                            <p class="text-sm text-(--text-secondary)">Loading…</p>
                          {/if}
                        </td>
                      </tr>
                    {/if}
                  {/each}
                </tbody>
              </table>
            </div>
          {/if}

          <!-- OIDC auto-membership: about who joins, so it lives with Members. -->
          <div class="space-y-4 pt-4 border-t border-(--border) max-w-xl">
            <div>
              <h3 class="text-sm font-semibold text-(--text-primary)">OIDC auto-membership</h3>
              <p class="text-xs text-(--text-secondary)">Auto-add users to this workspace when their IdP claim matches the pattern at login.</p>
            </div>
            <FormField label="OIDC claim name" help="The ID-token claim to match — one value or a list: groups on most providers, group on AD FS; under proxy (header) sign-in always groups. Name a claim your directory sets, never one users can edit.">
              <TextInput bind:value={editClaimName} placeholder="groups" mono />
            </FormField>
            <FormField label="OIDC claim pattern" help="POSIX regular expression matched against the claim value.">
              <TextInput bind:value={editClaimPattern} placeholder="^eng-.*$" mono />
            </FormField>
            <button onclick={saveOidc} disabled={savingOidc} class="px-4 py-1.5 text-sm rounded-lg bg-(--accent) text-(--accent-fg) hover:bg-(--accent-hover) disabled:opacity-50">{savingOidc ? 'Saving…' : 'Save OIDC mapping'}</button>
          </div>
        </div>
      {:else if active === 'access'}
        <div class="space-y-8">
          <GrantList
            title="LLM providers"
            testid="grants-providers"
            emptyTitle="No LLM providers granted"
            granted={grantedProviders}
            candidates={providerCandidates}
            emptyText="Members of this workspace reach no LLM provider."
            addPlaceholder="Search providers to grant…"
            unavailableNote={offPassthroughsHidden > 0
              ? `${offPassthroughsHidden} pass-through provider${offPassthroughsHidden === 1 ? ' is' : 's are'} not offered: ${offPassthroughsHidden === 1 ? 'its server is' : 'their servers are'} off in the LLM gateway.`
              : ''}
            onadd={addProvider}
            onremove={removeProvider}
            confirmRemove={confirmProviderRemoval}
          />
          <GrantList
            title="MCP servers"
            testid="grants-mcp"
            emptyTitle="No MCP servers granted"
            granted={grantedMcp}
            candidates={mcpCandidates}
            emptyText="Members of this workspace reach no MCP server."
            addPlaceholder="Search MCP servers to grant…"
            unavailableNote={mcpOauthIncomplete > 0
              ? `${mcpOauthIncomplete} server${mcpOauthIncomplete === 1 ? ' is' : 's are'} not offered: the OAuth client is incomplete — set the Client ID and Secret on the upstream first.`
              : ''}
            onadd={addMcp}
            onremove={removeMcp}
          />
          <GrantList
            title="A2A agents"
            testid="grants-a2a"
            emptyTitle="No A2A agents granted"
            granted={grantedA2a}
            candidates={a2aCandidates}
            emptyText="Members of this workspace reach no A2A agent."
            addPlaceholder="Search agents to grant…"
            onadd={addA2a}
            onremove={removeA2a}
          />

          <!-- Per-kind profile assignment -->
          <WorkspaceProfilePicker
            kind="tools"
            label="Tool policy"
            workspaceId={id}
            current={assignmentState('tools')}
            profiles={profileLists.tools}
            manageHref={(pid) => `/policy/profiles/${pid}`}
            onchanged={loadDetail}
          />
          <WorkspaceProfilePicker
            kind="guardrail"
            label="Guardrail"
            workspaceId={id}
            current={assignmentState('guardrail')}
            profiles={profileLists.guardrail}
            manageHref={(pid) => `/guardrail/profiles/${pid}`}
            onchanged={loadDetail}
          />
          <WorkspaceProfilePicker
            kind="transform"
            label="Transforms"
            workspaceId={id}
            current={assignmentState('transform')}
            profiles={profileLists.transform}
            manageHref={(pid) => `/transforms/profiles/${pid}`}
            onchanged={loadDetail}
          />
          <WorkspaceProfilePicker
            kind="expert"
            label="Experts"
            workspaceId={id}
            current={assignmentState('expert')}
            profiles={profileLists.expert}
            manageHref={(pid) => `/experts/profiles/${pid}`}
            onchanged={loadDetail}
          />
        </div>
      {:else if active === 'limits'}
        <div class="space-y-5 max-w-3xl">
          <p class="text-xs text-(--text-secondary) px-3 py-2 rounded-lg border border-(--border) bg-(--bg-card)">
            <strong class="text-(--text-primary)">Organisation → Workspace pool → Member → Key</strong> — every limit applies; the tightest one stops a request first.
          </p>

          <!-- The pool, member default and exceptions need the limits read; the
               sections below them do not, and stay usable if it failed. -->
          {#if limits}
          {@const l = limits}
          <!-- Workspace pool: shared by all members -->
          <section class="rounded-xl border border-(--border) bg-(--bg-card) p-4 space-y-4" data-testid="limits-pool">
            <div class="flex items-baseline justify-between">
              <h3 class="text-sm font-semibold text-(--text-primary)">Workspace pool</h3>
              <span class="text-xs text-(--text-secondary)">shared by all members</span>
            </div>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-x-4 gap-y-3">
              <LimitField label="Requests / minute" bind:limit={poolRpm} encoding="pool_rate" />
              <LimitField label="Tokens / minute" bind:limit={poolTpm} encoding="pool_rate" />
              <LimitField label="Daily budget ({accountingCurrency()})" bind:limit={poolDaily} encoding="pool_budget" step={0.01} inheritedLabel={`tenant default: ${tenantDefaultLabel(l.tenant_default_daily_budget)}`} />
              <LimitField label="Monthly budget ({accountingCurrency()})" bind:limit={poolMonthly} encoding="pool_budget" step={0.01} inheritedLabel={`tenant default: ${tenantDefaultLabel(l.tenant_default_monthly_budget)}`} />
            </div>
            <FormField label="Budget mode">
              <BudgetModeToggle bind:mode={poolMode} />
              <p class="text-[10px] text-(--text-secondary) mt-1">{poolMode === 'alert_only' ? 'Over the budget, a notification fires but nothing is refused.' : 'Over the budget, requests are refused.'}</p>
            </FormField>
            {#if detail?.usage && (poolCaps.daily != null || poolCaps.monthly != null)}
              <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <LimitMeter label="Daily spend (fleet estimate)" used={detail.usage.daily_spent} cap={poolCaps.daily} fmt={money} />
                <LimitMeter label="Monthly spend (fleet estimate)" used={detail.usage.monthly_spent} cap={poolCaps.monthly} fmt={money} />
              </div>
            {/if}
            <button onclick={savePool} disabled={savingPool || ![poolRpm, poolTpm, poolDaily, poolMonthly].every(isValidLimit)} class="px-4 py-1.5 text-sm rounded-lg bg-(--accent) text-(--accent-fg) hover:bg-(--accent-hover) disabled:opacity-50">{savingPool ? 'Saving…' : 'Save pool'}</button>
          </section>

          <!-- Each member: default -->
          <section class="rounded-xl border border-(--border) bg-(--bg-card) p-4 space-y-4" data-testid="limits-member-default">
            <div class="flex items-baseline justify-between">
              <h3 class="text-sm font-semibold text-(--text-primary)">Each member — default</h3>
              <span class="text-xs text-(--text-secondary)">applies to every member separately</span>
            </div>
            {#if !l.member_defaults_allowed}
              <Callout severity="info" title="No member default here">
                One service member carries all of this workspace's traffic, so a per-member limit would throttle all of it at once. Use the workspace pool.
              </Callout>
            {:else}
              <div class="grid grid-cols-1 md:grid-cols-2 gap-x-4 gap-y-3">
                <LimitField label="Requests / minute" bind:limit={defRpm} encoding="member_default" />
                <LimitField label="Tokens / minute" bind:limit={defTpm} encoding="member_default" />
                <LimitField label="Daily budget ({accountingCurrency()})" bind:limit={defDaily} encoding="member_default" step={0.01} />
                <LimitField label="Monthly budget ({accountingCurrency()})" bind:limit={defMonthly} encoding="member_default" step={0.01} />
              </div>
              <FormField label="Budget mode">
                <BudgetModeToggle bind:mode={defMode} />
              </FormField>
              <p class="text-xs text-(--text-secondary)">{l.member_count} member{l.member_count === 1 ? '' : 's'} · {l.exception_count} with an exception. A value above the pool changes nothing — the pool still applies.</p>
              <button onclick={saveMemberDefaults} disabled={savingDefaults || ![defRpm, defTpm, defDaily, defMonthly].every(isValidLimit)} class="px-4 py-1.5 text-sm rounded-lg bg-(--accent) text-(--accent-fg) hover:bg-(--accent-hover) disabled:opacity-50">{savingDefaults ? 'Saving…' : 'Save member default'}</button>
            {/if}
          </section>

          <!-- Member exceptions -->
          <section class="rounded-xl border border-(--border) bg-(--bg-card) p-4 space-y-3" data-testid="limits-exceptions">
            <div class="flex items-center justify-between">
              <h3 class="text-sm font-semibold text-(--text-primary)">Member exceptions</h3>
              <button onclick={() => openException(null)} disabled={!overridesComplete} class="px-3 py-1.5 text-sm rounded-lg bg-(--accent) text-(--accent-fg) hover:bg-(--accent-hover) disabled:opacity-50">+ Add exception</button>
            </div>
            <p class="text-xs text-(--text-secondary)">
              An exception replaces the member default for one member — higher or lower. The pool and the
              organisation budget still apply. To see why one person was throttled, open them on the
              <button onclick={() => (wsTab.current = 'members')} class="text-(--accent) hover:underline">Members</button>
              tab: every limit that applies to them is listed there, with the one that binds.
            </p>
            {#if overridesFailed}
              <p class="text-sm text-(--text-secondary)">
                The exceptions could not be loaded.
                <button onclick={loadOverrides} class="text-(--accent) hover:underline">Retry</button>
              </p>
            {:else if overrides.length === 0}
              <p class="text-sm text-(--text-secondary)">No exceptions — every member is on the default.</p>
            {:else}
              <div class="overflow-x-auto rounded-lg border border-(--border)">
                <table class="w-full text-sm">
                  <thead><tr class="border-b border-(--border) bg-(--bg-primary)/30">
                    <th class="px-3 py-2 text-left text-xs text-(--text-secondary) uppercase tracking-wider">Member</th>
                    <th class="px-3 py-2 text-right text-xs text-(--text-secondary) uppercase tracking-wider">Req/min</th>
                    <th class="px-3 py-2 text-right text-xs text-(--text-secondary) uppercase tracking-wider">Tokens/min</th>
                    <th class="px-3 py-2 text-right text-xs text-(--text-secondary) uppercase tracking-wider">Daily</th>
                    <th class="px-3 py-2 text-right text-xs text-(--text-secondary) uppercase tracking-wider">Monthly</th>
                    <th class="px-3 py-2"></th>
                  </tr></thead>
                  <tbody>
                    {#each overrides as o (o.user_id)}
                      {@const cells = [
                        cell(o.requests_per_minute, l.member_defaults.requests_per_minute, count),
                        cell(o.tokens_per_minute, l.member_defaults.tokens_per_minute, formatTokens),
                        cell(o.daily_budget, l.member_defaults.daily_budget, money),
                        cell(o.monthly_budget, l.member_defaults.monthly_budget, money),
                      ]}
                      <tr class="border-b border-(--border) last:border-0">
                        <td class="px-3 py-2 text-(--text-primary)">
                          {memberEmail(o.user_id)}{#if o.budget_mode === 'alert_only'} <TagBadge color="amber">alert only</TagBadge>{/if}
                          {#if o.set_via}<div class="text-[10px] text-(--text-secondary)">set by {o.set_by_email ?? 'an administrator'}{o.set_via === 'manager' ? ' · workspace manager' : ''}</div>{/if}
                        </td>
                        {#each cells as c, i (i)}
                          <td class="px-3 py-2 text-right font-mono text-(--text-secondary) whitespace-nowrap">
                            {c.text}
                            {#if c.relation === 'inherits'}<span class="text-[10px] text-(--text-secondary)"> (default)</span>
                            {:else if c.relation === 'raised'}<TagBadge color="teal" title="Raised above the default">▲ raised</TagBadge>
                            {:else if c.relation === 'lowered'}<TagBadge color="amber" title="Lowered below the default">▼ lowered</TagBadge>{/if}
                          </td>
                        {/each}
                        <td class="px-3 py-2 text-right whitespace-nowrap">
                          <button onclick={() => openException(o.user_id)} disabled={!overridesComplete} class="text-xs text-(--accent) hover:underline mr-3 disabled:opacity-50">Edit</button>
                          <button onclick={() => (removeTarget = o.user_id)} disabled={!overridesComplete} class="text-xs text-(--error) hover:underline disabled:opacity-50">Remove</button>
                        </td>
                      </tr>
                    {/each}
                  </tbody>
                </table>
              </div>
            {/if}
          </section>

          {:else}
          <p class="text-sm text-(--text-secondary)">
            The workspace limits could not be loaded.
            <button onclick={loadLimits} class="text-(--accent) hover:underline">Retry</button>
          </p>
          {/if}

          <!-- Priority under load -->
          <section class="rounded-xl border border-(--border) bg-(--bg-card) p-4 space-y-3" data-testid="limits-qos">
            <h3 class="text-sm font-semibold text-(--text-primary)">Priority under load</h3>
            <p class="text-xs text-(--text-secondary)">
              Limits decide what this workspace may use; priority decides who goes first when a model
              has nothing free. It changes nothing while an upstream has capacity to spare.
            </p>
            <FormField label="Class this workspace's keys run as" for="ws-qos-class">
              <SelectInput id="ws-qos-class" bind:value={editQosClassId}>
                <option value="">Inherit the tenant default</option>
                {#each qosClasses as c (c.id)}
                  <option value={c.id}>{c.name}</option>
                {/each}
              </SelectInput>
            </FormField>
            <FormField
              label="Share of a busy model"
              for="ws-qos-weight"
              help="Against the other workspaces waiting on the same model. 1 is an equal share; 4 means this workspace is served roughly four times as much while both are backlogged."
            >
              <NumberInput id="ws-qos-weight" bind:value={editFairnessWeight} min={1} max={100} />
            </FormField>
            <button
              onclick={saveQos}
              disabled={savingQos}
              class="px-3 py-1.5 bg-(--accent) hover:bg-(--accent-hover) text-(--accent-fg) text-sm font-medium rounded-lg transition-colors disabled:opacity-50"
            >
              {savingQos ? 'Saving…' : 'Save priority'}
            </button>
          </section>

          <!-- Organisation budget -->
          <section class="rounded-xl border border-(--border) bg-(--bg-card) p-4 space-y-3">
            <h3 class="text-sm font-semibold text-(--text-primary)">Organisation budget</h3>
            <ToggleSetting
              label="Count this workspace's spend against the organisation budget"
              description="On by default. Turn it off for traffic the organisation does not pay for — inline AI, where each call is funded on the end user's own provider account, or any workspace you bill elsewhere."
              bind:value={countsTowardTenantBudget}
              saving={savingTenantBudgetFlag}
              onValueChange={saveTenantBudgetFlag}
            />
            <p class="text-xs text-(--text-secondary)">
              Off removes the workspace from the organisation ceiling entirely: its requests neither
              add to it nor are blocked by it. The workspace's own limits above still apply.
            </p>
          </section>
        </div>
      {/if}
    {/snippet}
  </TabbedPage>
{/if}

<!-- Only over a complete exception list: seeded from a partial or stale one,
     the modal would open blank over an exception and the save would wipe it. -->
{#if limits && overridesComplete}
  <MemberExceptionModal
    open={exceptionOpen}
    form={exceptionForm}
    {members}
    userId={exceptionUserId}
    exceptions={overrides}
    defaults={limits.member_defaults}
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
{/if}

<ConfirmDialog
  open={removeTarget !== null}
  title="Remove exception"
  message={removeTarget ? `${memberEmail(removeTarget)} goes back to the member default.` : ''}
  confirmLabel="Remove"
  destructive
  onconfirm={removeException}
  oncancel={() => (removeTarget = null)}
/>

<ConfirmDialog
  open={confirmDelete}
  title="Delete workspace"
  message="Delete this workspace? Its keys are revoked and members lose access. This cannot be undone."
  confirmLabel="Delete"
  destructive
  onconfirm={deleteWorkspace}
  oncancel={() => (confirmDelete = false)}
/>
