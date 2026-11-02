<script lang="ts">
  import type { LayoutProps } from './$types';
  import { untrack } from 'svelte';
  import SourceLink from '#lib/components/SourceLink.svelte';
  import RefreshButton from '#lib/components/RefreshButton.svelte';
  import { page } from '$app/state';
  import { onRefresh } from '#lib/hooks.svelte.js';
  import { isLiveView } from '#lib/liveViews.js';
  import { isPlatformOperator } from '#lib/home.js';
  import PeriodSelector from '#lib/components/PeriodSelector.svelte';
  import WorkspaceSelector from '#lib/components/WorkspaceSelector.svelte';
  import ChangelogModal from '#lib/components/ChangelogModal.svelte';
  import { consoleScope, profileLists, reconcileWorkspace } from '#lib/scope.svelte.js';
  import { adminApi, setApiSlug } from '#lib/api-client.js';
  import { setAccountingCurrency } from '#lib/currency.svelte.js';
  import SidebarNav from '#lib/components/nav/SidebarNav.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import { adminNav, breadcrumbFor, filterNavForViewer, scopeNav } from '#lib/nav.js';
  import { thref, untenant } from '#lib/tenant.js';

  let { children, data, params }: LayoutProps = $props();

  let slug = $derived(params.slug);

  // The path-scoped session cookie lives at /t/<slug>; the admin API client must
  // prefix its requests with it. Set synchronously at script init so the first
  // hydration render has it before any child load/$effect issues an adminApi
  // call, then keep it in sync on client-side slug navigation.
  // svelte-ignore state_referenced_locally
  setApiSlug(params.slug);
  $effect.pre(() => {
    setApiSlug(params.slug);
  });

  // Sidebar state from cookie — available during SSR, so zero flash on refresh.
  // svelte-ignore state_referenced_locally
  let collapsed = $state(data.sidebarCollapsed ?? false);

  function toggleSidebar() {
    collapsed = !collapsed;
    document.cookie = `sidebar_collapsed=${collapsed}; path=/; max-age=${60 * 60 * 24 * 365}; SameSite=Lax${location.protocol === 'https:' ? '; Secure' : ''}`;
  }

  let isSystemTenant = $derived(data.user?.tenant_slug === 'system');

  // The header period + workspace selectors are the *dashboard* live lens — they
  // render only on the dashboard surface (`/dashboard/*` and the dashboard-shaped
  // super-admin `/admin/overview`). Investigative pages own inline filters.
  let showHeaderScope = $derived(
    !!page.route.id &&
    (page.route.id.startsWith('/t/[slug]/dashboard') || page.route.id === '/t/[slug]/admin/overview')
  );

  // Config sync status indicator (tenant-scoped).
  let syncStatus = $state<{ all_synced: boolean } | null>(null);
  async function loadSyncStatus() {
    const { data: status } = await adminApi.GET('/api/v1/admin/config-sync/tenant-status').catch(() => ({ data: null }));
    if (status) syncStatus = status;
  }
  // Workspaces back the dashboard header selector + the inline audit filter.
  let workspacesGen = 0;
  async function loadWorkspaces() {
    const tenant = slug;
    const gen = ++workspacesGen;
    const { data: res } = await adminApi
      .GET('/api/v1/admin/workspaces', { params: { query: { limit: 200 } } })
      .catch(() => ({ data: null }));
    // Only the latest read lands — never an older one, nor one for a tenant
    // since left. A failed read keeps the list: an empty one means "every
    // workspace, the agent's included", which would silently widen every
    // scoped query (another tenant's list is never read here — `TenantHeld`).
    if (gen !== workspacesGen || tenant !== slug || !res) return;
    const lite = res.items.map((w) => ({
      id: w.id,
      name: w.name,
      role: w.role,
    }));
    consoleScope.workspaces = lite;
    reconcileWorkspace(lite);
  }

  // Every money figure the console reports in tenant money — budgets, spend
  // aggregates, dashboards — is denominated in the tenant's accounting
  // currency. Loaded here, from the effect below, so the value is never written
  // during SSR (module state is shared across requests on the server).
  // Fetched once per tenant per session, not per mount: the accounting currency
  // is tenant-static config, and the effect below re-runs on every navigation
  // and every manual refresh. Re-asking for a value that cannot have changed
  // adds a request to every page load in the console for nothing.
  let currencyLoadedFor = '';
  async function loadAccountingCurrency() {
    if (currencyLoadedFor === slug) return;
    currencyLoadedFor = slug;
    const { data: pricing } = await adminApi
      .GET('/api/v1/admin/settings/pricing')
      .catch(() => ({ data: null }));
    if (pricing) setAccountingCurrency(pricing.accounting_currency);
    else currencyLoadedFor = '';
  }

  // Each kind's profiles back its pickers: Tool-policy, Guardrail and
  // Transform on the workspace (Transform also the programs scope selector),
  // Experts on the workspace and the experts-page membership editor.
  function loadTenantContext() {
    loadSyncStatus();
    loadWorkspaces();
    loadAccountingCurrency();
    // The profile lists feed the pickers of editing pages only: a viewing page
    // (and its every auto-refresh tick) does not read them.
    if (isLiveView(page.route.id)) return;
    profileLists.loadAll();
  }
  // On every navigation — what this effect tracks is named here, and the
  // loaders run untracked, so nothing they read or land re-runs it — and on
  // every refresh.
  $effect(() => {
    void slug;
    void page.route.id;
    if (data?.user) untrack(loadTenantContext);
  });
  onRefresh(() => {
    if (data?.user) loadTenantContext();
  });

  let filteredNav = $derived(
    scopeNav(
      filterNavForViewer(adminNav, {
        isSystemTenant,
        isSuperAdmin: isPlatformOperator(data.user),
        isAppliance: !!data.user?.appliance,
      }),
      (href) => thref(slug, href)
    )
  );

  // The route id is tenant-prefixed (`/t/[slug]/…`) like the pathname.
  let breadcrumbs = $derived(
    breadcrumbFor(adminNav, untenant(page.url.pathname), page.route.id?.replace(/^\/t\/\[slug\]/, '') || null),
  );
</script>

<ChangelogModal />
<div class="flex min-h-screen">
  <!-- Sidebar -->
  <nav
    class="fixed top-0 left-0 h-dvh flex flex-col border-r border-(--border) bg-(--bg-secondary) transition-all duration-300 z-30"
    style="width: {collapsed ? '4.5rem' : '16rem'}"
  >
    <!-- Header: logo + collapse toggle -->
    <div class="flex items-center gap-3 px-4 h-16 border-b border-(--border) shrink-0">
      <button
        onclick={toggleSidebar}
        class="w-8 h-8 rounded-lg bg-(--accent) flex items-center justify-center shrink-0 hover:bg-(--accent-hover) transition-all"
        title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
      >
        <Icon name="brand" color="var(--accent-fg)" />
      </button>
      {#if !collapsed}
        <div class="overflow-hidden whitespace-nowrap flex-1">
          <h1 class="text-lg font-bold text-(--text-primary) leading-tight">Streamscope AI</h1>
          <p class="text-[10px] text-(--text-secondary) leading-tight">Admin Console</p>
        </div>
      {/if}
    </div>

    <!-- Scrollable body: nav tree + version pushed to bottom -->
    <div class="flex-1 min-h-0 flex flex-col overflow-y-auto overflow-x-visible">
      <SidebarNav nav={filteredNav} {collapsed} />
      <div class="flex-1"></div>
      {#if !collapsed}
        <div class="border-t border-(--border) p-3 shrink-0">
          <SourceLink />
        </div>
      {/if}
    </div>
  </nav>

  <!-- Main area -->
  <div class="flex-1 flex flex-col min-w-0 transition-all duration-300" style="margin-left: {collapsed ? '4.5rem' : '16rem'}">
    <!-- Header bar -->
    <header class="h-16 border-b border-(--border) bg-(--bg-secondary)/50 backdrop-blur-xs flex items-center justify-between px-8 sticky top-0 z-20">
      <nav class="flex items-center gap-2 text-sm">
        {#each breadcrumbs as crumb, i (crumb.href)}
          {#if i > 0}
            <Icon name="chevronRight" size="sm" tone="neutral" />
          {/if}
          {#if i === breadcrumbs.length - 1}
            <span class="text-(--text-primary) font-medium">{crumb.label}</span>
          {:else}
            <a href={crumb.href ? thref(slug, crumb.href) : crumb.href} class="text-(--text-secondary) hover:text-(--text-primary) transition-colors">
              {crumb.label}
            </a>
          {/if}
        {/each}
      </nav>

      <div class="flex items-center gap-2">
        {#if data.user?.role === 'read_only'}
          <span class="inline-flex items-center gap-1.5 px-2 py-1 rounded-md text-[10px] font-medium text-(--warning-text) bg-(--warning-bg) border border-(--warning-border)" title="Your account is read-only — changes are disabled.">
            <Icon name="lock" size="sm" tone="warning" />
            Read-only
          </span>
        {/if}
        {#if syncStatus}
          <span class="inline-flex items-center gap-1.5 px-2 py-1 rounded-md text-[10px] font-medium {syncStatus.all_synced ? 'text-(--success)' : 'text-(--warning)'}" title="Config sync: whether every live proxy holds this tenant's current config">
            <span class="w-1.5 h-1.5 rounded-full bg-current"></span>
            {syncStatus.all_synced ? 'Synced' : 'Syncing…'}
          </span>
        {/if}
        {#if showHeaderScope}
          <WorkspaceSelector />
          <PeriodSelector selected={consoleScope.period} onchange={(v) => (consoleScope.period = v)} />
        {/if}
        <RefreshButton
          label="Refresh"
          title="Refresh now (R)"
          autoRefresh={{
            live: isLiveView(page.route.id),
            label: 'auto',
            name: 'Auto-refresh (Shift+R)',
            startLabel: 'Auto-refresh every 30 s for an hour (Shift+R)',
            stopLabel: 'Stop auto-refresh (Shift+R)',
            pausedLabel: 'paused',
            pausedTitle: 'Auto-refresh waits while a dialog is open or a field has the cursor (click to stop it)',
            manualTitle: 'Auto-refresh runs on viewing pages only; on this page ↻ refreshes once',
            heldHereTitle: 'Auto-refresh holds on this page and resumes on a viewing page; its hour keeps counting (click to stop it)',
          }}
        />
      </div>

      {#if data?.user}
        <div class="flex items-center gap-2">
          <!-- User avatar + name -->
          <div class="flex items-center gap-2.5 px-2.5 py-1.5 rounded-lg">
            <div class="w-7 h-7 rounded-full bg-(--accent)/15 flex items-center justify-center shrink-0">
              <Icon name="user" size="sm" color="var(--accent)" />
            </div>
            <div class="flex flex-col">
              <span class="text-sm text-(--text-primary) font-medium leading-tight">{data.user.email.split('@')[0] || data.user.email}</span>
              {#if data.user.tenant_name}
                <span class="text-[10px] text-(--text-secondary) leading-tight">{data.user.tenant_name}</span>
              {/if}
            </div>
          </div>

          <!-- Divider -->
          <div class="w-px h-5 bg-(--border)"></div>

          <!-- Sign out button — per-tenant: ends only this tenant's session. -->
          <form method="POST" action={thref(slug, '/logout')}>
            <button
              type="submit"
              class="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-(--text-secondary) hover:text-(--error) hover:bg-(--error-bg) transition-all text-sm"
              title="Sign out"
            >
              <Icon name="signOut" size="sm" tone="neutral" />
              <span>Sign out</span>
            </button>
          </form>
        </div>
      {/if}
    </header>

    <!-- Page content, mounted afresh for each tenant: nothing a page set up
         for one tenant (its filters, the remembered lens it seeded) carries
         over to the next. -->
    <main class="flex-1 p-8 overflow-hidden">
      {#key slug}
        {@render children()}
      {/key}
    </main>
  </div>
</div>
