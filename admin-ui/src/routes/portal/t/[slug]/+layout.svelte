<script lang="ts">
  import type { LayoutProps } from './$types';
  import { onMount } from 'svelte';
  import { invalidateAll } from '$app/navigation';
  import { refreshCycle } from '#lib/refreshCycle.svelte.js';
  import { hiddenPages, pageHidden, type PortalPage } from '#lib/portalPages.svelte.js';
  import SourceLink from '#lib/components/SourceLink.svelte';
  import RefreshButton from '#lib/components/RefreshButton.svelte';
  import { portalScope, reconcilePortalWorkspace } from '#lib/scope.svelte.js';
  import PortalWorkspaceSelector from '#lib/components/PortalWorkspaceSelector.svelte';
  import { setPortalSlug } from '#lib/portal-client.js';
  import { setAccountingCurrency } from '#lib/currency.svelte.js';
  import SidebarNav from '#lib/components/nav/SidebarNav.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import LocaleSelector from '#lib/components/LocaleSelector.svelte';
  import { buildPortalNav, filterNavForViewer, scopeNav } from '#lib/nav.js';
  import { pthref } from '#lib/tenant.js';
  import { m } from '#lib/paraglide/messages.js';

  let { children, data, params }: LayoutProps = $props();

  let slug = $derived(params.slug);

  // The path-scoped portal_session cookie lives at /portal/t/<slug>; the portal
  // API client must prefix its requests with it. Set synchronously at script init
  // (before any child load/$effect issues a portalApi call), then keep in sync.
  // svelte-ignore state_referenced_locally
  setPortalSlug(params.slug);
  $effect.pre(() => {
    setPortalSlug(params.slug);
  });

  // Sidebar state from cookie — available during SSR, so zero flash on refresh.
  // svelte-ignore state_referenced_locally
  let collapsed = $state(data.sidebarCollapsed ?? false);

  function toggleSidebar() {
    collapsed = !collapsed;
    document.cookie = `sidebar_collapsed=${collapsed}; path=/; max-age=${60 * 60 * 24 * 365}; SameSite=Lax${location.protocol === 'https:' ? '; Secure' : ''}`;
  }

  // Portal sidebar — same component, different nav tree. Of the visibility
  // flags `managerOnly` applies (the portal has no system tenant and no
  // super-admin): shown to a manager of ANY of their workspaces, read from the
  // server-loaded memberships so the server render already has it (the Team
  // page itself follows the header workspace) — and the pages hidden for the
  // viewer's workspaces are left out. Hrefs scoped to /portal/t/<slug>.
  const PAGES: PortalPage[] = ['sessions', 'requests'];
  let filteredPortalNav = $derived(
    scopeNav(
      filterNavForViewer(buildPortalNav(), {
        isSystemTenant: false,
        isSuperAdmin: false,
        isManager: (data?.portalWorkspaces ?? []).some((w) => w.role === 'manager'),
        hiddenPages: PAGES.filter((p) => pageHidden(p, data ?? {})),
      }),
      (href) => pthref(slug, href)
    )
  );

  // Portal active-workspace context — hydrated from the server-loaded memberships
  // (the `me` query, Default-first). The active id reconciles against this list so
  // a stale/dropped membership falls back to the first.
  $effect(() => {
    const list = data?.portalWorkspaces ?? [];
    portalScope.workspaces = list;
    reconcilePortalWorkspace(list);
  });

  // Every figure the portal renders in tenant money — key budgets, spend vs cap,
  // usage totals — is denominated in the tenant's accounting currency. Written
  // from an effect, never during load, so the value stays at its default on the
  // server (module state is shared across requests there). An audit row is
  // rendered with its OWN `cost_currency` instead: it records what the ledger
  // said when it was written, which this setting can no longer restate.
  $effect(() => {
    setAccountingCurrency(data?.accountingCurrency);
  });

  // The identity this layout loaded — the memberships, what is hidden — is a
  // copy of the gateway's answer. It is re-read when the gateway refuses a
  // route as hidden (`hiddenPages`) and on every Refresh, so the sidebar and
  // the pages follow an administrator's change without a reload.
  onMount(() => {
    const withdraw = hiddenPages.rereadWith(invalidateAll);
    const unlisten = refreshCycle.listen(() => void hiddenPages.recheck());
    return () => {
      withdraw();
      unlisten();
    };
  });

</script>

<!-- Portal layout: same SidebarNav as admin, no top-bar tabs. -->
<div class="flex min-h-screen">
  <nav
    class="fixed top-0 left-0 h-dvh flex flex-col border-r border-(--border) bg-(--bg-secondary) transition-all duration-300 z-30"
    style="width: {collapsed ? '4.5rem' : '16rem'}"
  >
    <div class="flex items-center gap-3 px-4 h-16 border-b border-(--border) shrink-0">
      <button
        onclick={toggleSidebar}
        class="w-8 h-8 rounded-lg bg-(--accent) flex items-center justify-center shrink-0 hover:bg-(--accent-hover) transition-all"
        title={collapsed ? m.portal_layout_expand_sidebar() : m.portal_layout_collapse_sidebar()}
      >
        <Icon name="brand" color="var(--accent-fg)" />
      </button>
      {#if !collapsed}
        <div class="overflow-hidden whitespace-nowrap flex-1">
          <h1 class="text-lg font-bold text-(--text-primary) leading-tight">Streamscope AI</h1><!-- i18n-ok: product name -->
          <p class="text-[10px] text-(--text-secondary) leading-tight">{m.portal_layout_subtitle()}</p>
        </div>
      {/if}
    </div>
    <div class="flex-1 min-h-0 flex flex-col overflow-y-auto overflow-x-visible">
      <SidebarNav nav={filteredPortalNav} {collapsed} />
      <div class="flex-1"></div>
      {#if !collapsed}
        <div class="border-t border-(--border) p-3 shrink-0">
          <SourceLink />
        </div>
      {/if}
    </div>
  </nav>

  <div class="flex-1 flex flex-col min-w-0 transition-all duration-300" style="margin-left: {collapsed ? '4.5rem' : '16rem'}">
    <header class="h-16 border-b border-(--border) bg-(--bg-secondary)/50 backdrop-blur-xs flex items-center justify-end px-8 sticky top-0 z-20 gap-3">
      <PortalWorkspaceSelector />
      <!-- No auto-refresh on the portal: many members, each refreshes by hand. -->
      <RefreshButton label={m.portal_layout_refresh()} title={m.portal_layout_refresh_title()} />
      <LocaleSelector />
      {#if data?.portalUser}
        <div class="flex items-center gap-2.5 px-2.5 py-1.5 rounded-lg">
          <div class="w-7 h-7 rounded-full bg-(--accent)/15 flex items-center justify-center shrink-0">
            <Icon name="user" size="sm" color="var(--accent)" />
          </div>
          <div class="flex flex-col">
            <span class="text-sm text-(--text-primary) font-medium leading-tight">{data.portalUser.display_name || data.portalUser.email.split('@')[0] || data.portalUser.email}</span>
            {#if data.portalUser.tenant_name}
              <span class="text-[10px] text-(--text-secondary) leading-tight">{data.portalUser.tenant_name}</span>
            {/if}
          </div>
        </div>
        <div class="w-px h-5 bg-(--border)"></div>
      {/if}
      <form method="POST" action={pthref(slug, '/logout')}>
        <button type="submit" class="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-(--text-secondary) hover:text-(--error) hover:bg-(--error-bg) transition-all text-sm" title={m.portal_layout_sign_out()}>
          <Icon name="signOut" size="sm" tone="neutral" />
          <span>{m.portal_layout_sign_out()}</span>
        </button>
      </form>
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
