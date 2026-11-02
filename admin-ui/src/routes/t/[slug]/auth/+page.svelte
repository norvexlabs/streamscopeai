<script lang="ts">
  // Authentication — three tabs: global auth settings, human accounts, and
  // service accounts. Tab id rides `?tab=` so views deep-link/refresh stably.
  import TabbedPage from '#lib/components/page/TabbedPage.svelte';
  import AuthSettingsTab from '#lib/components/auth/AuthSettingsTab.svelte';
  import AccountsTab from '#lib/components/auth/AccountsTab.svelte';
  import ServiceAccountsTab from '#lib/components/auth/ServiceAccountsTab.svelte';
  import { getTabFromUrl } from '#lib/tabs.js';
  import type { PageProps } from './$types';

  let { data }: PageProps = $props();

  type TabId = 'settings' | 'accounts' | 'service-accounts';
  const TAB_IDS: TabId[] = ['settings', 'accounts', 'service-accounts'];
  const tabs: { id: TabId; label: string }[] = [
    { id: 'settings', label: 'Settings' },
    { id: 'accounts', label: 'Accounts' },
    { id: 'service-accounts', label: 'Service Accounts' },
  ];

  let activeTab = $state<TabId>(getTabFromUrl(TAB_IDS, 'settings'));
</script>

<TabbedPage
  title="Authentication"
  subtitle="Identity and authentication configuration — auth mode, human accounts, service accounts"
  {tabs}
  {activeTab}
  onTabChange={(next) => (activeTab = next)}
>
  {#snippet children(tab)}
    {#if tab === 'settings'}
      <AuthSettingsTab registration={data.oidcRegistration} />
    {:else if tab === 'accounts'}
      <AccountsTab />
    {:else}
      <ServiceAccountsTab />
    {/if}
  {/snippet}
</TabbedPage>
