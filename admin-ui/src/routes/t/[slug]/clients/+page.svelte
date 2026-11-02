<script lang="ts">
  import TabbedPage from '#lib/components/page/TabbedPage.svelte';
  import { useTabState } from '#lib/hooks.svelte.js';
  import DetectionSection from '#lib/components/clients/DetectionSection.svelte';
  import ProfilesSection from '#lib/components/clients/ProfilesSection.svelte';
  import CliSessionsSection from '#lib/components/clients/CliSessionsSection.svelte';

  type ClientsTab = 'detection' | 'profiles' | 'cli-sessions';
  const CLIENTS_TABS = ['detection', 'profiles', 'cli-sessions'] as const satisfies readonly ClientsTab[];
  const clientsTab = useTabState<ClientsTab>(CLIENTS_TABS, 'detection');
</script>

<TabbedPage
  title="Clients"
  subtitle="Identify the AI clients hitting the gateway and serve them per-app quickstart config."
  tabs={[
    { id: 'detection', label: 'Detection' },
    { id: 'profiles', label: 'Profiles' },
    { id: 'cli-sessions', label: 'CLI Sessions' },
  ]}
  activeTab={clientsTab.current}
  onTabChange={(t: ClientsTab) => (clientsTab.current = t)}
>
  {#snippet children(active: ClientsTab)}
    {#if active === 'detection'}
      <DetectionSection activate={active === 'detection'} />
    {:else if active === 'profiles'}
      <ProfilesSection activate={active === 'profiles'} />
    {:else if active === 'cli-sessions'}
      <CliSessionsSection activate={active === 'cli-sessions'} />
    {/if}
  {/snippet}
</TabbedPage>
