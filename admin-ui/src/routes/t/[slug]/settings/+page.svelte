<script lang="ts">
  import TabbedPage from '#lib/components/page/TabbedPage.svelte';
  import { useTabState } from '#lib/hooks.svelte.js';
  import ProxySettingsSection from '#lib/components/settings/ProxySettingsSection.svelte';
  import ScriptSettingsSection from '#lib/components/settings/ScriptSettingsSection.svelte';
  import AuditRetentionSettingsSection from '#lib/components/settings/AuditRetentionSettingsSection.svelte';
  import AgentSettingsSection from '#lib/components/settings/AgentSettingsSection.svelte';
  import CacheSettingsSection from '#lib/components/settings/CacheSettingsSection.svelte';
  import QosSettingsSection from '#lib/components/settings/QosSettingsSection.svelte';
  import GuardrailSettingsSection from '#lib/components/settings/GuardrailSettingsSection.svelte';
  import AdvancedSettingsSection from '#lib/components/settings/AdvancedSettingsSection.svelte';
  import EgressSettingsSection from '#lib/components/settings/EgressSettingsSection.svelte';
  import DefaultsSettingsSection from '#lib/components/settings/DefaultsSettingsSection.svelte';
  import BudgetSettingsSection from '#lib/components/settings/BudgetSettingsSection.svelte';
  import AccountingSettingsSection from '#lib/components/settings/AccountingSettingsSection.svelte';
  import { adminApi } from '#lib/api-client.js';
  import { extractInheritedDefaults } from '#lib/api-helpers.js';
  import { page } from '$app/state';
  import { onMount } from 'svelte';

  type Tab = 'system' | 'egress' | 'defaults' | 'budget' | 'accounting' | 'proxy' | 'audit-retention' | 'scripts' | 'agents' | 'guardrail' | 'cache' | 'priority';
  type Audience = 'system' | 'tenant' | 'both';

  const isSuperAdmin = !!page.data?.user?.is_super_admin;
  const isSystemTenant = page.data?.user?.tenant_slug === 'system';

  const TABS: { id: Tab; label: string; audience: Audience; superAdmin?: boolean }[] = [
    { id: 'system',          label: 'System',          audience: 'system', superAdmin: true },
    { id: 'egress',          label: 'Egress',          audience: 'system', superAdmin: true },
    { id: 'defaults',        label: 'Defaults',        audience: 'both' },
    { id: 'budget',          label: 'Budget',          audience: 'tenant' },
    { id: 'accounting',      label: 'Accounting',      audience: 'tenant' },
    { id: 'proxy',           label: 'Proxy',           audience: 'tenant' },
    { id: 'scripts',         label: 'Scripts',         audience: 'tenant' },
    { id: 'audit-retention', label: 'Audit Retention', audience: 'tenant' },
    { id: 'agents',          label: 'Agent',           audience: 'tenant' },
    { id: 'guardrail',       label: 'Guardrail',       audience: 'tenant' },
    { id: 'cache',           label: 'Response Cache',  audience: 'tenant' },
    { id: 'priority',        label: 'Priority',        audience: 'tenant' },
  ];

  const visibleTabs = TABS.filter((t) => {
    if (t.superAdmin && !isSuperAdmin) return false;
    if (t.audience === 'system' && !isSystemTenant) return false;
    if (t.audience === 'tenant' && isSystemTenant) return false;
    return true;
  });
  const TAB_IDS = visibleTabs.map((t) => t.id);
  const tab = useTabState<Tab>(TAB_IDS, 'defaults');

  // Surface a warning banner when any public-facing URL has neither a
  // tenant override nor a SYSTEM default. The banner doesn't fire when
  // the SYSTEM default is set and the tenant just hasn't overridden —
  // the system is fully functional in that case. `api_public_url` is
  // optional (only meaningful on distinct-hostname installs), so it
  // never triggers the banner.
  let missingKeys = $state<string[]>([]);
  onMount(async () => {
    const { data } = await adminApi.GET('/api/v1/admin/settings');
    if (data) {
      const inh = extractInheritedDefaults(data);
      const m: string[] = [];
      if (!inh.proxy_public_url) m.push('proxy_public_url');
      if (!inh.admin_public_url) m.push('admin_public_url');
      missingKeys = m;
    }
  });
</script>

{#if missingKeys.length > 0}
  <div class="mb-4 p-4 rounded-lg bg-(--warning-bg) border border-(--warning-border) text-(--warning) text-sm">
    <p class="font-semibold mb-1">Public URL{missingKeys.length === 1 ? '' : 's'} not configured: <code class="font-mono">{missingKeys.join(', ')}</code></p>
    <p>
      Quickstart snippets, MCP OAuth, login links, and CORS allowlists all read these values. Without them, dependent features fail closed for this tenant.
      The platform operator sets defaults on the system tenant; tenant admins can override on the Defaults tab.
    </p>
  </div>
{/if}

<TabbedPage
  title="Settings"
  subtitle={isSystemTenant ? 'Platform-tier settings — defaults inherited by every tenant.' : 'Tenant-scoped settings consolidated from across the admin UI.'}
  tabs={visibleTabs.map((t) => ({ id: t.id, label: t.label }))}
  activeTab={tab.current}
  onTabChange={(t: Tab) => (tab.current = t)}
>
  {#snippet children(active: Tab)}
    {#if active === 'system'}
      <AdvancedSettingsSection />
    {:else if active === 'egress'}
      <EgressSettingsSection />
    {:else if active === 'defaults'}
      <DefaultsSettingsSection {isSystemTenant} />
    {:else if active === 'budget'}
      <BudgetSettingsSection />
    {:else if active === 'accounting'}
      <AccountingSettingsSection />
    {:else if active === 'proxy'}
      <ProxySettingsSection />
    {:else if active === 'scripts'}
      <ScriptSettingsSection />
    {:else if active === 'audit-retention'}
      <AuditRetentionSettingsSection />
    {:else if active === 'agents'}
      <AgentSettingsSection />
    {:else if active === 'guardrail'}
      <GuardrailSettingsSection />
    {:else if active === 'cache'}
      <CacheSettingsSection />
    {:else if active === 'priority'}
      <QosSettingsSection />
    {/if}
  {/snippet}
</TabbedPage>
