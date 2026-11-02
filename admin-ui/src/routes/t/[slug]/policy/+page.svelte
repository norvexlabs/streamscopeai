<script lang="ts">
  import TabbedPage from '#lib/components/page/TabbedPage.svelte';
  import { useTabState } from '#lib/hooks.svelte.js';
  import FieldProfilesSection from '#lib/components/policy/FieldProfilesSection.svelte';
  import FieldProfileSuggestionsSection from '#lib/components/policy/FieldProfileSuggestionsSection.svelte';
  import ProfilesManager from '#lib/components/policy/ProfilesManager.svelte';
  import RuleSuggestionsSection from '#lib/components/policy/RuleSuggestionsSection.svelte';

  type PolicyTab = 'profiles' | 'field-profiles' | 'suggestions';
  const POLICY_TABS = ['profiles', 'field-profiles', 'suggestions'] as const satisfies readonly PolicyTab[];
  const policyTab = useTabState<PolicyTab>(POLICY_TABS, 'profiles');
</script>

<TabbedPage
  title="Tool Policy"
  subtitle="Tool-call rules, field-redaction profiles, and rule suggestions applied across LLM and MCP traffic. Per-workspace rule overrides live on each workspace."
  tabs={[
    { id: 'profiles', label: 'Profiles' },
    { id: 'field-profiles', label: 'Field Profiles' },
    { id: 'suggestions', label: 'Rule Suggestions' },
  ]}
  activeTab={policyTab.current}
  onTabChange={(t: PolicyTab) => (policyTab.current = t)}
>
  {#snippet children(active: PolicyTab)}
    {#if active === 'profiles'}
      <ProfilesManager kind="tools" activate={active === 'profiles'} />
    {:else if active === 'field-profiles'}
      <FieldProfilesSection activate={active === 'field-profiles'} />
    {:else if active === 'suggestions'}
      <RuleSuggestionsSection activate={active === 'suggestions'} />
      <div class="pt-6 border-t border-(--border)">
        <h3 class="text-sm font-semibold text-(--text-primary) mb-3">Field Profile Suggestions</h3>
        <FieldProfileSuggestionsSection activate={active === 'suggestions'} />
      </div>
    {/if}
  {/snippet}
</TabbedPage>
