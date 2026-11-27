<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import { extractError, fetchAllPages } from '#lib/api-helpers.js';
  import { toast } from '#lib/toast.svelte.js';
  import { page } from '$app/state';
  import { thref } from '#lib/tenant.js';
  import { auditHref } from '#lib/deeplinks.js';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import ConfirmDialog from '#lib/components/ConfirmDialog.svelte';
  import { KeyedContent } from '#lib/keyedContent.svelte.js';
  import { profileLists } from '#lib/scope.svelte.js';
  import { observedRuleCounts, type ToolEnforcementChoice } from '#lib/toolEnforcement.js';
  import type { components } from '#lib/generated/api-types.js';

  type Profile = components['schemas']['Profile'];

  interface Props {
    /** The tool-policy profile whose mode this edits. */
    profileId: string;
    /** Whether the profile currently observes — kept in step with what the
     *  server resolved, for the rule list's chips. */
    observing?: boolean;
  }

  let { profileId, observing = $bindable(false) }: Props = $props();

  const slug = $derived(page.params.slug ?? '');
  // The profile and its effective rule counts, as one visit of its id: an
  // answer for a profile the page has since left is dropped.
  // `counts` is null when the rules could not be read: never taken for zero.
  type Shown = {
    profile: Profile;
    counts: { block: number; rewrite: number } | null;
    /** null when the Default could not be read: never assumed. */
    defaultMode: 'enforce' | 'observe' | null;
  };
  const shown = new KeyedContent<Shown>();
  const profile = $derived(shown.value?.profile ?? null);
  const counts = $derived(shown.value?.counts ?? null);
  let saving = $state(false);
  let confirmEnforce = $state<ToolEnforcementChoice | null>(null);

  // A Layered profile may follow the Default; the Default and a Standalone
  // profile always run in their own mode.
  const canFollow = $derived(!!profile && !profile.is_default && !profile.standalone);
  const effective = $derived(profile?.effective_tool_enforcement ?? 'observe');
  // No value of its own: a Layered profile follows the Default; the Default or
  // a Standalone runs in the mode that reads as (Observe).
  const choice = $derived<ToolEnforcementChoice>(profile?.tool_enforcement ?? (canFollow ? 'follow' : effective));

  // The select's value: the saved choice, put back when a confirmation is
  // declined.
  let selected = $state<ToolEnforcementChoice>('follow');
  $effect(() => {
    selected = choice;
  });

  $effect(() => {
    observing = effective === 'observe';
  });

  async function load() {
    const asked = profileId;
    const visit = shown.show(asked);
    const [{ data, error }, rules, list] = await Promise.all([
      adminApi.GET('/api/v1/admin/profiles/{id}', { params: { path: { id: asked } } }),
      fetchAllPages((offset, limit) =>
        adminApi.GET('/api/v1/admin/tool-rules', { params: { query: { offset, limit, profile_id: asked } } }),
      ).catch(() => null),
      adminApi.GET('/api/v1/admin/profiles', { params: { query: { kind: 'tools', offset: 0, limit: 200 } } }),
    ]);
    if (error || !data) {
      shown.land(visit, null);
      return;
    }
    const defaultMode = list.error ? null : (list.data?.items.find((p) => p.is_default)?.effective_tool_enforcement ?? null);
    shown.land(visit, { profile: data, counts: rules ? observedRuleCounts(rules) : null, defaultMode });
  }

  $effect(() => {
    if (profileId) void load();
  });

  function pick(next: ToolEnforcementChoice) {
    if (next === choice) return;
    // Starting to block is the direction that can break a workflow: confirm
    // every way into it — following an enforcing Default included — unless
    // the rules were counted and none would act.
    // Following a Default whose mode could not be read may start enforcing.
    const resulting = next === 'follow' ? (shown.value?.defaultMode ?? 'enforce') : next;
    const noneWouldAct = counts !== null && counts.block === 0 && counts.rewrite === 0;
    if (effective === 'observe' && resulting === 'enforce' && !noneWouldAct) {
      confirmEnforce = next;
      return;
    }
    void save(next);
  }

  async function save(next: ToolEnforcementChoice) {
    confirmEnforce = null;
    const visit = shown.visit;
    saving = true;
    const { error } = await adminApi.PATCH('/api/v1/admin/profiles/{id}', {
      params: { path: { id: profileId } },
      body: { tool_enforcement: next === 'follow' ? null : next },
    });
    saving = false;
    if (!shown.isCurrent(visit)) return;
    if (error) {
      toast.error('Failed to change the mode', { body: extractError(error) });
      // The select shows the saved mode, not the one that was refused.
      selected = choice;
      return;
    }
    toast.success(next === 'observe' ? 'Observing — nothing is blocked or rewritten' : 'Mode saved');
    // The workspace pickers mark an observing profile.
    void profileLists.load('tools');
    await load();
  }

  const caughtHref = $derived(
    thref(slug, auditHref({ badges: 'tool_block_not_applied,modified_not_applied', days: '7' })),
  );
  const where = $derived(
    'in every workspace that uses this profile' + (profile?.is_default ? ' or a Layered profile following it.' : '.'),
  );
  const confirmMessage = $derived(
    counts
      ? `${counts.block} rule${counts.block === 1 ? '' : 's'} will start blocking calls and ${counts.rewrite} will start rewriting them, ${where}`
      : `This profile's block and rewrite rules will start acting (they could not be counted), ${where}`,
  );
  // What following the Default means now.
  const followLabel = $derived(
    shown.value?.defaultMode
      ? `Follow the Default (${shown.value.defaultMode === 'enforce' ? 'Enforce' : 'Observe'} now)`
      : 'Follow the Default',
  );
</script>

{#if profile}
  <div class="bg-(--bg-card) rounded-xl border border-(--border) p-4 mb-4">
    <label class="block max-w-md">
      <span class="text-[10px] text-(--text-secondary) uppercase tracking-wider">Mode</span>
      <span class="block text-xs text-(--text-secondary) mt-0.5">
        Observe records what block and rewrite rules would do, without applying them. Switch to Enforce once you trust what they catch.
      </span>
      <SelectInput
        bind:value={selected}
        disabled={saving}
        class="mt-1.5"
        onchange={() => pick(selected)}
      >
        {#if canFollow}
          <option value="follow">{followLabel}</option>
        {/if}
        <option value="enforce">Enforce — block and rewrite</option>
        <option value="observe">Observe — record only, change nothing</option>
      </SelectInput>
    </label>
    {#if effective === 'observe'}
      <p class="text-xs mt-3 px-3 py-2 rounded-lg bg-(--warning-bg) text-(--warning) border border-(--warning-border)">
        {#if counts}Observing — {counts.block} rule{counts.block === 1 ? '' : 's'} would block and {counts.rewrite} would rewrite.{:else}Observing.{/if}
        Nothing is blocked or rewritten; each match is recorded as "Would block" or "Not applied".
        <a href={caughtHref} class="underline ml-1">See every request recorded as not applied in the organisation in the last 7 days — this policy's and other checks' →</a>
      </p>
    {/if}
  </div>
{/if}

<ConfirmDialog
  open={confirmEnforce !== null}
  title="Start enforcing"
  message={confirmMessage}
  confirmLabel="Enforce"
  destructive
  onconfirm={() => confirmEnforce && void save(confirmEnforce)}
  oncancel={() => {
    confirmEnforce = null;
    selected = choice;
  }}
/>
