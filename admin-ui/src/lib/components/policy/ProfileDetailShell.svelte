<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import { extractError } from '#lib/api-helpers.js';
  import { toast } from '#lib/toast.svelte.js';
  import { page } from '$app/state';
  import { thref } from '#lib/tenant.js';
  import ConfirmDialog from '#lib/components/ConfirmDialog.svelte';
  import type { Snippet } from 'svelte';
  import type { components } from '#lib/generated/api-types.js';

  type Profile = components['schemas']['Profile'];
  type ProfileKind = 'tools' | 'guardrail' | 'transform' | 'expert';

  interface Props {
    /** Which profile family this drill-down belongs to. */
    kind: ProfileKind;
    /** Editor body — receives the resolved profile context. */
    children: Snippet<[{ id: string; isDefault: boolean; standalone: boolean; name: string }]>;
  }

  let { kind, children }: Props = $props();

  // The feature root doubles as the profile-list view (Profiles is its first
  // tab), so "back" lands on the list this card was opened from.
  const featureRoot = $derived(
    kind === 'tools'
      ? '/policy'
      : kind === 'transform'
        ? '/transforms'
        : kind === 'expert'
          ? '/experts'
          : '/guardrail',
  );
  const featureLabel = $derived(
    kind === 'tools'
      ? 'Tool policy'
      : kind === 'transform'
        ? 'Transforms'
        : kind === 'expert'
          ? 'Experts'
          : 'Guardrail',
  );

  // `shared` is the stable route alias for the tenant's Default profile of this
  // kind — the baseline every Layered profile builds on (mirrors the still-valid
  // `view=shared` rule query). Resolve it to the Default's UUID so the route
  // loads the Default profile instead of 400ing on a non-UUID id; any other
  // segment is already a profile UUID and passes straight through.
  const routeId = $derived(page.params.id ?? '');
  let id = $state('');

  async function resolveRouteId() {
    if (routeId !== 'shared') {
      id = routeId;
      return;
    }
    const { data } = await adminApi.GET('/api/v1/admin/profiles', {
      params: { query: { kind, offset: 0, limit: 200 } },
    });
    id = data?.items?.find((p) => p.is_default)?.id ?? '';
  }

  $effect(() => {
    resolveRouteId();
  });

  let slug = $derived(page.params.slug ?? '');
  let profile = $state<Profile | null>(null);
  let loading = $state(true);
  let loadError = $state('');
  // Bumped after a reset so the editor body re-mounts and reloads its content.
  let bodyNonce = $state(0);
  let confirmReset = $state(false);
  let resetting = $state(false);

  async function load() {
    loading = true;
    loadError = '';
    profile = null;
    const { data, error } = await adminApi.GET('/api/v1/admin/profiles/{id}', {
      params: { path: { id } },
    });
    if (error) loadError = extractError(error, 'Failed to load profile');
    else profile = data ?? null;
    loading = false;
  }

  $effect(() => {
    if (id) load();
  });

  const name = $derived(profile?.name ?? '');
  const isDefault = $derived(profile?.is_default ?? false);
  const standalone = $derived(profile?.standalone ?? false);
  // "Reset to seed" restores the built-in defaults — only meaningful where the
  // profile owns its content (the Default base, or a Standalone copy).
  const canReset = $derived(isDefault || standalone);

  async function doReset() {
    confirmReset = false;
    resetting = true;
    const { error } = await adminApi.POST('/api/v1/admin/profiles/{id}/actions/reset-to-seed', {
      params: { path: { id } },
    });
    resetting = false;
    if (error) {
      toast.error('Failed to reset', { body: extractError(error) });
      return;
    }
    toast.success('Reset to seed');
    await load();
    bodyNonce += 1;
  }
</script>

<div class="mb-4">
  <a href={thref(slug, featureRoot)} class="text-xs text-(--text-secondary) hover:text-(--text-primary)">‹ {featureLabel}</a>
</div>

{#if loading}
  <div class="text-sm text-(--text-secondary)">Loading…</div>
{:else if loadError}
  <div class="px-3 py-2 rounded-lg bg-(--error-bg) border border-(--error-border) text-sm text-(--error-text)">{loadError}</div>
{:else if profile}
  <div class="mb-6 flex items-center justify-between gap-3">
    <div class="flex items-center gap-3">
      <h1 class="text-2xl font-semibold text-(--text-primary)">{name}</h1>
      {#if isDefault}
        <span class="px-2 py-0.5 text-[10px] rounded-full bg-(--accent)/10 text-(--accent)">Default</span>
      {:else if standalone}
        <span class="px-2 py-0.5 text-[10px] rounded-full bg-(--bg-secondary) text-(--text-secondary)">Standalone</span>
      {:else}
        <span class="px-2 py-0.5 text-[10px] rounded-full bg-(--bg-secondary) text-(--text-secondary)">Layered</span>
      {/if}
    </div>
    {#if canReset}
      <button
        onclick={() => (confirmReset = true)}
        disabled={resetting}
        class="px-3 py-1.5 text-xs rounded-lg border border-(--border) text-(--text-secondary) hover:text-(--text-primary) hover:border-(--accent) disabled:opacity-50"
      >{resetting ? 'Resetting…' : 'Reset to seed'}</button>
    {/if}
  </div>
  {#if isDefault}
    <p class="text-sm text-(--text-secondary) mb-4">The shared defaults every Layered profile builds on.</p>
  {:else if standalone}
    <p class="text-sm text-(--text-secondary) mb-4">Independent — ignores the Default.</p>
  {:else}
    <p class="text-sm text-(--text-secondary) mb-4">Builds on the Default — edit only what's different.</p>
  {/if}

  {#key bodyNonce}
    {@render children({ id, isDefault, standalone, name })}
  {/key}
{/if}

<ConfirmDialog
  open={confirmReset}
  title="Reset to seed"
  message={isDefault
    ? 'Restore this Default profile to the built-in defaults? Your changes to it will be lost.'
    : 'Restore this profile to a fresh copy of the built-in defaults? Its current content will be replaced.'}
  confirmLabel="Reset"
  destructive
  onconfirm={doReset}
  oncancel={() => (confirmReset = false)}
/>
