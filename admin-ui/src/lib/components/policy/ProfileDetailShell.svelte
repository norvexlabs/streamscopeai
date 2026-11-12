<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import { extractError } from '#lib/api-helpers.js';
  import { toast } from '#lib/toast.svelte.js';
  import { page } from '$app/state';
  import { thref } from '#lib/tenant.js';
  import ConfirmDialog from '#lib/components/ConfirmDialog.svelte';
  import { untrack, type Snippet } from 'svelte';
  import type { components } from '#lib/generated/api-types.js';
  import type { ProfileListKind } from '#lib/scope.svelte.js';
  import { PROFILE_KINDS } from '#lib/profileKinds.js';
  import { KeyedContent } from '#lib/keyedContent.svelte.js';

  type Profile = components['schemas']['Profile'];
  type ProfileKind = ProfileListKind;

  interface Props {
    /** Which profile family this drill-down belongs to. */
    kind: ProfileKind;
    /** Editor body — receives the resolved profile context. */
    children: Snippet<[{ id: string; isDefault: boolean; standalone: boolean; name: string }]>;
  }

  let { kind, children }: Props = $props();

  // The feature root doubles as the profile-list view (Profiles is its first
  // tab), so "back" lands on the list this card was opened from.
  const info = $derived(PROFILE_KINDS[kind]);
  const featureRoot = $derived(info.root);
  const featureLabel = $derived(info.label);

  // `shared` is the stable route alias for the tenant's Default profile of this
  // kind — the baseline every Layered profile builds on (mirrors the still-valid
  // `view=shared` rule query). Resolve it to the Default's UUID so the route
  // loads the Default profile instead of 400ing on a non-UUID id; any other
  // segment is already a profile UUID and passes straight through.
  const routeId = $derived(page.params.id ?? '');
  // The profile id the route resolves to, as one visit of the route
  // (`KeyedContent`): the alias is resolved by a read, and an answer that lands
  // after the route moved on is dropped — it would open the Default under
  // another profile's address.
  const resolved = new KeyedContent<string>();
  const id = $derived(resolved.value ?? '');

  async function resolveRouteId() {
    const visit = resolved.show(routeId);
    if (routeId !== 'shared') {
      resolved.land(visit, routeId);
      return;
    }
    const { data } = await adminApi.GET('/api/v1/admin/profiles', {
      params: { query: { kind, offset: 0, limit: 200 } },
    });
    resolved.land(visit, data?.items?.find((p) => p.is_default)?.id ?? '');
  }

  // The route alone re-runs it: the resolution writes the state it reads.
  $effect(() => {
    void routeId;
    untrack(() => void resolveRouteId());
  });

  let slug = $derived(page.params.slug ?? '');
  // The profile shown, as one visit of its id (`KeyedContent`): an answer
  // issued under an earlier visit — another profile's, or this one's before a
  // reload — is dropped when it lands.
  const shown = new KeyedContent<Profile>();
  const profile = $derived(shown.value);
  let loading = $state(true);
  let loadError = $state('');
  // Bumped after a reset so the editor body re-mounts and reloads its content.
  let bodyNonce = $state(0);
  let confirmReset = $state(false);
  let resetting = $state(false);

  async function load() {
    const asked = id;
    const visit = shown.show(asked);
    loading = true;
    loadError = '';
    const { data, error } = await adminApi.GET('/api/v1/admin/profiles/{id}', {
      params: { path: { id: asked } },
    });
    // Another profile was opened meanwhile: its own load owns the page.
    if (!shown.land(visit, error ? null : (data ?? null))) return;
    if (error) loadError = extractError(error, 'Failed to load profile');
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
    const asked = shown.key;
    if (!asked) return;
    const visit = shown.visit;
    confirmReset = false;
    resetting = true;
    const { error } = await adminApi.POST('/api/v1/admin/profiles/{id}/actions/reset-to-seed', {
      params: { path: { id: asked } },
    });
    resetting = false;
    // Another profile was opened meanwhile: nothing here is about it.
    if (!shown.isCurrent(visit)) return;
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
      {:else if info.standaloneOnly}
        <!-- Every profile of the kind is an independent copy: no mode to tell apart. -->
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
  {#if info.standaloneOnly}
    <p class="text-sm text-(--text-secondary) mb-4">
      {isDefault
        ? 'Applies to every workspace with no profile of its own, and to the Agent and Inline AI workspaces.'
        : 'Applies to the workspaces it is assigned to. An edit to the Default does not reach it.'}
    </p>
  {:else if isDefault}
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
  message={info.standaloneOnly
    ? 'Offer every client again, detach every sandbox destination list and put the sandbox settings back to their defaults?'
    : isDefault
    ? 'Restore this Default profile to the built-in defaults? Your changes to it will be lost.'
    : 'Restore this profile to a fresh copy of the built-in defaults? Its current content will be replaced.'}
  confirmLabel="Reset"
  destructive
  onconfirm={doReset}
  oncancel={() => (confirmReset = false)}
/>
