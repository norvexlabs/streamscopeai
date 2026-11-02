<script lang="ts">
  import type { TransformProgram } from '#lib/api-types.js';
  import { adminApi } from '#lib/api-client.js';
  import { extractError, fetchAllPages } from '#lib/api-helpers.js';
  import TagBadge from '#lib/components/TagBadge.svelte';
  import EmptyState from '#lib/components/EmptyState.svelte';
  import ProfileDetailShell from '#lib/components/policy/ProfileDetailShell.svelte';
  import TransformProgramEditor from '#lib/components/policy/TransformProgramEditor.svelte';
  import { scopeColor, filterChipColor } from '#lib/colormaps/transforms.js';
  import type { PageProps } from './$types';

  let { params }: PageProps = $props();

  type ProfileLite = { id: string; is_default: boolean; standalone: boolean };

  const id = $derived(params.id);

  let programs = $state<TransformProgram[]>([]);
  let profiles = $state<ProfileLite[]>([]);
  let error = $state<string | null>(null);

  async function loadData() {
    try {
      programs = await fetchAllPages((offset, limit) =>
        adminApi.GET('/api/v1/admin/transforms/programs', { params: { query: { offset, limit } } }));
      const { data } = await adminApi.GET('/api/v1/admin/profiles', {
        params: { query: { kind: 'transform', offset: 0, limit: 200 } },
      });
      profiles = (data?.items ?? []).map((p) => ({
        id: p.id,
        is_default: p.is_default,
        standalone: p.standalone,
      }));
    } catch (e: unknown) {
      error = e instanceof Error ? e.message : String(e);
    }
  }

  $effect(() => {
    loadData();
  });

  const self = $derived(profiles.find((p) => p.id === id));
  // Layered profiles inherit the Default's programs; the Default/Standalone own
  // their full set.
  const isLayered = $derived(self ? !self.is_default && !self.standalone : false);
  const defaultId = $derived(profiles.find((p) => p.is_default)?.id ?? '');

  const SCOPE_ORDER = ['global', 'system_prompt', 'messages', 'tools', 'text', 'tool', 'thinking'];
  function byPhase(list: TransformProgram[], phase: string): TransformProgram[] {
    return list
      .filter((p) => (p.phase || 'request') === phase)
      .sort((a, b) =>
        (SCOPE_ORDER.indexOf(a.scope) - SCOPE_ORDER.indexOf(b.scope)) ||
        ((a.priority ?? 100) - (b.priority ?? 100)));
  }

  // This profile's own programs, plus (for a Layered profile) the Default's
  // programs it inherits (read-only here — edit them on the Default profile).
  const own = $derived(programs.filter((p) => (p.profile_id ?? '') === id));
  const inherited = $derived(
    isLayered ? programs.filter((p) => (p.profile_id ?? '') === defaultId) : [],
  );

  let editorOpen = $state(false);
  let editorProgram = $state<TransformProgram | null>(null);
  let editorPhase = $state('request');

  function openCreate(phase: string) {
    editorProgram = null;
    editorPhase = phase;
    editorOpen = true;
  }
  function openEdit(p: TransformProgram) {
    editorProgram = p;
    editorOpen = true;
  }

  async function toggleProgram(p: TransformProgram) {
    const { error: err } = await adminApi.PATCH('/api/v1/admin/transforms/programs/{id}', {
      params: { path: { id: p.id } },
      body: { enabled: !p.enabled },
    });
    if (err) error = extractError(err, 'Failed to toggle program');
    else programs = programs.map((prog) => (prog.id === p.id ? { ...prog, enabled: !prog.enabled } : prog));
  }
  async function removeProgram(pid: string) {
    if (!confirm('Delete this program?')) return;
    const { error: err } = await adminApi.DELETE('/api/v1/admin/transforms/programs/{id}', {
      params: { path: { id: pid } },
    });
    if (err) error = extractError(err, 'Failed to delete program');
    else await loadData();
  }
</script>

<ProfileDetailShell kind="transform">
  {#snippet children()}
    {#if error}
      <div class="p-3 rounded-lg bg-(--error-bg) text-(--error) text-sm mb-4">{error}</div>
    {/if}

    {#each ['request', 'response'] as phase (phase)}
      {@const ownPhase = byPhase(own, phase)}
      <section class="mb-8">
        <div class="flex items-center justify-between mb-3">
          <h2 class="text-sm font-semibold text-(--text-primary) capitalize">{phase} programs</h2>
          <button onclick={() => openCreate(phase)} class="px-3 py-1.5 text-sm rounded-lg bg-(--accent) text-(--accent-fg) hover:bg-(--accent-hover)">+ Create {phase} program</button>
        </div>

        {#if ownPhase.length === 0}
          <EmptyState title={`No ${phase} programs`} body={`Add a ${phase} program scoped to this profile.`} />
        {:else}
          <div class="bg-(--bg-card) rounded-xl border border-(--border) divide-y divide-(--border)">
            {#each ownPhase as p (p.id)}
              <div class="flex items-center justify-between px-5 py-3 gap-4">
                <div class="min-w-0">
                  <div class="flex items-center gap-2.5">
                    <span class="font-medium text-(--text-primary) truncate">{p.name}</span>
                    <TagBadge color={scopeColor(p.scope)} class="text-xs shrink-0">{p.scope}</TagBadge>
                    <span class="text-xs text-(--text-secondary) font-mono shrink-0">p:{p.priority}</span>
                    {#if p.match_mode === 'span'}<TagBadge color={scopeColor(p.scope)} class="text-xs">per-match</TagBadge>{/if}
                    {#if p.model_filter}<TagBadge color={filterChipColor.models} class="text-xs">models: {p.model_filter}</TagBadge>{/if}
                    {#if p.app_filter}<TagBadge color={filterChipColor.apps} class="text-xs">apps: {p.app_filter}</TagBadge>{/if}
                  </div>
                  {#if p.description}<p class="text-xs text-(--text-secondary) mt-1 line-clamp-2">{p.description}</p>{/if}
                </div>
                <div class="flex items-center gap-4 shrink-0">
                  <button onclick={() => toggleProgram(p)} aria-label="{p.enabled ? 'Disable' : 'Enable'} {p.name}" class="w-11 h-6 rounded-full transition-colors {p.enabled ? 'bg-(--success)' : 'bg-(--bg-elevated)'} relative">
                    <span class="absolute top-0.5 {p.enabled ? 'right-0.5' : 'left-0.5'} w-5 h-5 rounded-full bg-white ring-1 ring-(--bg-primary)/60 transition-all"></span>
                  </button>
                  <button onclick={() => openEdit(p)} class="text-(--accent) hover:underline text-sm">Edit</button>
                  <button onclick={() => removeProgram(p.id)} class="text-(--error) hover:underline text-sm">Delete</button>
                </div>
              </div>
            {/each}
          </div>
        {/if}

        {#if isLayered}
          {@const inh = byPhase(inherited, phase)}
          {#if inh.length > 0}
            <p class="text-xs text-(--text-secondary) mt-4 mb-2">Inherited from the Default profile (also runs here — edit them on the Default profile):</p>
            <div class="bg-(--bg-card)/50 rounded-xl border border-dashed border-(--border) divide-y divide-(--border)">
              {#each inh as p (p.id)}
                <div class="flex items-center gap-2.5 px-5 py-2.5 text-(--text-secondary)">
                  <span class="text-sm truncate">{p.name}</span>
                  <TagBadge color={scopeColor(p.scope)} class="text-xs shrink-0">{p.scope}</TagBadge>
                  <span class="text-xs font-mono shrink-0">p:{p.priority}</span>
                  {#if !p.enabled}<span class="text-xs">(disabled)</span>{/if}
                </div>
              {/each}
            </div>
          {/if}
        {/if}
      </section>
    {/each}

    <TransformProgramEditor
      open={editorOpen}
      program={editorProgram}
      profileId={id}
      defaultPhase={editorPhase}
      lockProfile
      onclose={() => (editorOpen = false)}
      onsaved={loadData}
    />
  {/snippet}
</ProfileDetailShell>
