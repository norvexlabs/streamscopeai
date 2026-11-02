<script lang="ts">
  import type { components } from '#lib/generated/api-types.js';
  import { adminApi } from '#lib/api-client.js';
  import { extractError, fetchAllPages } from '#lib/api-helpers.js';
  import FieldProfileEditModal from '#lib/components/FieldProfileEditModal.svelte';
  import Modal from '#lib/components/Modal.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import TextInput from '#lib/components/forms/TextInput.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';

  type FieldProfile = components['schemas']['FieldProfile'];
  type DiscoveredField = components['schemas']['DiscoveredField'];

  interface Props {
    activate?: boolean;
  }

  let { activate = true }: Props = $props();

  let fieldProfiles = $state<FieldProfile[]>([]);
  let profilesLoading = $state(false);
  /** Flips true after the first load attempt completes — gates the activate
   * effect so an empty server response doesn't re-fire the load forever. */
  let loaded = $state(false);
  let profilesError = $state<string | null>(null);
  let profilesSuccess = $state<string | null>(null);
  let profileFilterQ = $state('');
  let profileFilterNorm = $state('');
  let profileFilterSource = $state<'all' | 'builtin' | 'custom'>('all');
  let profileEditModalOpen = $state(false);
  let editingProfile = $state<FieldProfile | null>(null);
  let deletingProfile = $state<FieldProfile | null>(null);
  let profileResetModalOpen = $state(false);
  let profileResetRunning = $state(false);
  let discoveredFields = $state<DiscoveredField[]>([]);
  let discoveryLoading = $state(false);
  let showDiscoveryPanel = $state(false);

  export async function loadFieldProfiles() {
    profilesLoading = true;
    profilesError = null;
    try {
      fieldProfiles = await fetchAllPages<FieldProfile>((offset, limit) =>
        adminApi.GET('/api/v1/admin/tool-field-profiles', { params: { query: { offset, limit } } }));
    } catch (e) {
      profilesError = (e as Error).message;
    } finally {
      profilesLoading = false;
      loaded = true;
    }
  }

  async function loadDiscoveredFields() {
    discoveryLoading = true;
    try {
      const { data, error: err } = await adminApi.GET('/api/v1/admin/tool-field-profiles/discover', {});
      if (err) {
        profilesError = extractError(err, 'Discovery failed');
        discoveredFields = [];
      } else if (data) {
        discoveredFields = data.fields;
      }
    } finally {
      discoveryLoading = false;
    }
  }

  function openCreateProfile(seed?: {
    tool_name?: string;
    field?: string;
    suggested_tool_id?: string | null;
    mcp_server?: string | null;
  }) {
    editingProfile = seed
      ? ({
          tool_pattern: seed.mcp_server
            ? (seed.tool_name?.replace(/^mcp__[^_]+__/, '') ?? '')
            : (seed.tool_name ?? ''),
          field: seed.field ?? '',
          tool_id: seed.suggested_tool_id ?? '',
          mcp_server: seed.mcp_server ?? null,
          app_filter: null,
          wire_field: null,
          normalizer: 'raw',
          priority: 100,
          is_builtin: false,
        } as FieldProfile)
      : null;
    profileEditModalOpen = true;
  }

  function openEditProfile(profile: FieldProfile) {
    editingProfile = profile;
    profileEditModalOpen = true;
  }

  function profileFlash(msg: string) {
    profilesSuccess = msg;
    setTimeout(() => { if (profilesSuccess === msg) profilesSuccess = null; }, 3000);
  }

  function handleProfileSaved(_saved: FieldProfile) {
    profileFlash(editingProfile?.id ? 'Profile updated.' : 'Profile created.');
    void loadFieldProfiles();
    if (showDiscoveryPanel) void loadDiscoveredFields();
  }

  async function confirmProfileDelete() {
    if (!deletingProfile) return;
    const { error: err } = await adminApi.DELETE('/api/v1/admin/tool-field-profiles/{id}', {
      params: { path: { id: deletingProfile.id ?? '' } },
    });
    if (err) {
      profilesError = extractError(err, 'Failed to delete profile');
      deletingProfile = null;
      return;
    }
    deletingProfile = null;
    profileFlash('Profile deleted.');
    await loadFieldProfiles();
  }

  async function runProfileReset() {
    profileResetRunning = true;
    const { data, error: err } = await adminApi.POST('/api/v1/admin/tool-field-profiles/actions/reset', {});
    profileResetRunning = false;
    profileResetModalOpen = false;
    if (err) {
      profilesError = extractError(err, 'Reset failed');
      return;
    }
    profileFlash(data?.message ?? 'Builtin profiles restored.');
    await loadFieldProfiles();
  }

  $effect(() => {
    if (activate && !loaded && !profilesLoading) {
      void loadFieldProfiles();
    }
  });

  let filteredProfiles: FieldProfile[] = $derived.by(() => {
    return fieldProfiles.filter((p) => {
      if (profileFilterNorm && p.normalizer !== profileFilterNorm) return false;
      if (profileFilterSource === 'builtin' && !p.is_builtin) return false;
      if (profileFilterSource === 'custom' && p.is_builtin) return false;
      if (profileFilterQ) {
        const needle = profileFilterQ.toLowerCase();
        const hit = [p.id, p.description, p.source, p.tool_pattern, p.field]
          .some((v) => v?.toLowerCase().includes(needle));
        if (!hit) return false;
      }
      return true;
    });
  });
</script>

<p class="text-sm text-(--text-secondary)">
  Field profiles attach a normaliser (shell / url / sql / path / patch / raw) to a
  <code class="px-1 rounded-sm bg-(--bg-card) text-xs">(tool, field)</code> pair so risk rules match against the canonical
  form. Built-in profiles ship for major coding agents and the most-used MCP servers; add custom entries for in-house tools.
</p>

{#if profilesError}
  <div class="p-3 rounded-lg bg-(--error-bg) text-(--error) text-sm">{profilesError}</div>
{/if}
{#if profilesSuccess}
  <div class="p-3 rounded-lg bg-(--success-bg) text-(--tag-teal-text) text-sm">{profilesSuccess}</div>
{/if}

<div class="flex flex-wrap items-center justify-between gap-3 mb-4">
  <div class="flex flex-wrap items-center gap-2">
    <div class="w-64">
      <TextInput type="search" bind:value={profileFilterQ} placeholder="Search id / pattern / field…" />
    </div>
    <div>
      <SelectInput bind:value={profileFilterNorm} fluid={false}>
        <option value="">All normalisers</option>
        <option value="shell">shell</option>
        <option value="url">url</option>
        <option value="sql">sql</option>
        <option value="path">path</option>
        <option value="patch">patch</option>
        <option value="raw">raw</option>
      </SelectInput>
    </div>
    <div class="flex items-center gap-1 bg-(--bg-card) border border-(--border) rounded-lg p-0.5">
      {#each [['all', 'All'], ['builtin', 'Built-in'], ['custom', 'Custom']] as [key, label]}
        <button onclick={() => profileFilterSource = key as typeof profileFilterSource}
          class="px-3 py-1 text-xs rounded-sm {profileFilterSource === key ? 'bg-(--accent)/20 text-(--accent)' : 'text-(--text-secondary) hover:text-(--text-primary)'} transition-colors">
          {label}
        </button>
      {/each}
    </div>
  </div>
  <div class="flex items-center gap-2">
    <button onclick={() => { showDiscoveryPanel = !showDiscoveryPanel; if (showDiscoveryPanel && discoveredFields.length === 0) void loadDiscoveredFields(); }}
      class="px-3 py-2 text-sm border border-(--border) rounded-lg hover:bg-(--bg-elevated) transition-colors">
      {showDiscoveryPanel ? 'Hide' : 'Discover from traffic'}
    </button>
    <button onclick={() => profileResetModalOpen = true}
      class="px-3 py-2 text-sm border border-(--border) rounded-lg hover:bg-(--bg-elevated) transition-colors">
      Reset built-ins
    </button>
    <button onclick={() => openCreateProfile()}
      class="px-3 py-2 text-sm bg-(--accent) text-(--accent-fg) rounded-lg hover:bg-(--accent-hover) transition-colors">
      + New profile
    </button>
  </div>
</div>

{#if showDiscoveryPanel}
  <div class="border border-(--border) rounded-lg p-3 mb-4 bg-(--bg-card)">
    <div class="flex items-center justify-between mb-2">
      <div class="text-xs uppercase tracking-wider text-(--text-secondary) font-medium">Recently-seen tool fields</div>
      <button onclick={() => void loadDiscoveredFields()} class="text-xs text-(--accent) hover:underline">Refresh</button>
    </div>
    {#if discoveryLoading}
      <div class="py-4 text-center text-xs text-(--text-secondary)">Scanning audit traces…</div>
    {:else if discoveredFields.length === 0}
      <div class="py-4 text-center text-xs text-(--text-secondary)">No tool fields seen in the recent audit window.</div>
    {:else}
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
        {#each discoveredFields as f}
          <div class="flex items-center justify-between gap-2 p-2 rounded-sm border border-(--border) text-xs">
            <div class="min-w-0 flex-1">
              <code class="text-(--text-primary)">{f.tool_name}.{f.field}</code>
              {#if f.mcp_server}
                <span class="ml-1 px-1.5 py-0.5 rounded-sm bg-(--tag-violet-bg) text-(--tag-violet-text)">mcp:{f.mcp_server}</span>
              {/if}
              {#if f.suggested_tool_id}
                <span class="ml-1 px-1.5 py-0.5 rounded-sm bg-(--tag-teal-bg) text-(--tag-teal-text)" title="Suggested by {f.suggestion_source ?? 'classifier'} — confidence {f.suggestion_confidence ?? 0}">
                  → {f.suggested_tool_id}
                </span>
              {/if}
              <div class="text-(--text-secondary)">seen in {f.occurrences} tool def{f.occurrences === 1 ? '' : 's'}</div>
            </div>
            {#if f.already_covered}
              <span class="text-(--success)">covered</span>
            {:else}
              <button class="px-2 py-1 text-xs bg-(--accent)/20 text-(--accent) rounded-sm hover:bg-(--accent)/30"
                onclick={() => openCreateProfile({
                  tool_name: f.tool_name,
                  field: f.field,
                  suggested_tool_id: f.suggested_tool_id,
                  mcp_server: f.mcp_server,
                })}>Register</button>
            {/if}
          </div>
        {/each}
      </div>
    {/if}
  </div>
{/if}

{#if profilesLoading && fieldProfiles.length === 0}
  <div class="flex items-center gap-3 py-12 justify-center text-(--text-secondary)">
    <div class="w-5 h-5 border-2 border-(--accent) border-t-transparent rounded-full animate-spin"></div>
    Loading field profiles…
  </div>
{:else if filteredProfiles.length === 0}
  <div class="text-center py-12 text-(--text-secondary)">No profiles match the current filters.</div>
{:else}
  <div class="space-y-2">
    {#each filteredProfiles as p}
      <div class="bg-(--bg-card) rounded-xl border border-(--border) p-3">
        <div class="flex items-start gap-3">
          <div class="flex-1 min-w-0">
            <div class="flex items-center gap-2 flex-wrap">
              <span class="text-xs font-mono px-1.5 py-0.5 rounded-sm bg-(--tag-teal-bg) text-(--tag-teal-text)">{p.tool_id ?? '—'}</span>
              <span class="font-mono text-sm text-(--text-primary)">{p.tool_pattern}</span>
              <span class="text-(--text-secondary)">·</span>
              <span class="font-mono text-xs text-(--text-secondary)">arg.{p.field}</span>
              {#if p.wire_field && p.wire_field !== p.field}
                <span class="text-[10px] font-mono text-(--text-secondary)">(wire: {p.wire_field})</span>
              {/if}
              <span class="inline-flex items-center px-1.5 py-0.5 rounded-sm text-[10px] font-medium uppercase text-(--text-secondary) bg-(--bg-elevated) border border-(--border)">{p.normalizer}</span>
              {#if p.mcp_server}
                <span class="inline-flex items-center px-1.5 py-0.5 rounded-sm text-[10px] font-medium text-(--tag-violet-text) bg-(--tag-violet-bg)">mcp:{p.mcp_server}</span>
              {:else if p.app_filter}
                <span class="inline-flex items-center px-1.5 py-0.5 rounded-sm text-[10px] font-medium text-(--tag-blue-text) bg-(--tag-blue-bg)">app:{p.app_filter}</span>
              {:else}
                <span class="inline-flex items-center px-1.5 py-0.5 rounded-sm text-[10px] font-medium text-(--text-secondary) bg-(--bg-elevated) border border-(--border)">generic</span>
              {/if}
              {#if p.is_builtin}
                <span class="inline-flex items-center px-1.5 py-0.5 rounded-sm text-[10px] font-medium text-(--tag-blue-text) bg-(--tag-blue-bg)">builtin</span>
              {:else}
                <span class="inline-flex items-center px-1.5 py-0.5 rounded-sm text-[10px] font-medium text-(--warning) bg-(--warning-bg) border border-(--warning-border)">custom</span>
              {/if}
              <span class="text-[10px] text-(--text-secondary)">priority {p.priority}</span>
            </div>
            {#if p.description}
              <div class="text-[11px] text-(--text-secondary) mt-1 line-clamp-2">{p.description}</div>
            {/if}
            {#if p.source}
              <div class="text-[10px] text-(--text-secondary) mt-0.5">source: {p.source}</div>
            {/if}
          </div>
          <div class="flex items-center gap-1 shrink-0">
            <button onclick={() => openEditProfile(p)} aria-label="Edit"
              class="p-1 rounded-sm hover:bg-(--bg-elevated) text-(--text-secondary) hover:text-(--accent) transition-colors">
              <Icon name="pencil" size="sm" tone="neutral" />
            </button>
            <button onclick={() => deletingProfile = p} aria-label="Delete"
              class="p-1 rounded-sm hover:bg-(--error-bg) text-(--text-secondary) hover:text-(--error) transition-colors">
              <Icon name="trash" size="sm" tone="error" />
            </button>
          </div>
        </div>
      </div>
    {/each}
  </div>
{/if}

<FieldProfileEditModal
  open={profileEditModalOpen}
  initial={editingProfile}
  onclose={() => profileEditModalOpen = false}
  onsaved={handleProfileSaved}
/>

<Modal open={!!deletingProfile} title="Delete field profile" onclose={() => deletingProfile = null}>
  <div class="py-2 space-y-3 text-sm">
    <p>Delete profile <strong>{deletingProfile?.tool_pattern}.{deletingProfile?.field}</strong>?</p>
    {#if deletingProfile?.is_builtin}
      <div class="p-3 rounded-lg bg-(--warning-bg) text-(--warning) text-xs">
        Built-in profile — deleting it marks it as removed so startup sync won't resurrect it. Restore via "Reset built-ins".
      </div>
    {/if}
    <p class="text-xs text-(--text-secondary)">Rules referencing <code>arg.{deletingProfile?.field}</code> on matching tools will fall back to raw (un-normalised) matching.</p>
  </div>
  {#snippet footer()}
    <div class="flex items-center justify-end gap-2">
      <button type="button" onclick={() => deletingProfile = null}
        class="px-4 py-2 text-sm border border-(--border) rounded-lg hover:bg-(--bg-elevated) transition-colors">Cancel</button>
      <button type="button" onclick={confirmProfileDelete}
        class="px-4 py-2 bg-(--error)/90 text-(--error-fg) text-sm rounded-lg hover:bg-(--error) transition-colors">Delete</button>
    </div>
  {/snippet}
</Modal>

<Modal open={profileResetModalOpen} title="Reset built-in profiles" onclose={() => profileResetModalOpen = false}>
  <div class="py-2 space-y-3 text-sm">
    <p>Restore every built-in field profile from the shipped seeds and clear the deleted-built-ins list.</p>
    <ul class="list-disc pl-5 text-(--text-secondary) space-y-1 text-xs">
      <li>Custom profiles are preserved.</li>
      <li>Edits to built-in profiles will be overwritten with the shipped version.</li>
      <li>Built-in profiles you previously deleted will reappear.</li>
    </ul>
  </div>
  {#snippet footer()}
    <div class="flex items-center justify-end gap-2">
      <button type="button" onclick={() => profileResetModalOpen = false}
        class="px-4 py-2 text-sm border border-(--border) rounded-lg hover:bg-(--bg-elevated) transition-colors">Cancel</button>
      <button type="button" disabled={profileResetRunning} onclick={runProfileReset}
        class="px-4 py-2 bg-(--accent) text-(--accent-fg) text-sm rounded-lg hover:bg-(--accent-hover) transition-colors disabled:opacity-60">
        {profileResetRunning ? 'Restoring…' : 'Restore'}
      </button>
    </div>
  {/snippet}
</Modal>
