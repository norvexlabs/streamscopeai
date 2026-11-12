<script lang="ts">
  import { untrack } from 'svelte';
  import { adminApi } from '#lib/api-client.js';
  import { extractError, extractErrorCode } from '#lib/api-helpers.js';
  import { profileLists, type ProfileListKind } from '#lib/scope.svelte.js';
  import type { components } from '#lib/generated/api-types.js';
  import { toast } from '#lib/toast.svelte.js';
  import Modal from '#lib/components/Modal.svelte';
  import ConfirmDialog from '#lib/components/ConfirmDialog.svelte';
  import FormField from '#lib/components/forms/FormField.svelte';
  import TextInput from '#lib/components/forms/TextInput.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import EmptyState from '#lib/components/EmptyState.svelte';
  import { page } from '$app/state';
  import { scopeHref } from '#lib/tenant.js';
  import { fetchAllPages } from '#lib/api-helpers.js';
  import { profileUsage, usedByLabel } from '#lib/profileUsage.js';
  import { PROFILE_KINDS, profileCount } from '#lib/profileKinds.js';

  type Profile = components['schemas']['Profile'];

  interface Props {
    /** Which profile family this manager operates on. */
    kind: ProfileListKind;
    /** Lazy-load gate — defer until the hosting tab/section is shown. */
    activate?: boolean;
  }

  let { kind, activate = true }: Props = $props();

  /** What this kind is called and does (`PROFILE_KINDS`: one entry per kind). */
  const info = $derived(PROFILE_KINDS[kind]);
  /** Base route of this kind's drill-down editor — the single, uniform path
   *  every profile card (and the shared-baseline card) links into. */
  const basePath = $derived(`${info.root}/profiles`);
  let profiles = $state<Profile[]>([]);
  let loading = $state(true);
  let loaded = $state(false);
  let loadError = $state('');

  // A kind whose profiles each own their whole content (Portal & clients):
  // always Standalone, a copy of another or the seed, never Off for a workspace.
  const isClientAccess = $derived(info.standaloneOnly);
  const noun = $derived(info.noun);

  // The workspaces each profile applies to — shown for Portal & clients, whose
  // Default switch reaches developers at their next provision, sync or run. `null` until read (and when the
  // read failed): the line is then left out, never shown as "no workspace".
  let usage = $state<Map<string, string[]> | null>(null);
  // Only the latest read lands: a slower one never overwrites it.
  let usageRead = 0;

  /** Read in the background: the list and its actions never wait for it. */
  async function loadUsage(list: Profile[]) {
    const read = ++usageRead;
    let next: Map<string, string[]> | null = null;
    try {
      const workspaces = await fetchAllPages((offset, limit) =>
        adminApi.GET('/api/v1/admin/workspaces', { params: { query: { offset, limit } } }));
      next = profileUsage(kind, list, workspaces);
    } catch {
      next = null;
    }
    if (read === usageRead) usage = next;
  }

  async function load() {
    loading = true;
    loadError = '';
    const read = profileLists.begin(kind);
    const { data, error } = await adminApi.GET('/api/v1/admin/profiles', {
      params: { query: { kind, offset: 0, limit: 200 } },
    });
    if (error) {
      loadError = extractError(error, `Failed to load ${noun}s`);
    } else {
      profiles = data?.items ?? [];
      // Keep the shared profile list (drives the workspace pickers) in sync.
      profileLists.land(read, profiles.map((p) => ({ id: p.id, name: p.name, is_default: p.is_default })));
      if (isClientAccess) void loadUsage(profiles);
    }
    loading = false;
    loaded = true;
  }

  $effect(() => {
    // Only these two drive it: what the load reads (the tenant) does not.
    if (activate && !loaded) untrack(load);
  });

  // ── Create ──
  let showCreate = $state(false);
  let newName = $state('');
  let newDescription = $state('');
  /** 'layered' inherits the Default; 'standalone' owns its full content. */
  let newMode = $state<'layered' | 'standalone'>('layered');
  /** 'blank' | 'seed' | a profile id to deep-copy from. 'seed' is only offered
   *  for standalone (a layered profile already has the Default beneath it). */
  let startSource = $state('blank');
  let creating = $state(false);

  // A layered profile can't start from the seed (it would duplicate the Default).
  $effect(() => {
    if (newMode === 'layered' && startSource === 'seed') startSource = 'blank';
  });

  function openCreate() {
    newName = ''; newDescription = '';
    if (isClientAccess) {
      // A copy of the Default unless the admin picks another start.
      newMode = 'standalone';
      startSource = profiles.find((p) => p.is_default)?.id ?? 'seed';
    } else {
      newMode = 'layered'; startSource = 'blank';
    }
    showCreate = true;
  }

  async function create() {
    if (!newName.trim()) return;
    creating = true;
    const content =
      startSource === 'blank'
        ? ({ kind: 'blank' } as const)
        : startSource === 'seed'
          ? ({ kind: 'seed' } as const)
          : ({ kind: 'copy', id: startSource } as const);
    const start_from =
      newMode === 'standalone'
        ? ({ mode: 'standalone', content } as const)
        : ({ mode: 'layered', content } as const);
    const { error } = await adminApi.POST('/api/v1/admin/profiles', {
      body: {
        kind,
        name: newName.trim(),
        description: newDescription.trim() || null,
        start_from,
      },
    });
    creating = false;
    if (error) {
      const code = extractErrorCode(error);
      if (code === 'profile_name_taken') {
        toast.error('Name already in use', { body: 'Pick a different name for this profile.' });
      } else {
        toast.error('Failed to create profile', { body: extractError(error), code: code ?? undefined });
      }
      return;
    }
    toast.success('Profile created');
    showCreate = false;
    await load();
  }

  // ── Rename ──
  let showEdit = $state(false);
  let editId = $state('');
  let editName = $state('');
  let editDescription = $state('');

  function openEdit(p: Profile) {
    editId = p.id; editName = p.name; editDescription = p.description ?? '';
    showEdit = true;
  }

  async function saveEdit() {
    if (!editName.trim()) return;
    const { error } = await adminApi.PATCH('/api/v1/admin/profiles/{id}', {
      params: { path: { id: editId } },
      body: { name: editName.trim(), description: editDescription.trim() || null },
    });
    if (error) { toast.error('Failed to save', { body: extractError(error) }); return; }
    toast.success('Profile updated');
    showEdit = false;
    await load();
  }

  // ── Set as default ──
  // Portal & clients asks first: the switch reaches every developer of the
  // workspaces on the Default at their next provision, sync or run.
  let confirmDefault = $state<Profile | null>(null);
  function askDefault(p: Profile) {
    if (isClientAccess) confirmDefault = p;
    else void setDefault(p);
  }
  async function setDefault(p: Profile) {
    confirmDefault = null;
    const { error } = await adminApi.POST('/api/v1/admin/profiles/{id}/actions/set-default', {
      params: { path: { id: p.id } },
    });
    if (error) { toast.error('Failed to set default', { body: extractError(error) }); return; }
    toast.success(`${p.name} is now the default`);
    await load();
  }

  // ── Delete ──
  let confirmId = $state('');
  function askDelete(p: Profile) {
    confirmId = p.id;
  }
  async function doDelete() {
    const idToDelete = confirmId;
    confirmId = '';
    const { error } = await adminApi.DELETE('/api/v1/admin/profiles/{id}', {
      params: { path: { id: idToDelete } },
    });
    if (error) {
      const code = extractErrorCode(error);
      if (code === 'profile_default_protected') {
        toast.error('Cannot delete the default', { body: 'Set another profile as default first.' });
      } else {
        toast.error('Failed to delete', { body: extractError(error) });
      }
      return;
    }
    toast.success('Profile deleted');
    await load();
  }

  function manageLink(id: string): string {
    return scopeHref(page.params.slug ?? '', page.url.pathname, `${basePath}/${id}`);
  }
</script>

<div class="flex items-start justify-between mb-4 gap-4">
  {#if isClientAccess}
  <p class="text-sm text-(--text-secondary) max-w-2xl">
    The <strong>Default</strong> applies to every workspace with no profile of its own. Another
    profile is an independent copy: assign it to a workspace (Workspaces → Access) to give that team
    its own clients and sandbox rules. An edit to the Default does not reach it.
    {info.openHint}
  </p>
  {:else}
  <p class="text-sm text-(--text-secondary) max-w-2xl">
    The <strong>Default</strong> is the shared base. <strong>Layered</strong> profiles build on it
    (no duplication); <strong>Standalone</strong> profiles are independent (forked from the built-in
    defaults, or blank). A workspace assigned <strong>Off</strong> runs {info.offRuns}.
    {info.openHint}
  </p>
  {/if}
  <button onclick={openCreate} class="px-3 py-1.5 text-sm rounded-lg bg-(--accent) text-(--accent-fg) hover:bg-(--accent-hover) shrink-0">+ New profile</button>
</div>

{#if loading}
  <div class="text-sm text-(--text-secondary)">Loading…</div>
{:else if loadError}
  <div class="px-3 py-2 rounded-lg bg-(--error-bg) border border-(--error-border) text-sm text-(--error-text)">{loadError}</div>
{:else}
  {#if profiles.length === 0}
    <EmptyState title={`No ${noun}s`} body={`Create one to apply a distinct ${info.distinct} to a workspace.`} />
  {:else}
    <div class="bg-(--bg-card) rounded-xl border border-(--border) divide-y divide-(--border)">
      {#each profiles as p (p.id)}
        <div class="px-5 py-3 flex items-center justify-between gap-4" data-testid="profile-row" data-profile={p.name}>
          <a href={manageLink(p.id)} class="min-w-0 group">
            <div class="flex items-center gap-2">
              <span class="text-sm text-(--text-primary) group-hover:text-(--accent) truncate">{p.name}</span>
              {#if p.is_default}
                <span class="px-2 py-0.5 text-[10px] rounded-full bg-(--accent)/10 text-(--accent)">Default</span>
              {:else if isClientAccess}
                <!-- Every profile of the kind is an independent copy: no mode to tell apart. -->
              {:else if p.standalone}
                <span class="px-2 py-0.5 text-[10px] rounded-full bg-(--bg-secondary) text-(--text-secondary)">Standalone</span>
              {:else}
                <span class="px-2 py-0.5 text-[10px] rounded-full bg-(--bg-secondary) text-(--text-secondary)">Layered</span>
              {/if}
            </div>
            {#if p.description}<p class="text-xs text-(--text-secondary) truncate">{p.description}</p>{/if}
            {#if isClientAccess && usage}
              <p class="text-xs text-(--text-secondary) truncate" data-testid="profile-used-by" title={(usage.get(p.id) ?? []).join(', ')}>{usedByLabel(usage.get(p.id) ?? [])}</p>
            {/if}
          </a>
          <div class="flex items-center gap-4 shrink-0">
            {#if profileCount(info, p)}
              {@const count = profileCount(info, p)}
              <span class="text-xs font-mono text-(--text-secondary)" title={count?.title}>{count?.text}</span>
            {/if}
            <a href={manageLink(p.id)} class="text-xs text-(--accent) hover:underline">Edit →</a>
            <button onclick={() => openEdit(p)} class="text-xs text-(--text-secondary) hover:text-(--text-primary)">Rename</button>
            {#if !p.is_default}
              <button onclick={() => askDefault(p)} class="text-xs text-(--text-secondary) hover:text-(--text-primary)">Set as default</button>
              <button onclick={() => askDelete(p)} class="text-xs text-(--error) hover:underline">Delete</button>
            {/if}
          </div>
        </div>
      {/each}
    </div>
  {/if}
{/if}

<!-- Create -->
<Modal open={showCreate} title={`New ${noun}`} onclose={() => (showCreate = false)} maxWidth="max-w-md">
  <div class="space-y-4">
    <FormField label="Name"><TextInput bind:value={newName} placeholder={info.placeholder} /></FormField>
    <FormField label="Description"><TextInput bind:value={newDescription} placeholder="Optional" /></FormField>
    {#if isClientAccess}
    <FormField label="Start from" help="The new profile is an independent copy: later edits to its source do not reach it.">
      <SelectInput bind:value={startSource}>
        {#each profiles as p (p.id)}
          <option value={p.id}>Copy {p.name}{p.is_default ? ' (default)' : ''}</option>
        {/each}
        <option value="seed">{info.seedOption}</option>
      </SelectInput>
    </FormField>
    {:else}
    <FormField label="Relationship to the Default" help={newMode === 'layered'
      ? 'Builds on the Default and adds only its own — no duplication; tracks Default edits.'
      : 'Independent of the Default — owns its full content.'}>
      <SelectInput bind:value={newMode}>
        <option value="layered">Layered — build on the Default</option>
        <option value="standalone">Standalone — independent copy</option>
      </SelectInput>
    </FormField>
    <FormField label="Start from">
      <SelectInput bind:value={startSource}>
        {#if newMode === 'standalone'}
          <option value="seed">{info.seedOption}</option>
        {/if}
        <option value="blank">{info.blankOption ?? (newMode === 'layered' ? 'Blank — just the Default' : 'Blank — empty')}</option>
        {#each profiles as p (p.id)}
          <option value={p.id}>Copy {p.name}{p.is_default ? ' (default)' : ''}</option>
        {/each}
      </SelectInput>
    </FormField>
    {/if}
    <div class="flex justify-end gap-2">
      <button onclick={() => (showCreate = false)} class="px-4 py-1.5 text-sm rounded-lg text-(--text-secondary) hover:text-(--text-primary)">Cancel</button>
      <button onclick={create} disabled={creating || !newName.trim()} class="px-4 py-1.5 text-sm rounded-lg bg-(--accent) text-(--accent-fg) hover:bg-(--accent-hover) disabled:opacity-50">{creating ? 'Creating…' : 'Create'}</button>
    </div>
  </div>
</Modal>

<!-- Rename -->
<Modal open={showEdit} title={`Edit ${noun}`} onclose={() => (showEdit = false)} maxWidth="max-w-md">
  <div class="space-y-4">
    <FormField label="Name"><TextInput bind:value={editName} /></FormField>
    <FormField label="Description"><TextInput bind:value={editDescription} placeholder="Optional" /></FormField>
    <div class="flex justify-end gap-2">
      <button onclick={() => (showEdit = false)} class="px-4 py-1.5 text-sm rounded-lg text-(--text-secondary) hover:text-(--text-primary)">Cancel</button>
      <button onclick={saveEdit} disabled={!editName.trim()} class="px-4 py-1.5 text-sm rounded-lg bg-(--accent) text-(--accent-fg) hover:bg-(--accent-hover) disabled:opacity-50">Save</button>
    </div>
  </div>
</Modal>

<ConfirmDialog
  open={!!confirmId}
  title={`Delete ${noun}`}
  message={'Delete this profile? Its own content is removed and any workspace using it falls back to the Default.'}
  confirmLabel="Delete"
  destructive
  onconfirm={doDelete}
  oncancel={() => (confirmId = '')}
/>

<ConfirmDialog
  open={!!confirmDefault}
  title="Set as default"
  message={`Make ${confirmDefault?.name ?? 'this profile'} the Default? Every workspace with no profile of its own, and the Agent and Inline AI workspaces, follow its clients and sandbox rules at their developers' next provision, sync or run; the portal Quickstart follows on its next load.`}
  confirmLabel="Set as default"
  onconfirm={() => confirmDefault && setDefault(confirmDefault)}
  oncancel={() => (confirmDefault = null)}
/>
