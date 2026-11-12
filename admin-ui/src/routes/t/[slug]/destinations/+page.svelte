<script lang="ts">
  // Destination lists: named sets of network destinations that a consumer
  // attaches as allow or block — the developers' sandbox (Governance →
  // Portal & clients) and the built-in Web tool (Gateways → MCP → Web).
  import { onMount } from 'svelte';
  import { adminApi } from '#lib/api-client.js';
  import { extractError, extractErrorCode } from '#lib/api-helpers.js';
  import { toast } from '#lib/toast.svelte.js';
  import { useDirtyForm } from '#lib/hooks.svelte.js';
  import { entriesFromText, useLabel } from '#lib/destinationAttachments.js';
  import Page from '#lib/components/page/Page.svelte';
  import Skeleton from '#lib/components/Skeleton.svelte';
  import EmptyState from '#lib/components/EmptyState.svelte';
  import ConfirmDialog from '#lib/components/ConfirmDialog.svelte';
  import FormModal from '#lib/components/forms/FormModal.svelte';
  import TextInput from '#lib/components/forms/TextInput.svelte';
  import TextArea from '#lib/components/forms/TextArea.svelte';
  import type { components } from '#lib/generated/api-types.js';

  type DestinationList = components['schemas']['DestinationList'];

  let lists = $state<DestinationList[]>([]);
  // The Portal & clients profiles by id, to name the profile behind a sandbox
  // use. Empty until read, and when the read fails: the chips then go unnamed.
  let profileNames = $state<Map<string, string>>(new Map());
  let loading = $state(true);

  const form = useDirtyForm();
  let editing = $state<{ open: boolean; id: string | null }>({ open: false, id: null });
  let draft = $state({ name: '', description: '', entries: '' });
  let saving = $state(false);
  let formError = $state<string | null>(null);
  let confirmDelete = $state<DestinationList | null>(null);
  let confirmResetAll = $state(false);

  async function load() {
    loading = true;
    const { data, error } = await adminApi.GET('/api/v1/admin/destination-lists', { params: { query: { limit: 500 } } });
    loading = false;
    if (error) {
      toast.error('Failed to load destination lists', { body: extractError(error), code: extractErrorCode(error) ?? undefined });
      return;
    }
    lists = data?.items ?? [];
    const profiles = await adminApi.GET('/api/v1/admin/profiles', { params: { query: { kind: 'client_access', limit: 200 } } });
    if (profiles.data) profileNames = new Map(profiles.data.items.map((p) => [p.id, p.name]));
  }

  function openCreate() {
    draft = { name: '', description: '', entries: '' };
    formError = null;
    editing = { open: true, id: null };
    form.markClean();
  }

  function openEdit(l: DestinationList) {
    draft = { name: l.name, description: l.description, entries: l.entries.join('\n') };
    formError = null;
    editing = { open: true, id: l.id };
    form.markClean();
  }

  async function closeEdit() {
    if (!(await form.confirmDiscard())) return;
    editing = { open: false, id: null };
  }

  async function save() {
    saving = true;
    formError = null;
    const body = { name: draft.name, description: draft.description, entries: entriesFromText(draft.entries) };
    const { error } = editing.id
      ? await adminApi.PATCH('/api/v1/admin/destination-lists/{id}', { params: { path: { id: editing.id } }, body })
      : await adminApi.POST('/api/v1/admin/destination-lists', { body });
    saving = false;
    if (error) {
      formError = extractError(error);
      return;
    }
    form.markClean();
    editing = { open: false, id: null };
    toast.success('Destination list saved');
    await load();
  }

  async function performDelete() {
    const l = confirmDelete;
    confirmDelete = null;
    if (!l) return;
    const { error } = await adminApi.DELETE('/api/v1/admin/destination-lists/{id}', { params: { path: { id: l.id } } });
    if (error) {
      toast.error('Failed to delete the list', { body: extractError(error), code: extractErrorCode(error) ?? undefined });
      return;
    }
    toast.success(`Deleted ${l.name}`);
    await load();
  }

  async function reset(l: DestinationList) {
    const { error } = await adminApi.POST('/api/v1/admin/destination-lists/{id}/actions/reset', { params: { path: { id: l.id } } });
    if (error) {
      toast.error('Failed to reset the list', { body: extractError(error), code: extractErrorCode(error) ?? undefined });
      return;
    }
    toast.success(`${l.name} restored from the seed`);
    await load();
  }

  async function resetAll() {
    confirmResetAll = false;
    const { error } = await adminApi.POST('/api/v1/admin/destination-lists/actions/reset');
    if (error) {
      toast.error('Failed to restore the seeded lists', { body: extractError(error), code: extractErrorCode(error) ?? undefined });
      return;
    }
    toast.success('Seeded lists restored');
    await load();
  }

  onMount(load);
</script>

<Page
  title="Destinations"
  subtitle="Named sets of network destinations. The developers' sandbox and the Web tool each attach lists, as allow or block. Not the platform's egress list: a list never opens what the gateway itself may reach."
>
  {#snippet actions()}
    <div class="flex items-center gap-2">
      <button
        onclick={() => (confirmResetAll = true)}
        class="px-3 py-1.5 text-xs border border-(--border) text-(--text-secondary) hover:text-(--text-primary) rounded-lg transition-colors"
      >Restore seeded lists…</button>
      <button
        onclick={openCreate}
        class="px-3 py-1.5 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-xs font-medium transition-colors"
      >+ Add list</button>
    </div>
  {/snippet}

  <div class="rounded-lg border border-(--border) bg-(--bg-card) overflow-hidden">
    {#if loading}
      <div class="divide-y divide-(--border)">
        {#each Array(4) as _, i (i)}
          <div class="px-4 py-3"><Skeleton variant="row" /></div>
        {/each}
      </div>
    {:else if lists.length === 0}
      <EmptyState title="No destination lists" body="Add a list, or restore the seeded ones." />
    {:else}
      <div class="divide-y divide-(--border)">
        {#each lists as l (l.id)}
          <div class="px-4 py-3 flex items-center justify-between gap-3" data-testid="destination-list-row">
            <div class="min-w-0">
              <div class="flex items-center gap-2">
                <span class="text-sm font-medium text-(--text-primary) truncate">{l.name}</span>
                {#if l.seeded && l.is_builtin}
                  <span class="px-1.5 py-0.5 text-[10px] rounded-sm bg-(--bg-primary) text-(--text-secondary) border border-(--border)">built-in</span>
                {:else if l.seeded}
                  <span class="px-1.5 py-0.5 text-[10px] rounded-sm bg-(--info-bg) text-(--info-text) border border-(--info-border)">edited</span>
                {/if}
                <span class="text-xs text-(--text-tertiary)">{l.entries.length} entr{l.entries.length === 1 ? 'y' : 'ies'}</span>
                {#each l.used_by as u, i (i)}
                  <span class="px-1.5 py-0.5 text-[10px] rounded-sm bg-(--bg-primary) text-(--text-secondary) border border-(--border)">{useLabel(u, profileNames)}</span>
                {/each}
              </div>
              {#if l.description}
                <p class="text-xs text-(--text-secondary) mt-0.5 truncate">{l.description}</p>
              {/if}
            </div>
            <div class="flex items-center gap-3 shrink-0">
              <button onclick={() => openEdit(l)} class="text-xs text-(--accent) hover:underline">Edit</button>
              {#if l.seeded && !l.is_builtin}
                <button onclick={() => reset(l)} class="text-xs text-(--text-secondary) hover:text-(--text-primary) hover:underline" title="Restore the seeded version">Reset</button>
              {/if}
              <button onclick={() => (confirmDelete = l)} class="text-xs text-(--error) hover:underline">Delete</button>
            </div>
          </div>
        {/each}
      </div>
    {/if}
  </div>
</Page>

<FormModal
  open={editing.open}
  title={editing.id ? 'Edit destination list' : 'New destination list'}
  {form}
  {saving}
  error={formError}
  saveLabel={editing.id ? 'Save changes' : 'Create list'}
  saveDisabled={draft.name.trim().length === 0}
  saveDisabledHint="A list needs a name"
  onclose={closeEdit}
  onsave={save}
>
  <div class="space-y-3">
    <label class="block text-xs text-(--text-secondary)">Name
      <TextInput bind:value={draft.name} oninput={form.markDirty} placeholder="Internal services" class="mt-1" />
    </label>
    <label class="block text-xs text-(--text-secondary)">Description
      <TextInput bind:value={draft.description} oninput={form.markDirty} class="mt-1" />
    </label>
    <label class="block text-xs text-(--text-secondary)">Entries, one per line
      <TextArea bind:value={draft.entries} oninput={form.markDirty} mono rows={10} class="mt-1"
        placeholder={'git.corp.example:443,22\n*.corp.example\n10.20.0.0/16:5000'} />
    </label>
    <p class="text-xs text-(--text-tertiary)">
      An entry is a host name, <code class="font-mono">*.suffix</code> (names under it, never the suffix itself), an IP
      address or a CIDR prefix, then optionally <code class="font-mono">:</code> and ports
      (<code class="font-mono">443,8000-8100</code>; 443 when absent). The cloud metadata address is never reachable.
    </p>
  </div>
</FormModal>

<ConfirmDialog
  open={confirmDelete !== null}
  title="Delete destination list"
  message={confirmDelete
    ? confirmDelete.seeded
      ? `Delete "${confirmDelete.name}"? It came from the seed, so it is hidden rather than destroyed; "Restore seeded lists" brings it back. It is detached everywhere.`
      : `Delete "${confirmDelete.name}"? It is removed permanently and detached everywhere.`
    : ''}
  confirmLabel="Delete"
  destructive
  onconfirm={performDelete}
  oncancel={() => (confirmDelete = null)}
/>

<ConfirmDialog
  open={confirmResetAll}
  title="Restore seeded lists"
  message="Every seeded list goes back to the seed's version, edited and deleted ones included. Lists you created are kept."
  confirmLabel="Restore"
  onconfirm={resetAll}
  oncancel={() => (confirmResetAll = false)}
/>
