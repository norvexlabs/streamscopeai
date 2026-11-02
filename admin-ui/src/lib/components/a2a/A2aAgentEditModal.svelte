<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import { extractError } from '#lib/api-helpers.js';
  import { useDirtyForm } from '#lib/hooks.svelte.js';
  import type { A2aAgentRow } from '#lib/api-types.js';
  import Modal from '#lib/components/Modal.svelte';
  import ConfirmDialog from '#lib/components/ConfirmDialog.svelte';
  import FormField from '#lib/components/forms/FormField.svelte';
  import TextInput from '#lib/components/forms/TextInput.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';

  interface Props {
    open: boolean;
    editing: A2aAgentRow | null;
    onclose: () => void;
    onsaved: () => void;
  }

  let { open, editing, onclose, onsaved }: Props = $props();

  let form = $state({
    name: '',
    slug: '',
    card_url: '',
    description: '',
    auth_mode: 'no_auth',
    credential: '',
    credential_header: '',
  });
  let formError = $state('');
  let saving = $state(false);

  const dirty = useDirtyForm();
  let snapshot = $state<string | null>(null);
  function fieldSignature() {
    return JSON.stringify([
      form.name,
      form.slug,
      form.card_url,
      form.description,
      form.auth_mode,
      form.credential,
      form.credential_header,
    ]);
  }

  $effect(() => {
    if (!open) {
      snapshot = null;
      return;
    }
    formError = '';
    if (editing) {
      form = {
        name: editing.name,
        slug: editing.slug,
        card_url: editing.card_url,
        description: editing.description ?? '',
        auth_mode: editing.auth_mode,
        credential: '',
        credential_header: editing.credential_header ?? '',
      };
    } else {
      form = {
        name: '',
        slug: '',
        card_url: '',
        description: '',
        auth_mode: 'no_auth',
        credential: '',
        credential_header: '',
      };
    }
    queueMicrotask(() => {
      snapshot = fieldSignature();
      dirty.markClean();
    });
  });

  $effect(() => {
    if (!open || snapshot === null) return;
    if (fieldSignature() !== snapshot) dirty.markDirty();
    else dirty.markClean();
  });

  async function save() {
    saving = true;
    formError = '';
    const shared = {
      name: form.name,
      description: form.description || null,
      auth_mode: form.auth_mode,
      credential: form.credential || null,
      credential_header: form.credential_header || null,
    };
    const result = editing
      ? await adminApi.PATCH('/api/v1/admin/a2a/agents/{id}', {
          params: { path: { id: editing.id } },
          body: {
            ...shared,
            slug: form.slug !== editing.slug ? form.slug : null,
            card_url: form.card_url !== editing.card_url ? form.card_url : null,
          },
        })
      : await adminApi.POST('/api/v1/admin/a2a/agents', {
          body: { ...shared, slug: form.slug, card_url: form.card_url, enabled: true },
        });
    saving = false;
    if (result.error) {
      formError = extractError(result.error);
      return;
    }
    dirty.markClean();
    onsaved();
  }
</script>

<Modal {open} title={editing ? 'Edit A2A Agent' : 'Register A2A Agent'} {onclose} onCloseRequest={dirty.confirmDiscard}>
  {#if formError}
    <div class="bg-(--error-bg) border border-(--error-border) text-(--error-text) p-2 rounded-sm mb-3 text-sm">
      {formError}
    </div>
  {/if}
  <div class="space-y-4">
    <FormField label="Name">
      <TextInput bind:value={form.name} placeholder="Recipe Agent" />
    </FormField>
    <FormField label="Slug" help="Mount handle — the agent becomes reachable at /a2a/<slug>. Globally unique.">
      <TextInput bind:value={form.slug} placeholder="recipes" mono />
    </FormField>
    <FormField
      label="Agent card URL"
      help="The upstream card location (usually https://<agent-host>/.well-known/agent-card.json). Fetched and validated on save; the JSON-RPC 1.0 endpoint is derived from it."
    >
      <TextInput bind:value={form.card_url} placeholder="https://agent.example.com/.well-known/agent-card.json" mono />
    </FormField>
    <FormField label="Description">
      <TextInput bind:value={form.description} placeholder="Optional" />
    </FormField>
    <FormField label="Upstream auth">
      <SelectInput bind:value={form.auth_mode}>
        <option value="no_auth">No auth</option>
        <option value="service_account">Service account (stored credential)</option>
      </SelectInput>
    </FormField>
    {#if form.auth_mode === 'service_account'}
      <FormField
        label="Credential"
        help={editing?.has_credential
          ? 'Leave blank to keep the stored credential; enter a value to rotate it.'
          : 'Sent to the upstream agent on every call. Encrypted at rest, never shown again.'}
      >
        <TextInput bind:value={form.credential} type="password" placeholder={editing?.has_credential ? '(unchanged)' : ''} mono />
      </FormField>
      <FormField label="Credential header" help="Leave blank for Authorization: Bearer; set a header name (e.g. X-Api-Key) to send the credential there instead.">
        <TextInput bind:value={form.credential_header} placeholder="Authorization: Bearer (default)" mono />
      </FormField>
    {/if}
  </div>

  {#snippet footer()}
    <div class="flex justify-end gap-2">
      <button
        onclick={async () => { if (await dirty.confirmDiscard()) onclose(); }}
        class="px-4 py-1.5 text-sm rounded-lg border border-(--border) text-(--text-primary) hover:bg-(--bg-primary)"
      >Cancel</button>
      <button
        onclick={save}
        disabled={saving || !form.name || !form.slug || !form.card_url}
        class="px-4 py-1.5 text-sm rounded-lg bg-(--accent) text-(--accent-fg) hover:bg-(--accent-hover) disabled:opacity-50"
      >{saving ? 'Saving…' : editing ? 'Save' : 'Register'}</button>
    </div>
  {/snippet}
</Modal>

<!-- Wired to the dirty-form discard prompt: without it every close path
     (Escape / backdrop / X / Cancel) awaits a promise that never resolves once
     the form is dirty, trapping the operator in the modal. -->
<ConfirmDialog
  open={dirty.confirmOpen}
  title="Discard changes?"
  message="You have unsaved edits. Discard them?"
  confirmLabel="Discard"
  cancelLabel="Keep editing"
  destructive
  onconfirm={dirty.acceptDiscard}
  oncancel={dirty.rejectDiscard}
/>
