<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import { extractError } from '#lib/api-helpers.js';
  import { useDirtyForm } from '#lib/hooks.svelte.js';
  import type { components } from '#lib/generated/api-types.js';
  import Modal from '#lib/components/Modal.svelte';
  import ConfirmDialog from '#lib/components/ConfirmDialog.svelte';
  import Copyable from '#lib/components/Copyable.svelte';
  import TextInput from '#lib/components/forms/TextInput.svelte';
  import TextArea from '#lib/components/forms/TextArea.svelte';

  type OauthClientRow = components['schemas']['OauthClientRow'];

  interface Props {
    open: boolean;
    editing: OauthClientRow | null;
    onclose: () => void;
    onsaved: () => void;
  }

  let { open, editing, onclose, onsaved }: Props = $props();

  let form = $state({
    name: '',
    redirect_uris_csv: '',
    client_id_metadata_url: '',
  });
  let formError = $state('');
  /// Surfaces the freshly-issued `client_id` after a successful POST so
  /// the operator can copy it before closing the modal — the only time
  /// it's shown unmasked. Cleared whenever the modal opens fresh.
  let createdClientId = $state<string | null>(null);

  // Unsaved-changes guard (named `dirty` to avoid colliding with the
  // existing `form` state). Snapshot the form once it's seeded from
  // `editing`; derive dirty by signature comparison; Modal `onCloseRequest`
  // and the Cancel button prompt before discarding.
  const dirty = useDirtyForm();
  let snapshot = $state<string | null>(null);
  function fieldSignature() {
    return JSON.stringify([form.name, form.redirect_uris_csv, form.client_id_metadata_url]);
  }

  function parseRedirectUrisCsv(input: string): string[] {
    return input.split(/[\s,]+/).map((s) => s.trim()).filter((s) => s.length > 0);
  }
  function formatRedirectUris(value: unknown): string[] {
    if (!Array.isArray(value)) return [];
    return value.filter((v): v is string => typeof v === 'string');
  }

  $effect(() => {
    if (!open) {
      snapshot = null;
      return;
    }
    createdClientId = null;
    formError = '';
    if (editing) {
      form = {
        name: editing.name,
        redirect_uris_csv: formatRedirectUris(editing.redirect_uris).join('\n'),
        client_id_metadata_url: editing.client_id_metadata_url ?? '',
      };
    } else {
      form = { name: '', redirect_uris_csv: '', client_id_metadata_url: '' };
    }
    queueMicrotask(() => {
      snapshot = fieldSignature();
      dirty.markClean();
    });
  });

  $effect(() => {
    if (!open || snapshot === null) return;
    // Once a client_id has been issued, the form switches to a Done-button
    // post-create view with no save path. Any further field edits cannot be
    // committed, so the unsaved-changes prompt would be misleading — keep
    // the form clean from here on.
    if (createdClientId) {
      dirty.markClean();
      return;
    }
    if (fieldSignature() !== snapshot) dirty.markDirty();
    else dirty.markClean();
  });

  async function save() {
    formError = '';
    const redirect_uris = parseRedirectUrisCsv(form.redirect_uris_csv);
    if (editing) {
      const { error } = await adminApi.PATCH('/api/v1/admin/mcp/oauth-clients/{id}', {
        params: { path: { id: editing.id } },
        body: {
          name: form.name || undefined,
          redirect_uris: redirect_uris.length > 0 ? redirect_uris : undefined,
          client_id_metadata_url: form.client_id_metadata_url
            ? form.client_id_metadata_url
            : null,
        },
      });
      if (error) { formError = extractError(error); return; }
      dirty.markClean();
      onsaved();
    } else {
      const { data, error } = await adminApi.POST('/api/v1/admin/mcp/oauth-clients', {
        body: {
          name: form.name,
          redirect_uris,
          client_id_metadata_url: form.client_id_metadata_url || undefined,
        },
      });
      if (error) { formError = extractError(error); return; }
      dirty.markClean();
      createdClientId = data?.client_id ?? null;
      // Don't close the modal yet — the post-create state shows the
      // freshly-issued client_id and a Done button. The parent only
      // reloads its list (no close on its end either).
      onsaved();
    }
  }
</script>

{#if open}
  <Modal {open} title={editing ? 'Edit OAuth Client' : 'New OAuth Client'} {onclose} onCloseRequest={dirty.confirmDiscard}>
    {#if formError}
      <div class="bg-(--error-bg) border border-(--error-border) text-(--error-text) p-2 rounded-sm mb-3 text-sm">
        {formError}
      </div>
    {/if}
    {#if createdClientId}
      <div class="bg-(--success-bg) border border-(--success-border) text-(--text-primary) p-3 rounded-sm mb-3 space-y-2">
        <div class="text-sm font-semibold text-(--text-primary)">OAuth client registered.</div>
        <div class="text-xs">
          Hand this <code>client_id</code> to the MCP client (paste into the
          <code>OAuth Client ID</code> field of Claude Desktop / Cursor / ChatGPT,
          or use it directly in <code>/authorize</code> requests):
        </div>
        <div class="bg-(--bg-primary) border border-(--success) rounded-sm p-2 text-xs break-all">
          <Copyable value={createdClientId} />
        </div>
      </div>
    {/if}
    <div class="space-y-3">
      <label class="block">
        <span class="text-sm font-medium text-(--text-primary)">Client name</span>
        <TextInput placeholder="Claude Desktop (acme team)" bind:value={form.name} />
        <span class="text-xs text-(--text-secondary)">
          Shown on the consent page so users can distinguish multiple clients.
        </span>
      </label>
      <label class="block">
        <span class="text-sm font-medium text-(--text-primary)">Redirect URIs</span>
        <TextArea
          mono
          rows={3}
          placeholder="https://app.example.com/cb&#10;http://localhost:5173/cb"
          bind:value={form.redirect_uris_csv} />
        <span class="text-xs text-(--text-secondary)">
          One per line (or comma-separated). Each URI must be
          <code>https://</code>, <code>http://localhost*</code>, or
          <code>http://127.0.0.1*</code>. Fragments are rejected (RFC 6749 §3.1.2).
        </span>
      </label>
      <label class="block">
        <span class="text-sm font-medium text-(--text-primary)">
          Client ID Metadata Document URL
          <span class="text-(--text-secondary) text-xs ml-1">(optional, RFC 7591bis §6)</span>
        </span>
        <TextInput
          mono
          placeholder="https://app.example.com/.well-known/oauth-client"
          bind:value={form.client_id_metadata_url} />
        <span class="text-xs text-(--text-secondary)">
          When set, the redirect URIs above are ignored at runtime — Streamscope
          fetches this URL on each <code>/authorize</code> call to honor URI
          rotations without re-registration. SSRF-guarded (no
          loopback/RFC1918/IMDS).
        </span>
      </label>
    </div>
    <div class="flex justify-end gap-2 mt-4">
      <button
        type="button"
        class="px-3 py-1 rounded-lg border border-(--border) text-sm text-(--text-secondary) hover:text-(--text-primary) hover:bg-(--bg-elevated) transition-colors"
        onclick={async () => { if (await dirty.confirmDiscard()) onclose(); }}>
        {createdClientId ? 'Done' : 'Cancel'}
      </button>
      {#if !createdClientId}
        <button
          type="button"
          class="px-3 py-1 bg-(--accent) hover:bg-(--accent-hover) text-(--accent-fg) rounded-lg text-sm font-medium"
          onclick={save}>Save</button>
      {/if}
    </div>
  </Modal>
{/if}

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
