<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import { extractError } from '#lib/api-helpers.js';
  import { useDirtyForm } from '#lib/hooks.svelte.js';
  import type { components } from '#lib/generated/api-types.js';
  import Modal from '#lib/components/Modal.svelte';
  import ConfirmDialog from '#lib/components/ConfirmDialog.svelte';
  import TextInput from '#lib/components/forms/TextInput.svelte';
  import TextArea from '#lib/components/forms/TextArea.svelte';

  type VirtualServerRow = components['schemas']['McpVirtualServerRow'];

  interface Props {
    open: boolean;
    /** Row to edit, or `null` to create a new one. */
    editing: VirtualServerRow | null;
    onclose: () => void;
    /** Called after a successful save so the parent can refresh. */
    onsaved: () => void;
  }

  let { open, editing, onclose, onsaved }: Props = $props();

  let form = $state({
    slug: '',
    name: '',
    description: '',
    display_title: '',
    website_url: '',
    enabled: true,
    oauth_enabled: false,
    sampling_intercept_enabled: false,
    /** Plaintext bearer the operator just pasted. Empty string = leave existing
     * ciphertext alone on save (the row already has one). The blur-clear marker
     * lets us distinguish "didn't touch" from "explicitly clear". */
    sampling_credential: '',
    /** Tracks whether the operator has typed in the credential field at all
     * during this open. When true and the field is empty we send `""` to clear
     * the stored bearer; when false we send `undefined` to keep it. */
    sampling_credential_touched: false,
    sampling_model_alias: '',
  });
  let formError = $state('');

  // Unsaved-changes guard — see FieldProfileEditModal / RuleEditModal /
  // OAuthClientEditModal for the same pattern. Named `dirty` here because
  // `form` is the existing local state object.
  const dirty = useDirtyForm();
  let snapshot = $state<string | null>(null);
  function fieldSignature() {
    return JSON.stringify([
      form.slug, form.name, form.description, form.display_title, form.website_url,
      form.enabled, form.oauth_enabled,
      form.sampling_intercept_enabled, form.sampling_credential,
      form.sampling_credential_touched, form.sampling_model_alias,
    ]);
  }

  // Reset the form whenever the parent flips `open` from false → true,
  // so the next "New" or "Edit" press starts fresh.
  $effect(() => {
    if (!open) {
      snapshot = null;
      return;
    }
    if (editing) {
      form = {
        slug: editing.slug,
        name: editing.name,
        description: editing.description ?? '',
        display_title: editing.display_title ?? '',
        website_url: editing.website_url ?? '',
        enabled: editing.enabled,
        oauth_enabled: editing.oauth_enabled,
        sampling_intercept_enabled: editing.sampling_intercept_enabled ?? false,
        sampling_credential: '',
        sampling_credential_touched: false,
        sampling_model_alias: editing.sampling_model_alias ?? '',
      };
    } else {
      form = {
        slug: '',
        name: '',
        description: '',
        display_title: '',
        website_url: '',
        enabled: true,
        oauth_enabled: false,
        sampling_intercept_enabled: false,
        sampling_credential: '',
        sampling_credential_touched: false,
        sampling_model_alias: '',
      };
    }
    formError = '';
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

  /** Resolve the credential field into the patch shape:
   *  - undefined → leave stored ciphertext alone
   *  - "" (empty after touching) → clear the stored bearer (NULL in DB)
   *  - "sk-..." → encrypt + replace
   */
  function resolveCredentialPatch(): string | undefined {
    if (!form.sampling_credential_touched) return undefined;
    return form.sampling_credential;
  }

  async function save() {
    formError = '';
    // Local validation: enabling intercept requires both alias AND
    // credential set (either pasted now or already on the row).
    const hasCredentialNow = form.sampling_credential.length > 0
      || (editing?.sampling_credential_set === true && !form.sampling_credential_touched);
    const hasAliasNow = form.sampling_model_alias.trim().length > 0;
    if (form.sampling_intercept_enabled && (!hasCredentialNow || !hasAliasNow)) {
      formError = 'Sampling intercept requires both a credential and a model alias.';
      return;
    }
    if (editing) {
      // display_title / website_url tri-state: `undefined` keeps the stored
      // value; `""` clears it; otherwise replace. We send the empty string
      // when the operator deleted the field's contents.
      const trimmedTitle = form.display_title.trim();
      const trimmedUrl = form.website_url.trim();
      const titlePatch =
        trimmedTitle === (editing.display_title ?? '') ? undefined : trimmedTitle;
      const urlPatch =
        trimmedUrl === (editing.website_url ?? '') ? undefined : trimmedUrl;
      const { error } = await adminApi.PATCH('/api/v1/admin/mcp/virtual-servers/{id}', {
        params: { path: { id: editing.id } },
        body: {
          name: form.name,
          description: form.description || undefined,
          display_title: titlePatch,
          website_url: urlPatch,
          enabled: form.enabled,
          oauth_enabled: form.oauth_enabled,
          sampling_intercept_enabled: form.sampling_intercept_enabled,
          sampling_credential: resolveCredentialPatch(),
          sampling_model_alias: form.sampling_model_alias.trim() || undefined,
        },
      });
      if (error) { formError = extractError(error); return; }
    } else {
      const { error } = await adminApi.POST('/api/v1/admin/mcp/virtual-servers', {
        body: {
          slug: form.slug,
          name: form.name,
          description: form.description || undefined,
          display_title: form.display_title.trim() || undefined,
          website_url: form.website_url.trim() || undefined,
          enabled: form.enabled,
          oauth_enabled: form.oauth_enabled,
          sampling_intercept_enabled: form.sampling_intercept_enabled,
          sampling_credential: form.sampling_credential || undefined,
          sampling_model_alias: form.sampling_model_alias.trim() || undefined,
        },
      });
      if (error) { formError = extractError(error); return; }
    }
    dirty.markClean();
    onsaved();
  }
</script>

{#if open}
  <Modal {open} title={editing ? 'Edit Downstream' : 'New Downstream'} {onclose} onCloseRequest={dirty.confirmDiscard}>
    {#if formError}
      <div class="bg-(--error-bg) border border-(--error-border) text-(--error-text) p-2 rounded-sm mb-3 text-sm">{formError}</div>
    {/if}
    <div class="space-y-3">
      {#if !editing}
        <label class="block">
          <span class="text-sm font-medium text-(--text-primary)">Slug</span>
          <TextInput mono placeholder="github-bot" bind:value={form.slug} />
          <span class="text-xs text-(--text-secondary)">Lowercase letters, digits, hyphens. 1–31 chars. Must start with a letter.</span>
        </label>
      {/if}
      <label class="block">
        <span class="text-sm font-medium text-(--text-primary)">Name</span>
        <TextInput bind:value={form.name} />
      </label>
      <label class="block">
        <span class="text-sm font-medium text-(--text-primary)">Description</span>
        <TextInput bind:value={form.description} />
      </label>
      <label class="block">
        <span class="text-sm font-medium text-(--text-primary)">Display title <span class="text-xs text-(--text-tertiary) font-normal">(optional)</span></span>
        <TextInput placeholder={form.name || 'Defaults to Name'} bind:value={form.display_title} />
        <span class="text-xs text-(--text-secondary)">MCP <code class="font-mono">serverInfo.title</code> — display-friendly variant clients show in their UI.</span>
      </label>
      <label class="block">
        <span class="text-sm font-medium text-(--text-primary)">Website URL <span class="text-xs text-(--text-tertiary) font-normal">(optional)</span></span>
        <TextInput type="url" placeholder="https://example.com" bind:value={form.website_url} />
        <span class="text-xs text-(--text-secondary)">MCP <code class="font-mono">serverInfo.websiteUrl</code> — surfaced by clients that link out to product pages.</span>
      </label>
      <label class="flex items-center justify-between gap-2 pt-2">
        <span class="text-sm font-medium text-(--text-primary)">Enabled</span>
        <input type="checkbox" bind:checked={form.enabled} class="w-4 h-4" />
      </label>
      <div class="border border-(--border) rounded-sm p-3 space-y-2">
        <label class="flex items-center justify-between gap-2">
          <div>
            <div class="text-sm font-semibold text-(--text-primary)">OAuth 2.1 endpoint</div>
            <p class="text-xs text-(--text-secondary)">
              Allow native MCP clients (Claude Desktop, Cursor, ChatGPT) to discover this downstream via RFC 9728 metadata.
              The slug must be globally unique among OAuth-enabled downstreams. Existing
              <code class="bg-(--bg-primary) px-1.5 py-0.5 rounded-sm text-(--text-primary)">sk-*</code>
              keys keep working alongside.
            </p>
          </div>
          <input type="checkbox" bind:checked={form.oauth_enabled} class="w-4 h-4 mt-0.5" />
        </label>
      </div>

      <div class="border border-(--border) rounded-sm p-3 space-y-2">
        <label class="flex items-center justify-between gap-2">
          <div>
            <div class="text-sm font-semibold text-(--text-primary)">Sampling intercept</div>
            <p class="text-xs text-(--text-secondary)">
              Answer upstream <code class="bg-(--bg-primary) px-1 py-0.5 rounded-sm text-(--text-primary)">sampling/createMessage</code> calls
              through the gateway's LLM pipeline (auth, budgets, audit, transforms) instead of
              forwarding to the connected agent. Without this toggle, sampling traffic escapes
              audit and budget enforcement.
            </p>
          </div>
          <input type="checkbox" bind:checked={form.sampling_intercept_enabled} class="w-4 h-4 mt-0.5" />
        </label>
        {#if form.sampling_intercept_enabled}
          <div class="space-y-2 pt-2 border-t border-(--border)">
            <label class="block">
              <span class="text-xs font-medium text-(--text-primary)">Model alias</span>
              <TextInput mono placeholder="claude-default" bind:value={form.sampling_model_alias} />
              <span class="text-xs text-(--text-secondary)">Resolved by this tenant's model router (same name as in <strong>Models</strong>).</span>
            </label>
            <div class="block space-y-1">
              <div class="flex items-center justify-between gap-2">
                <span class="text-xs font-medium text-(--text-primary)">LLM bearer (write-only)</span>
                {#if editing?.sampling_credential_set && !form.sampling_credential_touched}
                  <button
                    type="button"
                    class="text-xs text-(--error) hover:bg-(--error-bg) px-1.5 py-0.5 rounded-sm"
                    onclick={() => { form.sampling_credential = ''; form.sampling_credential_touched = true; }}
                  >Clear stored</button>
                {:else if form.sampling_credential_touched && editing?.sampling_credential_set}
                  <button
                    type="button"
                    class="text-xs text-(--text-secondary) hover:text-(--text-primary) px-1.5 py-0.5 rounded-sm"
                    onclick={() => { form.sampling_credential = ''; form.sampling_credential_touched = false; }}
                  >Cancel — keep stored</button>
                {/if}
              </div>
              <TextArea
                mono
                rows={2}
                placeholder={editing?.sampling_credential_set ? 'leave blank to keep current; paste new key to replace' : 'sk-... or vk-... bearer'}
                oninput={() => { form.sampling_credential_touched = true; }}
                bind:value={form.sampling_credential} />
              <span class="text-xs text-(--text-secondary) block">
                {#if form.sampling_credential_touched && form.sampling_credential === '' && editing?.sampling_credential_set}
                  <span class="text-(--warning)">Stored bearer will be cleared on save.</span>
                {:else if editing?.sampling_credential_set}
                  A bearer is currently stored. Encrypted at rest with the gateway's process key.
                {:else}
                  Encrypted at rest with the gateway's process key. Never returned over the API.
                {/if}
              </span>
            </div>
          </div>
        {/if}
      </div>
    </div>
    <div class="flex justify-end gap-2 mt-4">
      <button type="button" class="px-3 py-1 rounded-lg border border-(--border) text-sm text-(--text-secondary) hover:text-(--text-primary) hover:bg-(--bg-elevated) transition-colors" onclick={async () => { if (await dirty.confirmDiscard()) onclose(); }}>Cancel</button>
      <button type="button" class="px-3 py-1 bg-(--accent) hover:bg-(--accent-hover) text-(--accent-fg) rounded-lg text-sm font-medium" onclick={save}>Save</button>
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
