<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import { extractError } from '#lib/api-helpers.js';
  import { useDirtyForm } from '#lib/hooks.svelte.js';
  import type { components } from '#lib/generated/api-types.js';
  import Modal from '#lib/components/Modal.svelte';
  import TextInput from '#lib/components/forms/TextInput.svelte';
  import TextArea from '#lib/components/forms/TextArea.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';

  type CatalogEntry = components['schemas']['McpCatalogEntry'];

  interface Props {
    open: boolean;
    /// `null` → create a new custom entry; a row → edit it (editing a built-in
    /// converts it to a user entry server-side so seed-sync stops overwriting it).
    editing: CatalogEntry | null;
    onclose: () => void;
    onsaved: () => void;
  }

  let { open, editing, onclose, onsaved }: Props = $props();

  let form = $state({
    name: '',
    display_title: '',
    description: '',
    category: '',
    upstream_url: '',
    transport: 'streamable_http',
    auth_mode: 'no_auth',
    featured: false,
    website_url: '',
    repository_url: '',
    icon_url: '',
    oauth_issuer_url: '',
    oauth_authorization_url: '',
    oauth_token_url: '',
    oauth_revocation_url: '',
    oauth_default_scopes_csv: '',
    enabled: true,
  });
  let formError = $state('');

  const isOauth = $derived(form.auth_mode === 'per_user_oauth');

  const dirty = useDirtyForm();
  let snapshot = $state<string | null>(null);
  function fieldSignature() {
    return JSON.stringify([
      form.name, form.display_title, form.description, form.category, form.upstream_url,
      form.transport, form.auth_mode, form.featured, form.website_url, form.repository_url,
      form.icon_url, form.oauth_issuer_url, form.oauth_authorization_url, form.oauth_token_url,
      form.oauth_revocation_url, form.oauth_default_scopes_csv, form.enabled,
    ]);
  }

  $effect(() => {
    if (!open) {
      snapshot = null;
      return;
    }
    if (editing) {
      form = {
        name: editing.name,
        display_title: editing.display_title ?? '',
        description: editing.description ?? '',
        category: editing.category ?? '',
        upstream_url: editing.upstream_url,
        transport: editing.transport,
        auth_mode: editing.auth_mode,
        featured: editing.featured,
        website_url: editing.website_url ?? '',
        repository_url: editing.repository_url ?? '',
        icon_url: editing.icon_url ?? '',
        oauth_issuer_url: editing.oauth_issuer_url ?? '',
        oauth_authorization_url: editing.oauth_authorization_url ?? '',
        oauth_token_url: editing.oauth_token_url ?? '',
        oauth_revocation_url: editing.oauth_revocation_url ?? '',
        oauth_default_scopes_csv: (editing.oauth_default_scopes ?? []).join(', '),
        enabled: editing.enabled,
      };
    } else {
      form = {
        name: '',
        display_title: '',
        description: '',
        category: '',
        upstream_url: '',
        transport: 'streamable_http',
        auth_mode: 'no_auth',
        featured: false,
        website_url: '',
        repository_url: '',
        icon_url: '',
        oauth_issuer_url: '',
        oauth_authorization_url: '',
        oauth_token_url: '',
        oauth_revocation_url: '',
        oauth_default_scopes_csv: '',
        enabled: true,
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

  function scopesFromCsv(): string[] {
    return form.oauth_default_scopes_csv
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
  }

  async function save() {
    formError = '';
    if (form.name.trim() === '') {
      formError = 'Name is required.';
      return;
    }
    if (!/^https?:\/\//.test(form.upstream_url.trim())) {
      formError = 'Endpoint URL must start with http:// or https://.';
      return;
    }
    const shared = {
      name: form.name.trim(),
      upstream_url: form.upstream_url.trim(),
      transport: form.transport,
      auth_mode: form.auth_mode,
      featured: form.featured,
      oauth_default_scopes: isOauth ? scopesFromCsv() : [],
    };
    if (editing) {
      // Edit sends optional text verbatim so clearing a field persists (empty →
      // NULL server-side). OAuth fields are sent only in OAuth mode; otherwise
      // omitted so switching modes doesn't silently wipe the stored config.
      const { error } = await adminApi.PATCH('/api/v1/admin/mcp/catalog/{id}', {
        params: { path: { id: editing.id } },
        body: {
          ...shared,
          display_title: form.display_title,
          description: form.description,
          category: form.category,
          website_url: form.website_url,
          repository_url: form.repository_url,
          icon_url: form.icon_url,
          oauth_issuer_url: isOauth ? form.oauth_issuer_url : undefined,
          oauth_authorization_url: isOauth ? form.oauth_authorization_url : undefined,
          oauth_token_url: isOauth ? form.oauth_token_url : undefined,
          oauth_revocation_url: isOauth ? form.oauth_revocation_url : undefined,
          enabled: form.enabled,
        },
      });
      if (error) { formError = extractError(error); return; }
    } else {
      const { error } = await adminApi.POST('/api/v1/admin/mcp/catalog', {
        body: {
          ...shared,
          display_title: form.display_title || undefined,
          description: form.description || undefined,
          category: form.category || undefined,
          website_url: form.website_url || undefined,
          repository_url: form.repository_url || undefined,
          icon_url: form.icon_url || undefined,
          oauth_issuer_url: isOauth ? form.oauth_issuer_url || undefined : undefined,
          oauth_authorization_url: isOauth ? form.oauth_authorization_url || undefined : undefined,
          oauth_token_url: isOauth ? form.oauth_token_url || undefined : undefined,
          oauth_revocation_url: isOauth ? form.oauth_revocation_url || undefined : undefined,
        },
      });
      if (error) { formError = extractError(error); return; }
    }
    dirty.markClean();
    onsaved();
  }
</script>

{#if open}
  <Modal
    {open}
    title={editing ? 'Edit catalog entry' : 'New catalog entry'}
    {onclose}
    onCloseRequest={dirty.confirmDiscard}
    maxWidth="max-w-2xl"
  >
    {#if formError}
      <div class="bg-(--error-bg) border border-(--error-border) text-(--error-text) p-2 rounded-sm mb-3 text-sm">{formError}</div>
    {/if}
    {#if editing?.is_builtin}
      <div class="bg-(--bg-primary) border border-(--border) text-(--text-secondary) p-2 rounded-sm mb-3 text-sm">
        Editing a built-in entry converts it to your own — it will no longer be overwritten when the
        catalog is updated, and it returns to the shipped version only if you reset the catalog.
      </div>
    {/if}
    <div class="space-y-3">
      <div class="grid grid-cols-2 gap-3">
        <label class="block">
          <span class="text-sm font-medium text-(--text-primary)">Name</span>
          <TextInput bind:value={form.name} placeholder="GitHub" />
        </label>
        <label class="block">
          <span class="text-sm font-medium text-(--text-primary)">Category</span>
          <TextInput bind:value={form.category} placeholder="Developer tools" />
        </label>
      </div>
      <label class="block">
        <span class="text-sm font-medium text-(--text-primary)">Display title <span class="text-xs text-(--text-secondary) font-normal">(optional)</span></span>
        <TextInput bind:value={form.display_title} />
      </label>
      <label class="block">
        <span class="text-sm font-medium text-(--text-primary)">Description</span>
        <TextArea bind:value={form.description} rows={2} />
      </label>
      <label class="block">
        <span class="text-sm font-medium text-(--text-primary)">Endpoint URL</span>
        <TextInput mono placeholder="https://example.com/mcp" bind:value={form.upstream_url} />
      </label>
      <div class="grid grid-cols-2 gap-3">
        <label class="block">
          <span class="text-sm font-medium text-(--text-primary)">Transport</span>
          <SelectInput bind:value={form.transport}>
            <option value="streamable_http">streamable_http</option>
            <option value="sse">sse</option>
          </SelectInput>
        </label>
        <label class="block">
          <span class="text-sm font-medium text-(--text-primary)">Authentication</span>
          <SelectInput bind:value={form.auth_mode}>
            <option value="no_auth">No auth</option>
            <option value="service_account">API key (service account)</option>
            <option value="per_user_oauth">Per-user OAuth</option>
            <option value="byot">Client token</option>
          </SelectInput>
        </label>
      </div>

      {#if isOauth}
        <div class="space-y-3 rounded-lg border border-(--border) p-3">
          <div class="text-xs uppercase tracking-wide text-(--text-secondary)">OAuth defaults</div>
          <label class="block">
            <span class="text-sm font-medium text-(--text-primary)">Issuer URL</span>
            <TextInput mono bind:value={form.oauth_issuer_url} placeholder="https://auth.example.com" />
          </label>
          <div class="grid grid-cols-2 gap-3">
            <label class="block">
              <span class="text-sm font-medium text-(--text-primary)">Authorization URL</span>
              <TextInput mono bind:value={form.oauth_authorization_url} />
            </label>
            <label class="block">
              <span class="text-sm font-medium text-(--text-primary)">Token URL</span>
              <TextInput mono bind:value={form.oauth_token_url} />
            </label>
          </div>
          <label class="block">
            <span class="text-sm font-medium text-(--text-primary)">Revocation URL <span class="text-xs text-(--text-secondary) font-normal">(optional)</span></span>
            <TextInput mono bind:value={form.oauth_revocation_url} />
          </label>
          <label class="block">
            <span class="text-sm font-medium text-(--text-primary)">Default scopes <span class="text-xs text-(--text-secondary) font-normal">(comma or space separated)</span></span>
            <TextInput bind:value={form.oauth_default_scopes_csv} placeholder="read, write" />
          </label>
        </div>
      {/if}

      <div class="grid grid-cols-2 gap-3">
        <label class="block">
          <span class="text-sm font-medium text-(--text-primary)">Website URL <span class="text-xs text-(--text-secondary) font-normal">(optional)</span></span>
          <TextInput mono bind:value={form.website_url} />
        </label>
        <label class="block">
          <span class="text-sm font-medium text-(--text-primary)">Repository URL <span class="text-xs text-(--text-secondary) font-normal">(optional)</span></span>
          <TextInput mono bind:value={form.repository_url} />
        </label>
      </div>
      <label class="block">
        <span class="text-sm font-medium text-(--text-primary)">Icon URL <span class="text-xs text-(--text-secondary) font-normal">(optional)</span></span>
        <TextInput mono bind:value={form.icon_url} />
      </label>

      <div class="flex items-center gap-4 pt-1">
        <label class="flex items-center gap-2 text-sm text-(--text-primary)">
          <input type="checkbox" bind:checked={form.featured} class="accent-(--accent)" />
          Featured
        </label>
        {#if editing}
          <label class="flex items-center gap-2 text-sm text-(--text-primary)">
            <input type="checkbox" bind:checked={form.enabled} class="accent-(--accent)" />
            Enabled
          </label>
        {/if}
      </div>
    </div>

    {#snippet footer()}
      <button
        type="button"
        class="rounded-lg border border-(--border) px-3 py-2 text-sm text-(--text-secondary) hover:bg-(--bg-primary)"
        onclick={onclose}
      >
        Cancel
      </button>
      <button
        type="button"
        class="rounded-lg bg-(--accent) px-3 py-2 text-sm font-medium text-(--accent-fg) hover:bg-(--accent-hover)"
        onclick={save}
      >
        {editing ? 'Save changes' : 'Create entry'}
      </button>
    {/snippet}
  </Modal>
{/if}
