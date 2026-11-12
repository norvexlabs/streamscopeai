<script lang="ts">
  /**
   * Catalog entry editor. An entry IS a `server.json` document (MCP Registry
   * schema): the form edits its common fields, the gateway's catalog facts
   * (`_meta."ai.streamscope/catalog"`) and its single remote; the
   * "server.json" view shows the whole document, where any field can be
   * edited or a document pasted in (the import — the gateway never fetches
   * one). Either view saves the same `server_json`.
   *
   * A document declares a remote, a package, or both. Its `packages` are
   * shown read-only and kept verbatim: they are written in the server.json
   * view. A document with packages may leave the endpoint empty, and is then
   * saved without `remotes`.
   */
  import { adminApi } from '#lib/api-client.js';
  import { extractError } from '#lib/api-helpers.js';
  import { useDirtyForm } from '#lib/hooks.svelte.js';
  import type { components } from '#lib/generated/api-types.js';
  import { untrack } from 'svelte';
  import Modal from '#lib/components/Modal.svelte';
  import TextInput from '#lib/components/forms/TextInput.svelte';
  import TextArea from '#lib/components/forms/TextArea.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import SegmentedControl from '#lib/components/forms/SegmentedControl.svelte';
  import RemoteHeadersEditor from '#lib/components/mcp/RemoteHeadersEditor.svelte';
  import { remoteFromRows, rowsFromRemote, type HeaderRow, type RemoteType } from '#lib/mcp/headerInputs.js';
  import {
    catalogMeta,
    emptyServerJson,
    parseServerJson,
    withCatalogMeta,
    type CatalogMeta,
    type OAuthHints,
    type ServerJson,
  } from '#lib/mcp/serverJson.js';

  type CatalogEntry = components['schemas']['McpCatalogEntry'];

  interface Props {
    open: boolean;
    /// `null` → create a new custom entry; a row → edit it (editing a built-in
    /// converts it to a user entry server-side so seed-sync stops overwriting it).
    editing: CatalogEntry | null;
    /// Open on the server.json view (the paste-import).
    startInJson?: boolean;
    onclose: () => void;
    onsaved: () => void;
  }

  let { open, editing, startInJson = false, onclose, onsaved }: Props = $props();

  type View = 'form' | 'json';

  type FormState = {
    name: string;
    title: string;
    description: string;
    version: string;
    website_url: string;
    icon_url: string;
    category: string;
    featured: boolean;
    remote_type: RemoteType;
    remote_url: string;
    oauth: boolean;
    oauth_issuer_url: string;
    oauth_authorization_url: string;
    oauth_token_url: string;
    oauth_revocation_url: string;
    oauth_default_scopes_csv: string;
    enabled: boolean;
  };

  /// The document as last loaded; the form writes its fields over it, so
  /// whatever the form does not show (packages, other `_meta` namespaces,
  /// extra remotes) is kept.
  let doc = $state<ServerJson>(emptyServerJson());
  let form = $state<FormState>(formFrom(emptyServerJson(), true));
  let rows = $state<HeaderRow[]>([]);
  let view = $state<View>('form');
  let jsonText = $state('');
  let formError = $state('');
  let refused = $state(0);

  const multiRemote = $derived((doc.remotes ?? []).length > 1);
  const packageCount = $derived((doc.packages ?? []).length);
  /// The saved entry's packages as the server read them — shown only while
  /// the document's `packages` are the saved ones; edited ones are read by
  /// the server at the next save.
  const savedPackages = $derived(
    editing !== null && JSON.stringify(doc.packages ?? []) === JSON.stringify(editing.server_json.packages ?? [])
      ? editing.packages
      : null,
  );
  /// The form's endpoint is left empty: no URL and no header row.
  const endpointEmpty = $derived(form.remote_url.trim() === '' && rows.length === 0);

  function formFrom(d: ServerJson, enabled: boolean): FormState {
    const meta = catalogMeta(d);
    const remote = d.remotes?.[0];
    return {
      name: d.name,
      title: d.title ?? '',
      description: d.description,
      version: d.version,
      website_url: d.websiteUrl ?? '',
      icon_url: d.icons?.[0]?.src ?? '',
      category: meta.category ?? '',
      featured: meta.featured === true,
      remote_type: remote?.type ?? 'streamable-http',
      remote_url: remote?.url ?? '',
      oauth: meta.oauth !== undefined && meta.oauth !== null,
      oauth_issuer_url: meta.oauth?.issuerUrl ?? '',
      oauth_authorization_url: meta.oauth?.authorizationUrl ?? '',
      oauth_token_url: meta.oauth?.tokenUrl ?? '',
      oauth_revocation_url: meta.oauth?.revocationUrl ?? '',
      oauth_default_scopes_csv: (meta.oauth?.defaultScopes ?? []).join(', '),
      enabled,
    };
  }

  function load(d: ServerJson) {
    doc = d;
    form = formFrom(d, form.enabled);
    rows = rowsFromRemote(d.remotes?.[0] ?? {});
  }

  /** The document the form describes. */
  function buildDoc(): ServerJson {
    const prevMeta = catalogMeta(doc);
    const meta: CatalogMeta = {
      ...prevMeta,
      category: form.category.trim() || undefined,
      featured: form.featured,
    };
    if (form.oauth) {
      const scopes = form.oauth_default_scopes_csv
        .split(/[\s,]+/)
        .map((s) => s.trim())
        .filter((s) => s.length > 0);
      const hints: OAuthHints = {};
      if (form.oauth_issuer_url.trim()) hints.issuerUrl = form.oauth_issuer_url.trim();
      if (form.oauth_authorization_url.trim()) hints.authorizationUrl = form.oauth_authorization_url.trim();
      if (form.oauth_token_url.trim()) hints.tokenUrl = form.oauth_token_url.trim();
      if (form.oauth_revocation_url.trim()) hints.revocationUrl = form.oauth_revocation_url.trim();
      if (scopes.length > 0) hints.defaultScopes = scopes;
      meta.oauth = hints;
    } else {
      delete meta.oauth;
    }
    const next: ServerJson = {
      ...doc,
      name: form.name.trim(),
      description: form.description.trim(),
      version: form.version.trim(),
    };
    if (form.title.trim()) next.title = form.title.trim();
    else delete next.title;
    if (form.website_url.trim()) next.websiteUrl = form.website_url.trim();
    else delete next.websiteUrl;
    const icons = [...(doc.icons ?? [])];
    if (form.icon_url.trim()) icons[0] = { ...(icons[0] ?? {}), src: form.icon_url.trim() };
    else icons.splice(0, 1);
    if (icons.length > 0) next.icons = icons;
    else delete next.icons;
    if (!multiRemote && endpointEmpty && packageCount > 0) {
      // A package-only document carries no `remotes`.
      delete next.remotes;
    } else if (!multiRemote) {
      const prev = doc.remotes?.[0];
      next.remotes = [
        remoteFromRows(
          { type: form.remote_type, url: form.remote_url, variables: prev?.variables },
          rows,
          false,
          prev,
        ),
      ];
    }
    return withCatalogMeta(next, meta);
  }

  function switchView(next: View) {
    formError = '';
    if (next === view) return;
    if (next === 'json') {
      jsonText = JSON.stringify(buildDoc(), null, 2);
      view = 'json';
      return;
    }
    const parsed = parseServerJson(jsonText);
    if ('error' in parsed) {
      formError = parsed.error;
      // Re-mount the view switch: it already shows the view it was clicked to.
      refused += 1;
      return;
    }
    load(parsed.doc);
    view = 'form';
  }

  const dirty = useDirtyForm();
  let snapshot = $state<string | null>(null);
  function fieldSignature() {
    return JSON.stringify([view, view === 'json' ? jsonText : [form, rows]]);
  }

  // Before the fields render: each binds to a key this sets.
  $effect.pre(() => {
    if (!open) {
      snapshot = null;
      return;
    }
    const entry = editing;
    const asJson = startInJson;
    untrack(() => {
      form = formFrom(emptyServerJson(), entry?.enabled ?? true);
      load(entry ? entry.server_json : emptyServerJson());
      view = asJson ? 'json' : 'form';
      jsonText = asJson ? '' : JSON.stringify(doc, null, 2);
      formError = '';
    });
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
    formError = '';
    let serverJson: ServerJson;
    if (view === 'json') {
      const parsed = parseServerJson(jsonText);
      if ('error' in parsed) {
        formError = parsed.error;
        return;
      }
      serverJson = parsed.doc;
    } else {
      if (form.name.trim() === '' || form.description.trim() === '') {
        formError = 'Name and description are required.';
        return;
      }
      if (!multiRemote && endpointEmpty && packageCount === 0) {
        formError =
          'Enter the endpoint URL of a remote server, or declare a package in the server.json view for a server that runs on the developer\'s machine.';
        return;
      }
      serverJson = buildDoc();
    }
    if (editing) {
      const { error } = await adminApi.PATCH('/api/v1/admin/mcp/catalog/{id}', {
        params: { path: { id: editing.id } },
        body: { server_json: serverJson, enabled: form.enabled },
      });
      if (error) { formError = extractError(error); return; }
    } else {
      const { error } = await adminApi.POST('/api/v1/admin/mcp/catalog', {
        body: { server_json: serverJson },
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
    maxWidth="max-w-3xl"
  >
    {#if formError}
      <div class="bg-(--error-bg) border border-(--error-border) text-(--error-text) p-2 rounded-sm mb-3 text-sm" data-testid="catalog-form-error">{formError}</div>
    {/if}
    {#if editing?.is_builtin}
      <div class="bg-(--bg-primary) border border-(--border) text-(--text-secondary) p-2 rounded-sm mb-3 text-sm">
        Editing a built-in entry converts it to your own — it will no longer be overwritten when the
        catalog is updated, and it returns to the shipped version only if you reset the catalog.
      </div>
    {/if}
    <div class="mb-3 flex items-center justify-between gap-2">
      {#key refused}
        <SegmentedControl
          label="Editor view"
          value={view}
          options={[
            { value: 'form', label: 'Form' },
            { value: 'json', label: 'server.json' },
          ]}
          onchange={(v: View) => switchView(v)} />
      {/key}
      {#if editing}
        <label class="flex items-center gap-2 text-sm text-(--text-primary)">
          <input type="checkbox" bind:checked={form.enabled} class="accent-(--accent)" />
          Enabled
        </label>
      {/if}
    </div>

    {#if view === 'json'}
      <div class="space-y-2">
        <p class="text-xs text-(--text-secondary)">
          A <code class="font-mono">server.json</code> document (MCP Registry schema 2025-12-11). Paste one to
          import it. The gateway's own facts live under <code class="font-mono">_meta."ai.streamscope/catalog"</code>.
        </p>
        <TextArea mono rows={22} bind:value={jsonText} spellcheck="false" placeholder={'{\n  "name": "io.example/server",\n  …\n}'} data-testid="server-json" />
      </div>
    {:else}
      <div class="space-y-3">
        <div class="grid grid-cols-2 gap-3">
          <label class="block">
            <span class="text-sm font-medium text-(--text-primary)">Name <span class="text-xs text-(--text-secondary) font-normal">(reverse-DNS, one /)</span></span>
            <TextInput mono bind:value={form.name} placeholder="io.github.example/weather" data-testid="catalog-name" />
          </label>
          <label class="block">
            <span class="text-sm font-medium text-(--text-primary)">Title <span class="text-xs text-(--text-secondary) font-normal">(optional)</span></span>
            <TextInput bind:value={form.title} placeholder="Weather" />
          </label>
        </div>
        <label class="block">
          <span class="text-sm font-medium text-(--text-primary)">Description <span class="text-xs text-(--text-secondary) font-normal">(up to 100 characters)</span></span>
          <TextArea bind:value={form.description} rows={2} maxlength={100} data-testid="catalog-description" />
        </label>
        <div class="grid grid-cols-3 gap-3">
          <label class="block">
            <span class="text-sm font-medium text-(--text-primary)">Version</span>
            <TextInput mono bind:value={form.version} />
          </label>
          <label class="block">
            <span class="text-sm font-medium text-(--text-primary)">Category</span>
            <TextInput bind:value={form.category} placeholder="Developer tools" />
          </label>
          <label class="flex items-center gap-2 text-sm text-(--text-primary) pt-6">
            <input type="checkbox" bind:checked={form.featured} class="accent-(--accent)" />
            Featured
          </label>
        </div>

        {#if multiRemote}
          <div class="rounded-lg border border-(--border) p-3 text-xs text-(--text-secondary)">
            This server declares {doc.remotes?.length} endpoints — edit them in the server.json view.
          </div>
        {:else}
          <div class="space-y-3 rounded-lg border border-(--border) p-3">
            <div class="text-xs uppercase tracking-wide text-(--text-secondary)">
              Endpoint{#if packageCount > 0} <span class="normal-case tracking-normal">(optional — this server declares a package)</span>{/if}
            </div>
            <div class="grid grid-cols-3 gap-3">
              <label class="col-span-2 block">
                <span class="text-sm font-medium text-(--text-primary)">URL</span>
                <TextInput mono placeholder="https://example.com/mcp" bind:value={form.remote_url} data-testid="catalog-remote-url" />
              </label>
              <label class="block">
                <span class="text-sm font-medium text-(--text-primary)">Transport</span>
                <SelectInput bind:value={form.remote_type}>
                  <option value="streamable-http">Streamable HTTP</option>
                  <option value="sse">HTTP+SSE</option>
                </SelectInput>
              </label>
            </div>
            {#if Object.keys(doc.remotes?.[0]?.variables ?? {}).length > 0}
              <p class="text-xs text-(--text-secondary)">
                URL variables: {Object.keys(doc.remotes?.[0]?.variables ?? {}).join(', ')} — declared in the server.json view, filled at adopt.
              </p>
            {/if}
            <RemoteHeadersEditor bind:rows withFillers={false} oauth={form.oauth} />
          </div>
        {/if}

        {#if packageCount > 0}
          <div class="space-y-2 rounded-lg border border-(--border) p-3" data-testid="catalog-packages">
            <div class="text-xs uppercase tracking-wide text-(--text-secondary)">Packages</div>
            {#if savedPackages}
              <ul class="space-y-1 text-xs">
                {#each savedPackages as pkg (pkg.index)}
                  <li class="flex flex-wrap items-center gap-2">
                    <code class="font-mono text-(--text-primary)">{pkg.identifier}{pkg.version ? `@${pkg.version}` : ''}</code>
                    <span class="text-(--text-secondary)">· {pkg.registry_type}</span>
                    <span class="text-(--text-secondary)">· {pkg.transport}</span>
                  </li>
                {/each}
              </ul>
            {:else}
              <p class="text-xs text-(--text-primary)">
                {packageCount} package{packageCount === 1 ? '' : 's'} declared — listed here once the entry is saved.
              </p>
            {/if}
            <p class="text-xs text-(--text-secondary)">
              A package runs on each developer's machine and can be added as a local server from the catalog.
              Packages are written in the server.json view and kept as they are.
            </p>
          </div>
        {/if}

        <div class="space-y-3 rounded-lg border border-(--border) p-3">
          <label class="flex items-center gap-2 text-sm text-(--text-primary)">
            <input type="checkbox" bind:checked={form.oauth} class="accent-(--accent)" data-testid="catalog-oauth" />
            Users sign in with OAuth
          </label>
          {#if form.oauth}
            <p class="text-xs text-(--text-secondary)">
              Endpoints for servers that publish no OAuth metadata. Leave them empty to discover them when
              the server is adopted.
            </p>
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
          {/if}
        </div>

        <div class="grid grid-cols-2 gap-3">
          <label class="block">
            <span class="text-sm font-medium text-(--text-primary)">Website URL <span class="text-xs text-(--text-secondary) font-normal">(optional)</span></span>
            <TextInput mono bind:value={form.website_url} />
          </label>
          <label class="block">
            <span class="text-sm font-medium text-(--text-primary)">Icon URL <span class="text-xs text-(--text-secondary) font-normal">(optional)</span></span>
            <TextInput mono bind:value={form.icon_url} />
          </label>
        </div>
      </div>
    {/if}

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
        data-testid="catalog-save"
        class="rounded-lg bg-(--accent) px-3 py-2 text-sm font-medium text-(--accent-fg) hover:bg-(--accent-hover)"
        onclick={save}
      >
        {editing ? 'Save changes' : 'Create entry'}
      </button>
    {/snippet}
  </Modal>
{/if}
