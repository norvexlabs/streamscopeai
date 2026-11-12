<script lang="ts">
  /**
   * The local MCP server form: its slug, name and command line (command,
   * arguments, environment). Three uses, one form:
   * - `editing` null, no `adopt` → create a hand-typed server;
   * - `editing` a row → edit it;
   * - `adopt` → add a catalog entry's package as a local server, the command
   *   line prefilled from the package.
   * Creating and adopting also pick the workspaces to grant the server to.
   *
   * A pasted command line fills the command, argument and environment rows;
   * the rows stay what is saved.
   *
   * No secret is meant to be typed here: a variable that holds one is left
   * for each developer, who fills it in their own config. A variable loaded
   * as secret keeps the mark for as long as it exists on the server, so its
   * Secret box cannot be unticked.
   *
   * An edit sends only the fields that changed, and never the slug: it is
   * the server's key in every client config already written, so it is set
   * at creation and shown read-only afterwards.
   */
  import { adminApi } from '#lib/api-client.js';
  import { extractError, extractErrorCode } from '#lib/api-helpers.js';
  import { useDirtyForm } from '#lib/hooks.svelte.js';
  import { toast } from '#lib/toast.svelte.js';
  import type { components } from '#lib/generated/api-types.js';
  import { untrack } from 'svelte';
  import Modal from '#lib/components/Modal.svelte';
  import ConfirmDialog from '#lib/components/ConfirmDialog.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import TextInput from '#lib/components/forms/TextInput.svelte';
  import FormError from '#lib/components/forms/FormError.svelte';
  import WorkspaceGrantChecklist from '#lib/components/mcp/WorkspaceGrantChecklist.svelte';
  import { displayName } from '#lib/mcp/serverJson.js';
  import {
    MAX_ARGS,
    MAX_ENV,
    applyCommandLine,
    emptyLaunchForm,
    formFromLaunch,
    launchFromForm,
    launchProblem,
    sameLaunch,
    slugProblem,
    type LaunchForm,
  } from '#lib/mcp/localServer.js';
  import { parseCommandLine } from '#lib/mcp/parseCommandLine.js';

  type LocalServer = components['schemas']['McpLocalServer'];
  type LocalServerPatch = components['schemas']['UpdateMcpLocalServer'];
  type CatalogEntry = components['schemas']['McpCatalogEntry'];
  type CatalogPackage = components['schemas']['McpCatalogPackage'];

  interface Props {
    open: boolean;
    editing: LocalServer | null;
    /** The catalog package to add as a local server; wins over `editing`. */
    adopt?: { entry: CatalogEntry; pkg: CatalogPackage } | null;
    onclose: () => void;
    onsaved: () => void;
  }

  let { open, editing, adopt = null, onclose, onsaved }: Props = $props();

  let slug = $state('');
  let name = $state('');
  let description = $state('');
  let enabled = $state(true);
  let launch = $state<LaunchForm>(emptyLaunchForm());
  let selectedWorkspaces = $state<Set<string>>(new Set());
  let formError = $state('');
  let slugTaken = $state(false);
  /** Set by a save attempt: a variable row without a name then says so. */
  let namelessShown = $state(false);
  let saving = $state(false);

  /** The pasted command line, and what applying it last said. */
  let pasted = $state('');
  let pasteError = $state('');
  let pasteNote = $state('');

  const built = $derived(launchFromForm(launch));
  /** The row being edited; null while creating or adopting, where the slug is typed. */
  const edited = $derived(adopt ? null : editing);
  const title = $derived(
    adopt
      ? `Add ${displayName(adopt.entry.server_json)} as a local server`
      : editing
        ? 'Edit local server'
        : 'New local server',
  );

  const dirty = useDirtyForm();
  let snapshot = $state<string | null>(null);
  function fieldSignature() {
    return JSON.stringify([slug, name, description, enabled, launch, [...selectedWorkspaces].sort()]);
  }

  // Before the fields render: each binds to a key this sets.
  $effect.pre(() => {
    if (!open) {
      snapshot = null;
      return;
    }
    const row = editing;
    const from = adopt;
    untrack(() => {
      if (from) {
        // An empty slug is derived by the server from the document.
        slug = '';
        name = displayName(from.entry.server_json);
        description = '';
        enabled = true;
        launch = formFromLaunch(from.pkg.launch);
      } else if (row) {
        slug = row.slug;
        name = row.name;
        description = row.description ?? '';
        enabled = row.enabled;
        launch = formFromLaunch(row.launch);
      } else {
        slug = '';
        name = '';
        description = '';
        enabled = true;
        launch = emptyLaunchForm();
      }
      selectedWorkspaces = new Set();
      pasted = '';
      pasteError = '';
      pasteNote = '';
      formError = '';
      slugTaken = false;
      namelessShown = false;
      saving = false;
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

  function addArg() {
    launch.args = [...launch.args, ''];
  }
  function removeArg(i: number) {
    launch.args = launch.args.filter((_, j) => j !== i);
  }
  function addEnv() {
    launch.env = [...launch.env, { name: '', value: '', developerFilled: false, secret: false, locked: false }];
  }
  function removeEnv(i: number) {
    launch.env = launch.env.filter((_, j) => j !== i);
  }
  /** Leaving a variable to each developer clears the value typed for it. */
  function setDeveloperFilled(i: number, on: boolean) {
    launch.env[i].developerFilled = on;
    if (on) launch.env[i].value = '';
  }
  /** A secret is always left to each developer, and holds no value. */
  function setSecret(i: number, on: boolean) {
    launch.env[i].secret = on;
    if (on) {
      launch.env[i].developerFilled = true;
      launch.env[i].value = '';
    }
  }

  /** Fills the rows from the pasted line: its command and arguments replace
   *  the form's, its variables are merged in by name. Nothing changes on an
   *  empty line or one that does not parse. */
  function applyPasted() {
    pasteError = '';
    pasteNote = '';
    if (pasted.trim() === '') return;
    const parsed = parseCommandLine(pasted);
    if (!parsed.ok) {
      pasteError = parsed.error;
      return;
    }
    const applied = applyCommandLine(launch, parsed);
    launch = applied.form;
    const kept = applied.keptSecrets;
    if (kept.length === 0) pasteNote = 'Applied to the rows below.';
    else if (kept.length === 1) {
      pasteNote = `Applied to the rows below. ${kept[0]} is a secret variable and was left as it is.`;
    } else {
      pasteNote = `Applied to the rows below. ${kept.join(', ')} are secret variables and were left as they are.`;
    }
  }

  /** The server's refusal, with the slug field marked when the slug is taken. */
  function refused(error: unknown) {
    slugTaken = extractErrorCode(error) === 'mcp_local_server_slug_taken';
    formError = extractError(error);
  }

  async function save() {
    formError = '';
    slugTaken = false;
    namelessShown = true;
    const typedSlug = slug.trim();
    const typedName = name.trim();
    // An edit sends no slug. Adopting may leave it empty: the server derives it.
    if (!edited && (typedSlug !== '' || !adopt)) {
      const problem = slugProblem(typedSlug);
      if (problem) {
        formError = problem;
        return;
      }
    }
    // Adopting may leave the name empty: the server names it after the entry.
    if (!adopt && typedName === '') {
      formError = 'Name is required.';
      return;
    }
    const problem = launchProblem(built);
    if (problem) {
      formError = problem;
      return;
    }
    saving = true;
    if (adopt) {
      const { data, error } = await adminApi.POST('/api/v1/admin/mcp/catalog/{id}/actions/adopt', {
        params: { path: { id: adopt.entry.id } },
        body: {
          package_index: adopt.pkg.index,
          slug: typedSlug || undefined,
          name: typedName || undefined,
          launch: built,
          workspace_ids: [...selectedWorkspaces],
        },
      });
      saving = false;
      if (error) {
        refused(error);
        return;
      }
      toast.success('Local server added', data?.slug ? `${data.slug} is in the Local servers tab` : undefined);
    } else if (editing) {
      // Only what changed is sent: an untouched command line is not re-validated
      // against rules its stored form predates, and a concurrent edit to
      // another field is not overwritten.
      const body: LocalServerPatch = {};
      const typedDescription = description.trim();
      if (typedName !== editing.name) body.name = typedName;
      if (typedDescription !== (editing.description ?? '')) body.description = typedDescription || null;
      if (!sameLaunch(built, editing.launch)) body.launch = built;
      if (enabled !== editing.enabled) body.enabled = enabled;
      if (Object.keys(body).length === 0) {
        saving = false;
        dirty.markClean();
        onclose();
        return;
      }
      const { error } = await adminApi.PATCH('/api/v1/admin/mcp/local-servers/{id}', {
        params: { path: { id: editing.id } },
        body,
      });
      saving = false;
      if (error) {
        formError = extractError(error);
        return;
      }
    } else {
      const { error } = await adminApi.POST('/api/v1/admin/mcp/local-servers', {
        body: {
          slug: typedSlug,
          name: typedName,
          description: description.trim() || undefined,
          launch: built,
          enabled,
          workspace_ids: [...selectedWorkspaces],
        },
      });
      saving = false;
      if (error) {
        refused(error);
        return;
      }
    }
    dirty.markClean();
    onsaved();
  }
</script>

{#if open}
  <Modal {open} {title} {onclose} onCloseRequest={dirty.confirmDiscard} maxWidth="max-w-2xl">
    <div class="space-y-3 text-sm" data-testid="local-server-form">
      <p class="text-xs text-(--text-secondary)">
        This server runs on each developer's own machine: client provisioning writes the command line below
        into the client configs of the workspaces it is granted to. The gateway never connects to it.
      </p>

      {#if adopt}
        <p class="text-xs text-(--text-secondary)" data-testid="local-server-package">
          Package
          <code class="font-mono text-(--text-primary)">{adopt.pkg.identifier}{adopt.pkg.version ? `@${adopt.pkg.version}` : ''}</code>
          ({adopt.pkg.registry_type}, {adopt.pkg.transport}).
        </p>
        {#if adopt.pkg.underived_message}
          <div
            class="rounded-lg border border-(--info-border) bg-(--info-bg) px-3 py-2 text-xs text-(--info-text)"
            data-testid="local-server-underived"
          >
            {adopt.pkg.underived_message}
          </div>
        {/if}
      {/if}

      <div class="grid grid-cols-2 gap-3">
        <label class="block">
          <span class="text-sm font-medium text-(--text-primary)">
            Slug
            {#if adopt}<span class="text-xs text-(--text-secondary) font-normal">(optional)</span>{/if}
          </span>
          {#if edited}
            <!-- Raw input, not <TextInput>: a muted, read-only mirror of the
                 slug — TextInput hardcodes the primary text color. -->
            <input
              data-testid="local-server-slug"
              readonly
              value={edited.slug}
              class="w-full px-2.5 py-1.5 bg-(--bg-primary) border border-(--border) rounded-lg text-sm font-mono text-(--text-secondary) cursor-not-allowed"
            />
          {:else}
            <TextInput
              mono
              bind:value={slug}
              spellcheck="false"
              maxlength={31}
              placeholder={adopt ? 'Derived from the entry when empty' : 'github'}
              aria-invalid={slugTaken}
              data-testid="local-server-slug" />
          {/if}
          {#if slugTaken}
            <span class="mt-1 block text-xs text-(--error-text)" data-testid="local-server-slug-taken">
              An MCP endpoint or another local server already uses this slug.
            </span>
          {/if}
        </label>
        <label class="block">
          <span class="text-sm font-medium text-(--text-primary)">
            Name
            {#if adopt}<span class="text-xs text-(--text-secondary) font-normal">(optional)</span>{/if}
          </span>
          <TextInput
            bind:value={name}
            maxlength={100}
            placeholder={adopt ? 'Named after the entry when empty' : ''}
            data-testid="local-server-name" />
        </label>
      </div>
      <p class="text-xs text-(--text-secondary)">
        The slug is the server's key in a client's config and the prefix of its tool names
        (<code class="font-mono">mcp__{slug.trim() || 'slug'}__…</code>).
        {#if edited}
          <span data-testid="local-server-slug-locked">
            It is the server's key in every client config already written, so it cannot be changed: delete the
            server and add it again under another slug.
          </span>
        {:else}
          It starts with a letter and holds up to 31 of a–z, 0–9 and "-"; no MCP endpoint or other local server
          may already use it.
        {/if}
      </p>

      {#if !adopt}
        <label class="block">
          <span class="text-sm font-medium text-(--text-primary)">Description <span class="text-xs text-(--text-secondary) font-normal">(optional)</span></span>
          <TextInput bind:value={description} />
        </label>
      {/if}

      <div class="space-y-3 rounded-lg border border-(--border) p-3">
        <div class="text-xs uppercase tracking-wide text-(--text-secondary)">Command line</div>
        <div class="space-y-1">
          <label class="block">
            <span class="text-sm font-medium text-(--text-primary)">
              Paste a command line <span class="text-xs text-(--text-secondary) font-normal">(optional)</span>
            </span>
            <span class="mt-1 flex items-center gap-2">
              <TextInput
                mono
                bind:value={pasted}
                spellcheck="false"
                placeholder="REGION=eu npx -y @example/server --root '/my files'"
                aria-invalid={pasteError !== ''}
                data-testid="local-server-paste" />
              <button
                type="button"
                class="shrink-0 rounded-lg border border-(--border) px-3 py-1.5 text-xs font-medium text-(--accent) hover:bg-(--bg-primary)"
                onclick={applyPasted}
                data-testid="local-server-paste-apply">Apply</button>
            </span>
          </label>
          {#if pasteError}
            <p class="text-xs text-(--error-text)" data-testid="local-server-paste-error">{pasteError}</p>
          {:else if pasteNote}
            <p class="text-xs text-(--text-secondary)" data-testid="local-server-paste-note">{pasteNote}</p>
          {/if}
          <p class="text-xs text-(--text-secondary)">
            Apply splits the line as a shell would — quotes and backslashes group words, leading
            <code class="font-mono">NAME=value</code> words become variables — and fills the rows below: the
            command and arguments are replaced, variables are added or updated by name. The rows are what is saved.
          </p>
        </div>
        <label class="block">
          <span class="text-sm font-medium text-(--text-primary)">Command</span>
          <TextInput mono bind:value={launch.command} spellcheck="false" placeholder="npx" data-testid="local-server-command" />
          <span class="mt-1 block text-xs text-(--text-secondary)">
            The command must be installed on each developer's machine (<code class="font-mono">npx</code> needs
            Node.js, <code class="font-mono">uvx</code> needs uv).
          </span>
        </label>

        <div class="space-y-1.5">
          <div class="flex items-center justify-between">
            <span class="text-sm font-medium text-(--text-primary)">
              Arguments <span class="text-xs text-(--text-secondary) font-normal">(one per row, up to {MAX_ARGS})</span>
            </span>
            <button
              type="button"
              class="text-xs font-medium text-(--accent) hover:text-(--accent-hover) disabled:opacity-50"
              disabled={launch.args.length >= MAX_ARGS}
              onclick={addArg}
              data-testid="local-server-add-arg">+ Add argument</button>
          </div>
          {#each launch.args as _, i (i)}
            <div class="flex items-center gap-2" data-testid="local-server-arg">
              <TextInput mono bind:value={launch.args[i]} spellcheck="false" aria-label={`Argument ${i + 1}`} />
              <button
                type="button"
                class="shrink-0 rounded-sm p-1 hover:bg-(--error-bg)"
                aria-label={`Remove argument ${i + 1}`}
                title="Remove argument"
                onclick={() => removeArg(i)}><Icon name="trash" size="sm" /></button>
            </div>
          {/each}
          <p class="text-xs text-(--text-secondary)">
            Each argument is one argument: nothing goes through a shell. Some clients expand variable-looking text
            in a value (<code class="font-mono">{'${VAR}'}</code>, <code class="font-mono">$VAR</code>,
            <code class="font-mono">{'{env:X}'}</code>), so what you type is not always what runs. An empty row is
            an empty argument: remove a row with its delete button.
          </p>
        </div>

        <div class="space-y-1.5">
          <div class="flex items-center justify-between">
            <span class="text-sm font-medium text-(--text-primary)">
              Environment <span class="text-xs text-(--text-secondary) font-normal">(up to {MAX_ENV})</span>
            </span>
            <button
              type="button"
              class="text-xs font-medium text-(--accent) hover:text-(--accent-hover) disabled:opacity-50"
              disabled={launch.env.length >= MAX_ENV}
              onclick={addEnv}
              data-testid="local-server-add-env">+ Add variable</button>
          </div>
          {#each launch.env as row, i (i)}
            {@const locked = row.locked}
            {@const secret = row.secret}
            {@const nameless = namelessShown && row.name.trim() === ''}
            <div class="space-y-1 rounded-lg border border-(--border) p-2" data-testid="local-server-env">
              <div class="flex items-center gap-2">
                <div class="w-2/5 shrink-0">
                  <TextInput
                    mono
                    bind:value={launch.env[i].name}
                    spellcheck="false"
                    placeholder="NAME"
                    disabled={locked}
                    aria-invalid={nameless}
                    aria-label={`Variable ${i + 1} name`} />
                </div>
                {#if secret}
                  <span class="flex min-w-0 flex-1 items-center gap-1.5 text-xs text-(--text-secondary)" data-testid="local-server-env-secret-note">
                    <Icon name="lock" size="xs" />
                    Secret — each developer fills it in their own config.
                  </span>
                {:else if row.developerFilled}
                  <span class="min-w-0 flex-1 text-xs text-(--text-secondary)">
                    Each developer fills it in their own config.
                  </span>
                {:else}
                  <TextInput
                    mono
                    bind:value={launch.env[i].value}
                    spellcheck="false"
                    placeholder="value"
                    aria-label={`Variable ${i + 1} value`} />
                {/if}
                <button
                  type="button"
                  class="shrink-0 rounded-sm p-1 hover:bg-(--error-bg)"
                  aria-label={`Remove variable ${i + 1}`}
                  title="Remove variable"
                  onclick={() => removeEnv(i)}><Icon name="trash" size="sm" /></button>
              </div>
              <div class="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-(--text-secondary)">
                <label class="flex items-center gap-2">
                  <input
                    type="checkbox"
                    class="accent-(--accent)"
                    checked={secret || row.developerFilled}
                    disabled={secret}
                    onchange={(e) => setDeveloperFilled(i, e.currentTarget.checked)}
                    data-testid="local-server-env-developer" />
                  Each developer fills this in
                </label>
                <label class="flex items-center gap-2">
                  <input
                    type="checkbox"
                    class="accent-(--accent)"
                    checked={secret}
                    disabled={locked}
                    onchange={(e) => setSecret(i, e.currentTarget.checked)}
                    data-testid="local-server-env-secret" />
                  Secret
                </label>
              </div>
              {#if locked}
                <p class="text-xs text-(--text-secondary)" data-testid="local-server-env-locked">
                  Marked secret on this server: it cannot be given a value here.
                </p>
              {/if}
              {#if nameless}
                <p class="text-xs text-(--error-text)" data-testid="local-server-env-nameless">
                  Name this variable, or remove its row.
                </p>
              {/if}
            </div>
          {/each}
          <p class="text-xs text-(--text-secondary)">
            No secret goes here: a token or password is left for each developer, who pastes it into their own
            config. A value typed here is written into every member's client config, where some clients expand
            variable-looking text.
          </p>
          <p class="text-xs text-(--text-secondary)" data-testid="local-server-secret-hint">
            A variable marked secret keeps the mark for as long as it exists on this server: it cannot be given a
            value here. The mark guards against a mistake — it does not stop an administrator from typing a secret
            into another field.
          </p>
        </div>
      </div>

      {#if adopt || !editing}
        <WorkspaceGrantChecklist
          developersOnly
          bind:selected={selectedWorkspaces}
          note="Members of a granted workspace get the server in their client config at their next provisioning. Skip to grant later." />
      {/if}
      {#if !adopt}
        <label class="flex items-center gap-2 text-sm text-(--text-primary)">
          <input type="checkbox" bind:checked={enabled} class="accent-(--accent)" data-testid="local-server-enabled" />
          Enabled
        </label>
      {/if}

      <FormError message={formError} />
    </div>

    {#snippet footer()}
      <button
        type="button"
        class="rounded-lg border border-(--border) px-3 py-2 text-sm text-(--text-secondary) hover:bg-(--bg-primary)"
        disabled={saving}
        onclick={async () => { if (await dirty.confirmDiscard()) onclose(); }}
      >
        Cancel
      </button>
      <button
        type="button"
        data-testid="local-server-save"
        class="rounded-lg bg-(--accent) px-3 py-2 text-sm font-medium text-(--accent-fg) hover:bg-(--accent-hover) disabled:opacity-50"
        disabled={saving}
        onclick={save}
      >
        {adopt ? (saving ? 'Adding…' : 'Add local server') : editing ? 'Save changes' : 'Create server'}
      </button>
    {/snippet}
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
