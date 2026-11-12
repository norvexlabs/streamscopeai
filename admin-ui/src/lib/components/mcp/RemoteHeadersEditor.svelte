<script lang="ts">
  /**
   * Editor for the headers a remote MCP server expects (`server.json`
   * `remotes[].headers`). Each row is a whole-header input, a fixed value, or a
   * `{var}` template whose variables are the inputs. With `withFillers`, each
   * row also says who fills its input(s): the administrator (once, here), each
   * user (in the portal), or the calling client (on every request).
   */
  import Icon from '#lib/components/Icon.svelte';
  import TextInput from '#lib/components/forms/TextInput.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import { FILLER_HELP, FILLER_NAME } from '#lib/mcp/fillers.js';
  import {
    bearerSharedRow,
    emptyHeaderRow,
    fillerAllowed,
    rowWarnings,
    type HeaderMode,
    type HeaderRow,
  } from '#lib/mcp/headerInputs.js';

  interface Props {
    rows: HeaderRow[];
    /** Show the filler of each row (an upstream); a catalog document has none. */
    withFillers: boolean;
    /** The upstream uses per-user OAuth: its token owns `Authorization`. */
    oauth?: boolean;
  }

  let { rows = $bindable(), withFillers, oauth = false }: Props = $props();


  function addRow() {
    rows.push(emptyHeaderRow());
  }

  function addBearerPreset() {
    const existing = rows.findIndex((r) => r.name.trim().toLowerCase() === 'authorization');
    if (existing >= 0) rows[existing] = bearerSharedRow();
    else rows.push(bearerSharedRow());
  }

  function removeRow(i: number) {
    rows.splice(i, 1);
  }

  function setMode(row: HeaderRow, mode: HeaderMode) {
    row.mode = mode;
    if (!fillerAllowed(mode, row.filler)) row.filler = 'admin';
    if (mode === 'template' && row.variables.length === 0) {
      row.variables.push({ name: '', description: '', isSecret: false, isRequired: false, placeholder: '', choices: '' });
    }
  }

  const authorizationDeclared = $derived(rows.some((r) => r.name.trim().toLowerCase() === 'authorization'));
  const clientHeaders = $derived(
    withFillers ? rows.filter((r) => r.mode === 'input' && r.filler === 'client' && r.name.trim() !== '') : [],
  );
  const clientAuthorization = $derived(clientHeaders.some((r) => r.name.trim().toLowerCase() === 'authorization'));
</script>

<div class="space-y-3" data-testid="headers-editor">
  <div class="flex items-center justify-between gap-2">
    <span class="text-sm font-medium text-(--text-primary)">Headers</span>
    <div class="flex items-center gap-2">
      <button
        type="button"
        data-testid="preset-bearer-shared"
        class="px-2.5 py-1 text-xs border border-(--border) rounded-lg text-(--text-secondary) hover:text-(--text-primary) hover:bg-(--bg-elevated) transition-colors disabled:opacity-50"
        disabled={oauth}
        title={oauth ? 'Authorization carries each user\'s OAuth token on this server' : 'Authorization: Bearer <token>, one token set by the administrator'}
        onclick={addBearerPreset}>Bearer token (shared)</button>
      <button
        type="button"
        data-testid="add-header"
        class="inline-flex items-center gap-1 px-2.5 py-1 text-xs border border-(--border) rounded-lg text-(--text-secondary) hover:text-(--text-primary) hover:bg-(--bg-elevated) transition-colors"
        onclick={addRow}><Icon name="plus" size="xs" tone="neutral" />Add header</button>
    </div>
  </div>

  {#if rows.length === 0}
    <p class="text-xs text-(--text-secondary)" data-testid="no-headers">
      No header declared — the server is called without credentials.
    </p>
  {/if}

  {#each rows as row, i (i)}
    {@const warnings = rowWarnings(row)}
    <div class="border border-(--border) rounded-lg p-3 space-y-2 bg-(--bg-primary)" data-testid="header-row" data-header-name={row.name}>
      <div class="grid grid-cols-12 gap-2 items-end">
        <label class="col-span-5 block">
          <span class="text-xs text-(--text-secondary)">Header name</span>
          <TextInput mono bind:value={row.name} placeholder="X-Api-Key" data-testid="header-name" />
        </label>
        <label class="col-span-6 block">
          <span class="text-xs text-(--text-secondary)">Value</span>
          <SelectInput
            value={row.mode}
            onchange={(e) => setMode(row, e.currentTarget.value === 'fixed' ? 'fixed' : e.currentTarget.value === 'template' ? 'template' : 'input')}
            data-testid="header-mode">
            <option value="input">An input (the whole value)</option>
            <option value="template">A template with {'{variables}'}</option>
            <option value="fixed">A fixed value</option>
          </SelectInput>
        </label>
        <div class="col-span-1 flex justify-end">
          <button
            type="button"
            data-testid="remove-header"
            aria-label="Remove header"
            title="Remove header"
            class="p-1.5 rounded-sm text-(--text-secondary) hover:text-(--error) hover:bg-(--error-bg) transition-colors"
            onclick={() => removeRow(i)}><Icon name="trash" size="sm" tone="neutral" /></button>
        </div>
      </div>

      {#if row.mode !== 'input'}
        <label class="block">
          <span class="text-xs text-(--text-secondary)">{row.mode === 'fixed' ? 'Fixed value' : 'Template'}</span>
          <TextInput
            mono
            bind:value={row.value}
            placeholder={row.mode === 'fixed' ? 'value sent as is' : 'Bearer {token}'}
            data-testid="header-value" />
        </label>
      {/if}

      {#if row.mode !== 'fixed'}
        <div class="grid grid-cols-2 gap-2">
          <label class="block">
            <span class="text-xs text-(--text-secondary)">Description</span>
            <TextInput bind:value={row.description} data-testid="header-description" />
          </label>
          {#if row.mode === 'input'}
            <label class="block">
              <span class="text-xs text-(--text-secondary)">Placeholder</span>
              <TextInput bind:value={row.placeholder} />
            </label>
          {/if}
        </div>
        <div class="flex flex-wrap items-center gap-4">
          <label class="flex items-center gap-1.5 text-xs text-(--text-primary)">
            <input type="checkbox" class="accent-(--accent)" bind:checked={row.isSecret} data-testid="header-secret" />
            Secret
          </label>
          <label class="flex items-center gap-1.5 text-xs text-(--text-primary)">
            <input type="checkbox" class="accent-(--accent)" bind:checked={row.isRequired} data-testid="header-required" />
            Required
          </label>
          {#if row.mode === 'input'}
            <label class="flex items-center gap-1.5 text-xs text-(--text-secondary) flex-1 min-w-48">
              Choices
              <TextInput bind:value={row.choices} placeholder="a, b, c (optional)" />
            </label>
          {/if}
        </div>
      {/if}

      {#if row.mode === 'template'}
        <div class="space-y-2 pl-3 border-l-2 border-(--border)">
          <span class="text-xs text-(--text-secondary)">Variables</span>
          {#each row.variables as v, vi (vi)}
            <div class="grid grid-cols-12 gap-2 items-center" data-testid="variable-row">
              <div class="col-span-3"><TextInput mono bind:value={v.name} placeholder="token" data-testid="variable-name" /></div>
              <div class="col-span-5"><TextInput bind:value={v.description} placeholder="description" /></div>
              <label class="col-span-2 flex items-center gap-1 text-xs text-(--text-primary)">
                <input type="checkbox" class="accent-(--accent)" bind:checked={v.isSecret} />Secret
              </label>
              <label class="col-span-1 flex items-center gap-1 text-xs text-(--text-primary)">
                <input type="checkbox" class="accent-(--accent)" bind:checked={v.isRequired} />Req.
              </label>
              <button
                type="button"
                aria-label="Remove variable"
                class="col-span-1 p-1 rounded-sm text-(--text-secondary) hover:text-(--error)"
                onclick={() => row.variables.splice(vi, 1)}><Icon name="close" size="xs" tone="neutral" /></button>
            </div>
          {/each}
          <button
            type="button"
            data-testid="add-variable"
            class="text-xs text-(--accent) hover:text-(--accent-hover)"
            onclick={() => row.variables.push({ name: '', description: '', isSecret: false, isRequired: false, placeholder: '', choices: '' })}>+ Variable</button>
        </div>
      {/if}

      {#if withFillers && row.mode !== 'fixed'}
        <label class="block">
          <span class="text-xs text-(--text-secondary)">Filled by</span>
          <SelectInput bind:value={row.filler} data-testid="header-filler">
            <option value="admin">{FILLER_NAME.admin}</option>
            <option value="user">{FILLER_NAME.user}</option>
            {#if row.mode === 'input'}
              <option value="client">{FILLER_NAME.client}</option>
            {/if}
          </SelectInput>
          <span class="block text-xs text-(--text-secondary) mt-1" data-testid="filler-help">{FILLER_HELP[row.filler]}</span>
        </label>
      {/if}

      {#each warnings as w}
        <p class="text-xs text-(--warning-text)">{w}</p>
      {/each}
    </div>
  {/each}

  {#if oauth && authorizationDeclared}
    <div data-testid="oauth-authorization-conflict" class="rounded-sm border border-(--warning-border) bg-(--warning-bg) p-2 text-xs text-(--warning-text)">
      Authorization carries each user's OAuth token on this server — remove the Authorization header.
    </div>
  {/if}

  {#if clientHeaders.length > 0}
    <div data-testid="client-header-note" class="rounded-sm border border-(--info-border) bg-(--info-bg) p-2 text-xs text-(--text-secondary) space-y-1">
      <p>
        The client sends
        {#each clientHeaders as r, ci}<code class="font-mono text-(--text-primary)">{r.name.trim()}</code>{ci < clientHeaders.length - 1 ? ', ' : ''}{/each}
        on every request; the gateway forwards it to this server only and never stores it.
      </p>
      {#if clientAuthorization}
        <p>
          Its own <code class="font-mono">Authorization</code> header goes to this server, so the client
          connects to <code class="font-mono">/fwd/&lt;gateway-key&gt;/mcp/&lt;slug&gt;</code>, with its
          gateway key in the path.
        </p>
      {:else}
        <p>The client connects to <code class="font-mono">/mcp/&lt;slug&gt;</code> with its gateway key as usual.</p>
      {/if}
    </div>
  {/if}
</div>
