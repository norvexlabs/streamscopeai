<script lang="ts">
  import FormModal from '#lib/components/forms/FormModal.svelte';
  import FormField from '#lib/components/forms/FormField.svelte';
  import TextInput from '#lib/components/forms/TextInput.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import NumberInput from '#lib/components/forms/NumberInput.svelte';
  import { adminApi } from '#lib/api-client.js';
  import { extractError } from '#lib/api-helpers.js';
  import { useDirtyForm } from '#lib/hooks.svelte.js';
  import type { components } from '#lib/generated/api-types.js';

  type FieldProfile = components['schemas']['FieldProfile'];
  type Normalizer = components['schemas']['Normalizer'];
  type ToolIdEntry = components['schemas']['ToolIdEntry'];
  type KnownServerToolType = components['schemas']['KnownServerToolType'];

  interface Props {
    open: boolean;
    initial: FieldProfile | null;
    onclose: () => void;
    onsaved: (profile: FieldProfile) => void;
  }

  let { open, initial, onclose, onsaved }: Props = $props();

  // ── Form state ───────────────────────────────────────────────────────
  let idField = $state('');
  let description = $state('');
  let source = $state('');
  let toolId = $state('');
  let toolPattern = $state('');
  let appFilter = $state('');
  let mcpServer = $state('');
  let serverType = $state('');
  let field = $state('');
  let wireField = $state('');
  let normalizer = $state<Normalizer>('raw');
  let priority = $state(100);

  let saving = $state(false);
  let error = $state<string | null>(null);
  let isEdit = $derived(!!initial?.id);
  let toolIds = $state<ToolIdEntry[]>([]);
  let knownServerTypes = $state<KnownServerToolType[]>([]);
  let scopeKind = $state<'generic' | 'app' | 'mcp' | 'server'>('generic');

  // Unsaved-changes guard: snapshot the form state once it's seeded from
  // `initial`, then derive `dirty` by comparing current field values to the
  // snapshot. Pair with FormModal (which wires the confirmDiscard hook to
  // Esc / backdrop / Cancel); `useDirtyForm` also catches sidebar navigation
  // away from the form. Snapshot is null while the modal is closed.
  const form = useDirtyForm();
  let snapshot = $state<string | null>(null);
  function fieldSignature() {
    return JSON.stringify([idField, description, source, toolId, toolPattern, appFilter, mcpServer, serverType, field, wireField, normalizer, priority, scopeKind]);
  }

  // Reset form whenever the modal is (re-)opened so create/edit toggles
  // start clean and previous-modal state doesn't bleed across opens.
  $effect(() => {
    if (!open) {
      snapshot = null;
      return;
    }
    error = null;
    idField = initial?.id ?? '';
    description = initial?.description ?? '';
    source = initial?.source ?? '';
    toolId = initial?.tool_id ?? '';
    toolPattern = initial?.tool_pattern ?? '';
    appFilter = initial?.app_filter ?? '';
    mcpServer = initial?.mcp_server ?? '';
    serverType = initial?.server_type ?? '';
    field = initial?.field ?? '';
    wireField = initial?.wire_field ?? '';
    normalizer = initial?.normalizer ?? 'raw';
    priority = initial?.priority ?? 100;
    // Precedence mirrors the Rust `ServerType > Mcp > App > Generic` resolution
    // (see `crates/streamscope-core/src/config/risk.rs::resolve_tool_id_for_definition`).
    if (initial?.server_type) scopeKind = 'server';
    else if (initial?.mcp_server) scopeKind = 'mcp';
    else if (initial?.app_filter) scopeKind = 'app';
    else scopeKind = 'generic';
    // Capture the baseline AFTER all writes settle so the comparison effect
    // doesn't see a transient mid-seed state as "dirty".
    queueMicrotask(() => {
      snapshot = fieldSignature();
      form.markClean();
    });
  });

  // Derive dirty by comparing current field values to the post-seed snapshot.
  $effect(() => {
    if (!open || snapshot === null) return;
    if (fieldSignature() !== snapshot) form.markDirty();
    else form.markClean();
  });

  // Load tool_id taxonomy + known server-type tags once when first opened.
  // Both lists ship from the Rust admin API so the UI doesn't drift when a
  // new variant lands in `crates/streamscope-core/src/config/risk.rs`.
  $effect(() => {
    if (!open) return;
    if (toolIds.length === 0) {
      void (async () => {
        const { data } = await adminApi.GET('/api/v1/admin/tool-ids');
        if (data?.tool_ids) toolIds = data.tool_ids;
      })();
    }
    if (knownServerTypes.length === 0) {
      void (async () => {
        const { data } = await adminApi.GET(
          '/api/v1/admin/tool-field-profiles/known-server-types',
        );
        if (data?.server_types) knownServerTypes = data.server_types;
      })();
    }
  });

  async function save() {
    if (!toolId.trim() || !toolPattern.trim() || !field.trim()) {
      error = 'tool_id, tool_pattern and field are required';
      return;
    }
    if (scopeKind === 'app' && !appFilter.trim()) {
      error = 'app_filter required when scope = app';
      return;
    }
    if (scopeKind === 'mcp' && !mcpServer.trim()) {
      error = 'mcp_server required when scope = mcp';
      return;
    }
    if (scopeKind === 'server' && !serverType.trim()) {
      error = 'server_type required when scope = server';
      return;
    }
    saving = true;
    error = null;
    try {
      const baseBody = {
        description: description || null,
        source: source || null,
        tool_id: toolId,
        tool_pattern: toolPattern,
        app_filter: scopeKind === 'app' ? appFilter : null,
        mcp_server: scopeKind === 'mcp' ? mcpServer : null,
        server_type: scopeKind === 'server' ? serverType : null,
        field,
        wire_field: wireField || null,
        normalizer,
        priority,
      };
      if (isEdit) {
        const { data, error: err } = await adminApi.PATCH('/api/v1/admin/tool-field-profiles/{id}', {
          params: { path: { id: initial!.id! } },
          body: baseBody,
        });
        if (err) {
          error = extractError(err, 'Save failed');
          return;
        }
        if (data) {
          form.markClean();
          onsaved(data);
          onclose();
        }
      } else {
        const { data, error: err } = await adminApi.POST('/api/v1/admin/tool-field-profiles', {
          body: {
            id: idField || undefined,
            ...baseBody,
            // POST omits null scope fields entirely (server treats absent as None).
            app_filter: scopeKind === 'app' ? appFilter : undefined,
            mcp_server: scopeKind === 'mcp' ? mcpServer : undefined,
            server_type: scopeKind === 'server' ? serverType : undefined,
            wire_field: wireField || undefined,
          },
        });
        if (err) {
          error = extractError(err, 'Create failed');
          return;
        }
        if (data) {
          form.markClean();
          onsaved(data);
          onclose();
        }
      }
    } finally {
      saving = false;
    }
  }
</script>

<FormModal
  {open}
  title={isEdit ? 'Edit field profile' : 'New field profile'}
  {form}
  {error}
  {saving}
  saveLabel={isEdit ? 'Save changes' : 'Create profile'}
  {onclose}
  onsave={save}
>
  <FormField label="Id" for="fp-id" help="[A-Za-z0-9._-], up to 96 chars. Cannot change after create.">
    <TextInput id="fp-id" bind:value={idField} disabled={isEdit}
      placeholder="auto-generated when blank (e.g. TFP-mytool-command)" />
  </FormField>

  <div class="grid grid-cols-2 gap-3">
    <FormField label="Tool id" for="fp-tool-id" help="Canonical concept (free-form). Pick from taxonomy or invent your own.">
      <TextInput id="fp-tool-id" list="fp-tool-id-list" bind:value={toolId} placeholder="e.g. shell_exec" mono />
      <datalist id="fp-tool-id-list">
        {#each toolIds as t (t.id)}
          <option value={t.id}>{t.description}</option>
        {/each}
      </datalist>
    </FormField>
    <FormField label="Tool pattern" for="fp-pattern" help="Pipe-separated globs over wire tool names.">
      <TextInput id="fp-pattern" bind:value={toolPattern} placeholder="e.g. Bash or run_*" mono />
    </FormField>
  </div>

  <FormField label="Scope">
    <div class="flex items-center gap-3 text-xs flex-wrap">
      <label><input type="radio" bind:group={scopeKind} value="generic" /> Generic</label>
      <label><input type="radio" bind:group={scopeKind} value="app" /> App-scoped</label>
      <label><input type="radio" bind:group={scopeKind} value="mcp" /> MCP server</label>
      <label><input type="radio" bind:group={scopeKind} value="server" /> Server-tool</label>
    </div>
    {#if scopeKind === 'app'}
      <div class="mt-2"><TextInput bind:value={appFilter} placeholder="e.g. cursor-* | opencode | claude*" mono /></div>
      <p class="text-[10px] text-(--text-secondary) mt-1">Pipe-separated glob over the request <code>app_id</code>.</p>
    {/if}
    {#if scopeKind === 'mcp'}
      <div class="mt-2"><TextInput bind:value={mcpServer} placeholder="e.g. filesystem | postgres | github" mono /></div>
      <p class="text-[10px] text-(--text-secondary) mt-1">Server identity from <code>mcp__&lt;server&gt;__&lt;tool&gt;</code> namespace.</p>
    {/if}
    {#if scopeKind === 'server'}
      <div class="mt-2"><TextInput list="fp-server-type-list" bind:value={serverType} placeholder="e.g. web_search_preview" mono /></div>
      <datalist id="fp-server-type-list">
        {#each knownServerTypes as kst (kst.server_type)}
          <option value={kst.server_type}>{kst.label}</option>
        {/each}
      </datalist>
      <p class="text-[10px] text-(--text-secondary) mt-1">
        Provider's wire tag for a native server-tool. Wins over MCP / App / Generic profiles for the same canonical <code>tool_id</code>.
        Pick a known tag or type your own for a new provider.
      </p>
    {/if}
  </FormField>

  <div class="grid grid-cols-2 gap-3">
    <FormField label="Canonical field" for="fp-field">
      <TextInput id="fp-field" bind:value={field} placeholder="e.g. path or command" mono />
      {#snippet help()}Used by rules: <code>arg.&lt;field&gt;</code>.{/snippet}
    </FormField>
    <FormField label="Wire field" for="fp-wire">
      {#snippet hint()}<span class="text-[10px] normal-case opacity-60">(optional)</span>{/snippet}
      <TextInput id="fp-wire" bind:value={wireField} placeholder="defaults to canonical" mono />
      {#snippet help()}Set when the wire arg name differs (e.g. <code>target_file</code>).{/snippet}
    </FormField>
  </div>

  <div class="grid grid-cols-2 gap-3">
    <FormField label="Normaliser" for="fp-norm">
      <SelectInput id="fp-norm" bind:value={normalizer}>
        <option value="shell">shell — argv tokenise + recursive bash -c unwrap</option>
        <option value="url">url — percent-decode, lowercase, IMDS host alias</option>
        <option value="sql">sql — lowercase, comment-strip, whitespace-collapse</option>
        <option value="path">path — lexical .. collapse, separator normalise</option>
        <option value="patch">patch — the files a patch adds, deletes, updates or moves to</option>
        <option value="raw">raw — identity (low-risk fields)</option>
      </SelectInput>
    </FormField>
    <FormField label="Priority" for="fp-prio" help="Lower wins on overlapping match. Default 100.">
      <NumberInput id="fp-prio" bind:value={priority} />
    </FormField>
  </div>

  <FormField label="Source" for="fp-src" help="Provenance tag. Display-only — the engine doesn't read it.">
    <TextInput id="fp-src" bind:value={source} placeholder="e.g. internal:my-mcp@1.0" />
  </FormField>

  <FormField label="Description" for="fp-desc">
    <TextInput id="fp-desc" bind:value={description} placeholder="Optional human-readable description" />
  </FormField>
</FormModal>
