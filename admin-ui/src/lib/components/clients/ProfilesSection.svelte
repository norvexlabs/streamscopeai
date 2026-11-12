<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import { extractError, extractErrorCode } from '#lib/api-helpers.js';
  import { toast } from '#lib/toast.svelte.js';
  import { useDirtyForm } from '#lib/hooks.svelte.js';
  import Skeleton from '#lib/components/Skeleton.svelte';
  import EmptyState from '#lib/components/EmptyState.svelte';
  import Copyable from '#lib/components/Copyable.svelte';
  import ConfirmDialog from '#lib/components/ConfirmDialog.svelte';
  import Modal from '#lib/components/Modal.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import { API_FORMATS } from '#lib/constants.js';
  import type { components } from '#lib/generated/api-types.js';

  type ClientProfile = components['schemas']['ClientProfile'];
  type ClientProfileTemplate = components['schemas']['ClientProfileTemplate'];
  type CompanionTemplate = components['schemas']['CompanionTemplate'];
  type TemplateFormat = components['schemas']['TemplateFormat'];
  type TemplateKind = components['schemas']['TemplateKind'];
  type McpAuthMode = components['schemas']['McpAuthMode'];
  type KeyDelivery = components['schemas']['KeyDelivery'];
  type LocalMcpForm = components['schemas']['LocalMcpForm'];
  type PlaceholderRef = components['schemas']['PlaceholderRef'];
  type ClientProfilePreview = components['schemas']['ClientProfilePreview'];

  interface Props { activate?: boolean; }
  let { activate = true }: Props = $props();

  const FORMATS: TemplateFormat[] = ['json', 'yaml', 'toml', 'shell', 'text'];
  const KINDS: TemplateKind[] = ['llm', 'mcp', 'combined', 'instructions'];
  const MCP_AUTH_MODES: McpAuthMode[] = ['static', 'spec_oauth'];
  const KEY_DELIVERY: KeyDelivery[] = ['config', 'environment'];
  const LOCAL_MCP: { value: LocalMcpForm; label: string }[] = [
    { value: 'none', label: 'Not written' },
    { value: 'config', label: 'Written by this template' },
    { value: 'project', label: "Written only in a project's own file" },
  ];

  /** Set a template's local-MCP form. "Not written" is the field's absence,
   *  so a template that never declared one is saved as it was loaded. */
  function setLocalMcp(t: ClientProfileTemplate, value: string) {
    const picked = LOCAL_MCP.find((o) => o.value === value)?.value ?? 'none';
    if (picked === 'none') delete t.local_mcp;
    else t.local_mcp = picked;
    form.markDirty();
  }

  const ID_PATTERN = /^[a-z0-9_-]+$/;

  let profiles = $state<ClientProfile[]>([]);
  let loading = $state(true);
  let loaded = $state(false);
  let filterSource = $state<'all' | 'builtin' | 'custom'>('all');

  const form = useDirtyForm();

  let showAdd = $state(false);
  let editingId = $state<string | null>(null);
  let saving = $state(false);

  let draft = $state<ClientProfile>(emptyDraft());
  let draftOriginalId = $state('');

  let confirmDelete = $state<{ open: boolean; profile: ClientProfile | null }>({ open: false, profile: null });
  let resetModalOpen = $state(false);
  let resetRunning = $state(false);

  let placeholders = $state<PlaceholderRef[]>([]);
  let showPlaceholders = $state(false);
  let preview = $state<ClientProfilePreview | null>(null);
  let previewing = $state(false);

  $effect(() => {
    if (activate && !loaded) void load();
  });

  async function load() {
    loading = true;
    const { data, error: err } = await adminApi.GET('/api/v1/admin/client-profiles', {
      params: { query: { limit: 100, offset: 0 } },
    });
    loading = false;
    loaded = true;
    if (err) {
      toast.error('Failed to load profiles', { body: extractError(err), code: extractErrorCode(err) ?? undefined });
      return;
    }
    profiles = data?.items ?? [];
  }

  /** The reference is served from the same dictionary save-time validation
   *  renders against, so it cannot drift from what the API will accept. */
  async function loadPlaceholders() {
    if (placeholders.length > 0) return;
    const { data, error: err } = await adminApi.GET('/api/v1/admin/client-profiles/placeholders', {});
    if (err) {
      toast.error('Failed to load placeholders', { body: extractError(err), code: extractErrorCode(err) ?? undefined });
      return;
    }
    placeholders = data?.placeholders ?? [];
  }

  function emptyDraft(): ClientProfile {
    return {
      id: '',
      label: '',
      homepage: '',
      builtin: false,
      supports_llm: false,
      supports_mcp: false,
      templates: [emptyTemplate()],
    };
  }

  function emptyTemplate(): ClientProfileTemplate {
    return { title: '', body: '', format: 'yaml', kind: 'llm', key_delivery: 'config', companions: [] };
  }

  function emptyCompanion(): CompanionTemplate {
    return { path: null, format: 'shell', title: '', instructions: '', body: '' };
  }

  async function openAdd() {
    // Await the discard confirmation before clobbering edit state — without
    // the await the unawaited Promise resolves later while the code below
    // unconditionally replaces draft / editingId, losing the user's edits.
    if (editingId) {
      if (!(await form.confirmDiscard())) return;
      editingId = null;
      form.markClean();
    }
    draft = emptyDraft();
    draftOriginalId = '';
    preview = null;
    showAdd = true;
    form.markClean();
    void loadPlaceholders();
  }

  async function openEdit(p: ClientProfile) {
    if (showAdd) {
      if (!(await form.confirmDiscard())) return;
      showAdd = false;
      form.markClean();
    }
    draft = JSON.parse(JSON.stringify(p)) as ClientProfile;
    // `companions` is omitted from the wire when empty, so normalise before
    // binding — the editor mutates the array in place.
    for (const t of draft.templates) t.companions ??= [];
    draftOriginalId = p.id;
    editingId = p.id;
    preview = null;
    form.markClean();
    void loadPlaceholders();
  }

  async function cancelAdd() {
    if (!(await form.confirmDiscard())) return;
    showAdd = false;
    form.markClean();
  }

  async function cancelEdit() {
    if (!(await form.confirmDiscard())) return;
    editingId = null;
    form.markClean();
  }

  function addTemplate() {
    draft.templates = [...draft.templates, emptyTemplate()];
    form.markDirty();
  }

  function removeTemplate(idx: number) {
    if (draft.templates.length <= 1) return;
    draft.templates = draft.templates.filter((_, i) => i !== idx);
    form.markDirty();
  }

  function addCompanion(idx: number) {
    const t = draft.templates[idx];
    t.companions = [...(t.companions ?? []), emptyCompanion()];
    draft.templates = [...draft.templates];
    form.markDirty();
  }

  function removeCompanion(idx: number, cIdx: number) {
    const t = draft.templates[idx];
    t.companions = (t.companions ?? []).filter((_, i) => i !== cIdx);
    draft.templates = [...draft.templates];
    form.markDirty();
  }

  function draftError(): string | null {
    if (!draft.label.trim()) return 'Label is required';
    if (!showAdd && !draftOriginalId) return 'Edit target missing';
    if (showAdd) {
      if (!draft.id.trim()) return 'Id is required';
      if (!ID_PATTERN.test(draft.id)) return 'Id must match ^[a-z0-9_-]+$';
    }
    if (draft.templates.length === 0) return 'At least one template is required';
    for (const [i, t] of draft.templates.entries()) {
      if (!t.title.trim()) return `Template ${i + 1}: title is required`;
      if (!t.body.trim()) return `Template ${i + 1}: body is required`;
      for (const [j, c] of (t.companions ?? []).entries()) {
        if (!c.title.trim()) return `Template ${i + 1} companion ${j + 1}: title is required`;
        if (!c.body.trim()) return `Template ${i + 1} companion ${j + 1}: body is required`;
      }
    }
    return null;
  }

  /** Renders the draft through the identical code path save-time validation
   *  uses, so a clean preview IS a save that will pass. */
  async function runPreview() {
    const err = draftError();
    if (err) {
      toast.error(err);
      return;
    }
    previewing = true;
    const { data, error: apiErr } = await adminApi.POST('/api/v1/admin/client-profiles/actions/preview', { body: draft });
    previewing = false;
    if (apiErr) {
      preview = null;
      toast.error('Preview failed', { body: extractError(apiErr), code: extractErrorCode(apiErr) ?? undefined });
      return;
    }
    preview = data ?? null;
  }

  async function save() {
    const err = draftError();
    if (err) {
      toast.error(err);
      return;
    }
    saving = true;
    if (showAdd) {
      const { data, error: err } = await adminApi.POST('/api/v1/admin/client-profiles', { body: draft });
      saving = false;
      if (err) {
        toast.error('Save failed', { body: extractError(err), code: extractErrorCode(err) ?? undefined });
        return;
      }
      if (data) {
        toast.success(`Created ${data.label}`);
        showAdd = false;
        form.markClean();
        await load();
      }
      return;
    }
    if (editingId) {
      const { data, error: err } = await adminApi.PUT('/api/v1/admin/client-profiles/{id}', {
        params: { path: { id: editingId } },
        body: draft,
      });
      saving = false;
      if (err) {
        toast.error('Save failed', { body: extractError(err), code: extractErrorCode(err) ?? undefined });
        return;
      }
      if (data) {
        toast.success(`Saved ${data.label}`);
        editingId = null;
        form.markClean();
        await load();
      }
    }
  }

  async function reset(p: ClientProfile) {
    const { data, error: err } = await adminApi.POST('/api/v1/admin/client-profiles/{id}/actions/reset', {
      params: { path: { id: p.id } },
    });
    if (err) {
      toast.error('Reset failed', { body: extractError(err), code: extractErrorCode(err) ?? undefined });
      return;
    }
    if (data) {
      toast.success(`Reset ${data.label} to builtin`);
      await load();
    }
  }

  /** The only way back to a builtin an operator deleted: a suppressed row is
   *  filtered out of every read, so it can no longer be addressed by id. */
  async function runReset() {
    resetRunning = true;
    const { data, error: err } = await adminApi.POST('/api/v1/admin/client-profiles/actions/reset', {});
    resetRunning = false;
    resetModalOpen = false;
    if (err) {
      toast.error('Reset failed', { body: extractError(err), code: extractErrorCode(err) ?? undefined });
      return;
    }
    toast.success(data?.message ?? 'Built-ins restored.');
    await load();
  }

  function askDelete(p: ClientProfile) {
    confirmDelete = { open: true, profile: p };
  }

  async function performDelete() {
    const p = confirmDelete.profile;
    confirmDelete = { open: false, profile: null };
    if (!p) return;
    const { error: err } = await adminApi.DELETE('/api/v1/admin/client-profiles/{id}', {
      params: { path: { id: p.id } },
    });
    if (err) {
      toast.error('Delete failed', { body: extractError(err), code: extractErrorCode(err) ?? undefined });
      return;
    }
    profiles = profiles.filter((q) => q.id !== p.id);
    toast.success(`Deleted ${p.label}`);
  }

  const builtinCount = $derived(profiles.filter((p) => p.builtin).length);
  const editedCount = $derived(profiles.filter((p) => !p.builtin).length);
  const visible = $derived(
    profiles.filter((p) =>
      filterSource === 'all' ? true : filterSource === 'builtin' ? p.builtin : !p.builtin,
    ),
  );
</script>

<div class="flex flex-wrap items-center gap-2 mb-4">
  <div class="text-xs text-(--text-secondary)">
    {#if !loading}
      {builtinCount} builtin · {editedCount} customised
    {/if}
  </div>
  <SelectInput bind:value={filterSource} fluid={false}>
    <option value="all">All sources</option>
    <option value="builtin">Built-in</option>
    <option value="custom">Customised</option>
  </SelectInput>
  <button
    onclick={() => (resetModalOpen = true)}
    class="ml-auto px-3 py-1.5 text-xs border border-(--border) text-(--text-secondary) hover:text-(--text-primary) hover:border-(--error)/40 rounded-lg transition-colors"
  >
    Reset built-ins…
  </button>
  <button
    onclick={() => (showAdd ? cancelAdd() : openAdd())}
    class="px-3 py-1.5 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-xs font-medium transition-colors"
  >
    {showAdd ? 'Cancel' : '+ Add Profile'}
  </button>
</div>

{#if showAdd}
  {@render draftForm(false)}
{/if}

<div class="rounded-lg border border-(--border) bg-(--bg-card) overflow-hidden">
  {#if loading}
    <div class="divide-y divide-(--border)">
      {#each Array(4) as _, i (i)}
        <div class="px-4 py-3"><Skeleton variant="row" /></div>
      {/each}
    </div>
  {:else if visible.length === 0 && !showAdd}
    <EmptyState
      title="No client profiles yet"
      body="Add your first profile so it appears in the portal quickstart picker."
    />
  {:else}
    <div class="divide-y divide-(--border)">
      {#each visible as p (p.id)}
        {#if editingId === p.id}
          {@render draftForm(true)}
        {:else}
          <div class="px-4 py-3 flex items-center justify-between gap-3">
            <div class="flex items-center gap-2 min-w-0">
              <span class="text-sm font-medium text-(--text-primary) truncate">{p.label}</span>
              <Copyable value={p.id} />
              {#if p.supports_llm}
                <span class="px-1.5 py-0.5 text-[10px] rounded-sm bg-(--bg-primary) text-(--text-secondary) border border-(--border)">LLM</span>
              {/if}
              {#if p.supports_mcp}
                <span class="px-1.5 py-0.5 text-[10px] rounded-sm bg-(--bg-primary) text-(--text-secondary) border border-(--border)">MCP</span>
              {/if}
              {#if p.builtin}
                <span class="px-1.5 py-0.5 text-[10px] rounded-sm bg-(--bg-primary) text-(--text-secondary) border border-(--border)">built-in</span>
              {:else}
                <span class="px-1.5 py-0.5 text-[10px] rounded-sm bg-(--info-bg) text-(--info-text) border border-(--info-border)">edited</span>
              {/if}
              <span class="text-xs text-(--text-tertiary)">{p.templates.length} template{p.templates.length === 1 ? '' : 's'}</span>
            </div>
            <div class="flex items-center gap-3 shrink-0">
              <button onclick={() => openEdit(p)} class="text-xs text-(--accent) hover:underline">Edit</button>
              {#if !p.builtin}
                <button onclick={() => reset(p)} class="text-xs text-(--text-secondary) hover:text-(--text-primary) hover:underline" title="Restore the builtin version from disk">Reset</button>
              {/if}
              <button onclick={() => askDelete(p)} class="text-xs text-(--error) hover:underline">Delete</button>
            </div>
          </div>
        {/if}
      {/each}
    </div>
  {/if}
</div>

{#snippet draftForm(isEdit: boolean)}
  <div class="px-4 py-4 bg-(--bg-primary)/30 {isEdit ? '' : 'border border-(--border) rounded-lg mb-4'}">
    <div class="grid grid-cols-1 md:grid-cols-2 gap-3 mb-4">
      <label class="block text-xs text-(--text-secondary)">Id {isEdit ? '(read-only)' : ''}
        <input
          bind:value={draft.id}
          oninput={form.markDirty}
          readonly={isEdit}
          placeholder="claude-code"
          class="w-full mt-1 px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm font-mono {isEdit ? 'opacity-60' : ''}"
        />
      </label>
      <label class="block text-xs text-(--text-secondary)">Label
        <input
          bind:value={draft.label}
          oninput={form.markDirty}
          placeholder="Claude Code"
          class="w-full mt-1 px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm"
        />
      </label>
      <label class="block text-xs text-(--text-secondary) md:col-span-2">Homepage
        <input
          bind:value={draft.homepage}
          oninput={form.markDirty}
          placeholder="https://docs.example.com/clients/foo"
          class="w-full mt-1 px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm"
        />
      </label>
      <label class="block text-xs text-(--text-secondary) md:col-span-2">Launch command (optional)
        <input
          bind:value={draft.launch_command}
          oninput={form.markDirty}
          placeholder="goose"
          class="w-full mt-1 px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm font-mono"
        />
        <span class="block mt-1 opacity-70">What the CLI tells the user to run once provisioned. Leave blank for a GUI client — they are told to restart it instead.</span>
      </label>
      <label class="inline-flex items-center gap-2 text-xs text-(--text-secondary)">
        <input type="checkbox" bind:checked={draft.supports_llm} onchange={form.markDirty} class="rounded-sm border-(--border) bg-(--bg-primary) text-(--accent) focus:ring-(--accent)" />
        Supports LLM
      </label>
      <label class="inline-flex items-center gap-2 text-xs text-(--text-secondary)">
        <input type="checkbox" bind:checked={draft.supports_mcp} onchange={form.markDirty} class="rounded-sm border-(--border) bg-(--bg-primary) text-(--accent) focus:ring-(--accent)" />
        Supports MCP
      </label>
    </div>

    <div class="flex items-center justify-between mb-2">
      <span class="text-xs font-semibold text-(--text-primary) uppercase tracking-wider">Templates ({draft.templates.length})</span>
      <button onclick={addTemplate} class="text-xs text-(--accent) hover:underline">+ Add template</button>
    </div>

    <div class="space-y-3">
      {#each draft.templates as t, i (i)}
        <div class="rounded-lg border border-(--border) bg-(--bg-secondary) p-3 space-y-2">
          <div class="flex items-center justify-between">
            <span class="text-xs text-(--text-tertiary)">Template {i + 1}</span>
            {#if draft.templates.length > 1}
              <button onclick={() => removeTemplate(i)} class="text-xs text-(--error) hover:underline">Remove</button>
            {/if}
          </div>
          <div class="grid grid-cols-1 md:grid-cols-2 gap-2">
            <label class="block text-xs text-(--text-secondary)">Title
              <input bind:value={t.title} oninput={form.markDirty} placeholder="Stable" class="w-full mt-1 px-3 py-1.5 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm" />
            </label>
            <label class="block text-xs text-(--text-secondary)">Kind
              <SelectInput bind:value={t.kind} onchange={form.markDirty} class="mt-1">
                {#each KINDS as k}
                  <option value={k}>{k}</option>
                {/each}
              </SelectInput>
            </label>
            <label class="block text-xs text-(--text-secondary)">Format
              <SelectInput bind:value={t.format} onchange={form.markDirty} class="mt-1">
                {#each FORMATS as f}
                  <option value={f}>{f}</option>
                {/each}
              </SelectInput>
            </label>
            <label class="block text-xs text-(--text-secondary)">Filename (optional)
              <input bind:value={t.filename} oninput={form.markDirty} placeholder=".opencode.json" class="w-full mt-1 px-3 py-1.5 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm font-mono" />
            </label>
            <label class="block text-xs text-(--text-secondary)">Protocol (optional)
              <SelectInput bind:value={t.protocol} onchange={form.markDirty} class="mt-1">
                <option value={null}>—</option>
                {#each API_FORMATS as p}
                  <option value={p.value}>{p.label}</option>
                {/each}
              </SelectInput>
            </label>
            <label class="block text-xs text-(--text-secondary)">Route tag (optional)
              <input bind:value={t.route_tag} oninput={form.markDirty} placeholder="claude-code" class="w-full mt-1 px-3 py-1.5 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm" />
            </label>
            <label class="block text-xs text-(--text-secondary)">Project-local filename (optional)
              <input bind:value={t.project_filename} oninput={form.markDirty} placeholder=".claude/settings.json" class="w-full mt-1 px-3 py-1.5 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm font-mono" />
            </label>
            {#if t.kind === 'mcp' || t.kind === 'combined'}
              <label class="block text-xs text-(--text-secondary)">MCP auth mode
                <SelectInput bind:value={t.mcp_auth_mode} onchange={form.markDirty} class="mt-1">
                  {#each MCP_AUTH_MODES as m}
                    <option value={m}>{m}</option>
                  {/each}
                </SelectInput>
              </label>
            {/if}
            {#if t.kind !== 'mcp'}
              <label class="block text-xs text-(--text-secondary)">Key delivery
                <SelectInput bind:value={t.key_delivery} onchange={form.markDirty} class="mt-1">
                  {#each KEY_DELIVERY as k}
                    <option value={k}>{k}</option>
                  {/each}
                </SelectInput>
                <span class="block mt-1 opacity-70">
                  <strong>config</strong> — the key must appear in this template or one of its companions (a template with no file name may instead rely on an LLM-bearing sibling).
                  <strong>environment</strong> — the tool reads it from a shell variable and loads no file we can write; the portal shows the key itself instead.
                </span>
              </label>
            {/if}
            {#if t.kind === 'mcp' || t.kind === 'combined'}
              <label class="block text-xs text-(--text-secondary)">Local MCP servers
                <SelectInput
                  value={t.local_mcp ?? 'none'}
                  onchange={(e) => setLocalMcp(t, e.currentTarget.value)}
                  class="mt-1"
                  data-testid="template-local-mcp">
                  {#each LOCAL_MCP as o}
                    <option value={o.value}>{o.label}</option>
                  {/each}
                </SelectInput>
                <span class="block mt-1 opacity-70">
                  A template that writes one branches on <code>{'{{#if local}}'}</code> inside
                  <code>{'{{#each mcp_servers}}'}</code>. Local items come after the gateway ones; each
                  carries <code>local</code> (true), <code>slug</code>, <code>name</code>,
                  <code>command</code>, <code>args</code> (each <code>{'{{value}}'}</code>) and
                  <code>env</code> (each <code>{'{{name}}'}</code> / <code>{'{{value}}'}</code>).
                  In a YAML template write the command, each argument and each value with
                  <code>{'{{quoted value}}'}</code>, so <code>8080</code> or <code>true</code> stays text.
                  {#if (t.local_mcp ?? 'none') === 'none'}
                    A template with "Not written" is rendered with no local item.
                  {/if}
                </span>
              </label>
            {/if}
          </div>
          <label class="block text-xs text-(--text-secondary)">Instructions (rendered above the snippet)
            <textarea bind:value={t.instructions} oninput={form.markDirty} rows="2" class="w-full mt-1 px-3 py-1.5 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm"></textarea>
          </label>
          <label class="block text-xs text-(--text-secondary)">Body
            <textarea bind:value={t.body} oninput={form.markDirty} rows="8" spellcheck="false" class="w-full mt-1 px-3 py-1.5 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm font-mono"></textarea>
          </label>

          <div class="flex items-center justify-between pt-1">
            <span class="text-xs text-(--text-secondary)">Companion files ({(t.companions ?? []).length})</span>
            <button onclick={() => addCompanion(i)} class="text-xs text-(--accent) hover:underline">+ Add companion</button>
          </div>
          <p class="text-[10px] text-(--text-tertiary)">
            Part of the config the template's own file cannot carry — a secrets file, an auto-loaded
            <code>.env</code>, the file a tool reads its MCP servers from — or, with no path at all, a step
            the user runs (a command adding the tool's MCP servers), shown and never written. It is part of
            the config, not an extra: without it the user gets a config with the key or the servers nowhere
            in it. In a project a file goes to its project path, relative to the project root, or else to its
            <code>~/</code> path under the project root; one with only a project path exists only in a
            project. A JSON, YAML or TOML file, or a step, that renders empty is left out.
          </p>
          {#each t.companions ?? [] as c, j (j)}
            <div class="rounded-lg border border-(--border) bg-(--bg-primary) p-3 space-y-2">
              <div class="flex items-center justify-between">
                <span class="text-xs text-(--text-tertiary)">Companion {j + 1}</span>
                <button onclick={() => removeCompanion(i, j)} class="text-xs text-(--error) hover:underline">Remove</button>
              </div>
              <div class="grid grid-cols-1 md:grid-cols-2 gap-2">
                <label class="block text-xs text-(--text-secondary)">Path (optional)
                  <input bind:value={() => c.path ?? '', (v) => (c.path = v || null)} oninput={form.markDirty} placeholder="~/.config/tool/secrets.yaml" class="w-full mt-1 px-3 py-1.5 bg-(--bg-secondary) border border-(--border) rounded-lg text-(--text-primary) text-sm font-mono" />
                </label>
                <label class="block text-xs text-(--text-secondary)">Project path (optional)
                  <input
                    bind:value={() => c.project_path ?? '', (v) => (c.project_path = v || null)}
                    oninput={form.markDirty}
                    placeholder=".mcp.json"
                    class="w-full mt-1 px-3 py-1.5 bg-(--bg-secondary) border border-(--border) rounded-lg text-(--text-primary) text-sm font-mono"
                  />
                </label>
                <label class="block text-xs text-(--text-secondary)">Format
                  <SelectInput bind:value={c.format} onchange={form.markDirty} class="mt-1">
                    {#each FORMATS as f}
                      <option value={f}>{f}</option>
                    {/each}
                  </SelectInput>
                </label>
                <label class="block text-xs text-(--text-secondary) md:col-span-2">Title
                  <input bind:value={c.title} oninput={form.markDirty} placeholder="Goose · secrets.yaml" class="w-full mt-1 px-3 py-1.5 bg-(--bg-secondary) border border-(--border) rounded-lg text-(--text-primary) text-sm" />
                </label>
              </div>
              <label class="block text-xs text-(--text-secondary)">Instructions
                <textarea bind:value={c.instructions} oninput={form.markDirty} rows="2" class="w-full mt-1 px-3 py-1.5 bg-(--bg-secondary) border border-(--border) rounded-lg text-(--text-primary) text-sm"></textarea>
              </label>
              <label class="block text-xs text-(--text-secondary)">Body
                <textarea bind:value={c.body} oninput={form.markDirty} rows="4" spellcheck="false" class="w-full mt-1 px-3 py-1.5 bg-(--bg-secondary) border border-(--border) rounded-lg text-(--text-primary) text-sm font-mono"></textarea>
                <span class="block mt-1 opacity-70">
                  Splice values into bare positions — <code>{'KEY: {{api_key}}'}</code> in YAML, not
                  <code>{'KEY: "{{api_key}}"'}</code>. The renderer quotes and escapes for the declared format.
                </span>
              </label>
            </div>
          {/each}
        </div>
      {/each}
    </div>

    <div class="mt-4 rounded-lg border border-(--border) bg-(--bg-secondary)">
      <button
        onclick={() => (showPlaceholders = !showPlaceholders)}
        class="w-full flex items-center justify-between px-3 py-2 text-xs text-(--text-secondary) hover:text-(--text-primary)"
      >
        <span>Available placeholders ({placeholders.length})</span>
        <span>{showPlaceholders ? '−' : '+'}</span>
      </button>
      {#if showPlaceholders}
        <div class="px-3 pb-3 grid grid-cols-1 md:grid-cols-2 gap-x-4 gap-y-1 max-h-64 overflow-y-auto">
          {#each placeholders as ph (ph.name)}
            <div class="text-[11px] flex items-baseline gap-2 min-w-0">
              <code class="text-(--accent) shrink-0">
                {ph.kind === 'list' ? `{{#each ${ph.name}}}` : `{{${ph.name}}}`}
              </code>
              <span class="text-(--text-tertiary) truncate">
                {ph.kind === 'list' ? (ph.item_keys ?? []).join(', ') : (ph.sample ?? '')}
              </span>
            </div>
          {/each}
        </div>
      {/if}
    </div>

    {#if preview}
      <div class="mt-4 space-y-3">
        <span class="block text-xs font-semibold text-(--text-primary) uppercase tracking-wider">Preview</span>
        {#each preview.templates as pt, pi (pi)}
          <div class="rounded-lg border border-(--border) bg-(--bg-secondary) p-3 space-y-2">
            <div class="text-xs text-(--text-secondary)">
              {pt.title}{#if pt.filename}<code class="ml-2 text-(--text-tertiary)">{pt.filename}</code>{/if}
            </div>
            <pre class="text-[11px] text-(--text-primary) font-mono overflow-x-auto whitespace-pre">{pt.body}</pre>
            {#each pt.companions as pc, ci (ci)}
              <div class="text-xs text-(--text-secondary) pt-2 border-t border-(--border)">
                {pc.title}{#if pc.filename}<code class="ml-2 text-(--text-tertiary)">{pc.filename}</code>{/if}
              </div>
              <pre class="text-[11px] text-(--text-primary) font-mono overflow-x-auto whitespace-pre">{pc.body}</pre>
            {/each}
          </div>
        {/each}
      </div>
    {/if}

    <div class="flex justify-end gap-2 mt-4">
      <button
        onclick={() => (isEdit ? cancelEdit() : cancelAdd())}
        class="px-4 py-1.5 bg-(--bg-secondary) border border-(--border) rounded-lg text-(--text-primary) text-xs font-medium"
      >Cancel</button>
      <button
        onclick={runPreview}
        disabled={previewing}
        class="px-4 py-1.5 bg-(--bg-secondary) border border-(--border) rounded-lg text-(--text-primary) text-xs font-medium disabled:opacity-50"
        title="Render the draft against the same placeholders save-time validation uses"
      >{previewing ? 'Rendering…' : 'Preview'}</button>
      <button
        onclick={save}
        disabled={saving}
        class="px-4 py-1.5 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-xs font-medium disabled:opacity-50"
      >{saving ? 'Saving…' : isEdit ? 'Save' : 'Create'}</button>
    </div>
  </div>
{/snippet}

<ConfirmDialog
  open={confirmDelete.open}
  title="Delete profile?"
  message={confirmDelete.profile
    ? confirmDelete.profile.builtin
      ? `Delete "${confirmDelete.profile.label}"? It is a built-in, so it is hidden rather than destroyed and startup sync will not bring it back. "Reset built-ins" restores it.`
      : `Delete "${confirmDelete.profile.label}"? This profile was created here, so it is removed permanently.`
    : ''}
  confirmLabel="Delete"
  destructive
  onconfirm={performDelete}
  oncancel={() => (confirmDelete = { open: false, profile: null })}
/>

<ConfirmDialog
  open={form.confirmOpen}
  title="Discard changes?"
  message="You have unsaved edits to this profile. Discard them?"
  confirmLabel="Discard"
  cancelLabel="Keep editing"
  destructive
  onconfirm={form.acceptDiscard}
  oncancel={form.rejectDiscard}
/>

<Modal open={resetModalOpen} title="Reset built-ins" onclose={() => (resetModalOpen = false)}>
  <div class="py-2 space-y-3 text-sm">
    <p>Restore every built-in client profile from the shipped seed.</p>
    <ul class="list-disc pl-5 text-(--text-secondary) space-y-1 text-xs">
      <li>Profiles you created here are preserved — unless one uses the same name as a built-in, which the shipped version replaces.</li>
      <li>Any edits you have made to a built-in profile will be overwritten with the shipped version.</li>
      <li>Any built-in profiles you previously deleted will reappear — this is the only way to bring one back.</li>
    </ul>
  </div>
  {#snippet footer()}
    <div class="flex items-center justify-end gap-2">
      <button type="button" onclick={() => (resetModalOpen = false)}
        class="px-4 py-2 text-sm border border-(--border) rounded-lg hover:bg-(--bg-elevated) transition-colors">Cancel</button>
      <button type="button" onclick={runReset} disabled={resetRunning}
        class="px-4 py-2 bg-(--error)/90 text-(--error-fg) text-sm rounded-lg hover:bg-(--error) disabled:opacity-50 transition-colors">
        {resetRunning ? 'Resetting…' : 'Reset built-ins'}
      </button>
    </div>
  {/snippet}
</Modal>
