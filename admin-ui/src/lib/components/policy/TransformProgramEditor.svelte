<script lang="ts">
  import type { TransformProgram } from '#lib/api-types.js';
  import { adminApi } from '#lib/api-client.js';
  import { extractError } from '#lib/api-helpers.js';
  import { profileLists } from '#lib/scope.svelte.js';
  import Modal from '#lib/components/Modal.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';

  interface Props {
    open: boolean;
    /** Edit target; null/undefined = create a new program. */
    program?: TransformProgram | null;
    /** Scope a newly-created program (and lock it, with `lockProfile`) to this
     *  transform profile — `''` for the shared baseline. */
    profileId?: string;
    /** Phase for a newly-created program ('request' | 'response'). */
    defaultPhase?: string;
    /** Hide the profile-scope picker — the scope is fixed by the drill-down. */
    lockProfile?: boolean;
    onclose: () => void;
    /** Notified after a successful save (reload the caller's program list). */
    onsaved: () => void;
  }

  let { open, program = null, profileId = '', defaultPhase = 'request', lockProfile = false, onclose, onsaved }: Props = $props();

  let formName = $state('');
  let formDescription = $state('');
  let formSource = $state('fn transform(ctx) {\n    ctx\n}');
  let formPhase = $state('request');
  let formScope = $state('global');
  let formPriority = $state(100);
  let formEnabled = $state(false);
  let formModelFilter = $state('');
  let formAppFilter = $state('');
  let formTriggerRegex = $state('');
  let formMatchMode = $state<'full' | 'span'>('full');
  // Transform profile scope: `''` = shared (baseline); otherwise a profile id.
  let formProfileId = $state('');
  const formSpanNeedsTrigger = $derived(formMatchMode === 'span' && !formTriggerRegex.trim());
  let validationResult = $state<{ valid: boolean; error?: string } | null>(null);
  let validating = $state(false);
  let saving = $state(false);

  const editing = $derived(!!program);

  function seed() {
    validationResult = null;
    if (program) {
      formName = program.name;
      formDescription = program.description || '';
      formSource = program.source;
      formPhase = program.phase || 'request';
      formScope = program.scope || 'global';
      formPriority = program.priority ?? 100;
      formEnabled = program.enabled;
      formModelFilter = program.model_filter || '';
      formAppFilter = program.app_filter || '';
      formTriggerRegex = program.trigger_regex || '';
      formMatchMode = program.match_mode === 'span' ? 'span' : 'full';
      formProfileId = program.profile_id ?? '';
    } else {
      formName = '';
      formDescription = '';
      formSource = 'fn transform(ctx) {\n    ctx\n}';
      formPhase = defaultPhase;
      formScope = 'global';
      formPriority = 100;
      formEnabled = false;
      formModelFilter = '';
      formAppFilter = '';
      formTriggerRegex = '';
      formMatchMode = 'full';
      formProfileId = profileId;
    }
  }

  // Seed the form when the modal opens (not on every reactive tick while open).
  let wasOpen = $state(false);
  $effect(() => {
    if (open && !wasOpen) seed();
    wasOpen = open;
  });

  let validateTimer: ReturnType<typeof setTimeout> | null = null;
  function onSourceChange() {
    validationResult = null;
    clearTimeout(validateTimer ?? undefined);
    validateTimer = setTimeout(async () => {
      validating = true;
      const { data, error: err } = await adminApi.POST('/api/v1/admin/transforms/programs/actions/validate', {
        body: { source: formSource },
      });
      if (err) {
        validationResult = { valid: false, error: extractError(err, 'Validation request failed') };
      } else if (data) {
        validationResult = data as { valid: boolean; error?: string };
      }
      validating = false;
    }, 500);
  }

  let saveError = $state<string | null>(null);

  async function save() {
    saving = true;
    saveError = null;
    const body = {
      name: formName,
      // The form shows every field, so an emptied one means "none": `null` clears it.
      description: formDescription || null,
      source: formSource,
      phase: formPhase,
      scope: formScope,
      priority: formPriority,
      enabled: formEnabled,
      model_filter: formModelFilter || null,
      app_filter: formAppFilter || null,
      trigger_regex: formTriggerRegex || null,
      match_mode: formMatchMode,
      // Tri-state PATCH: an id sets the profile, null makes it shared.
      profile_id: formProfileId || null,
    };
    let err;
    if (program) {
      const res = await adminApi.PATCH('/api/v1/admin/transforms/programs/{id}', {
        params: { path: { id: program.id } },
        body,
      });
      err = res.error;
    } else {
      const res = await adminApi.POST('/api/v1/admin/transforms/programs', { body });
      err = res.error;
    }
    saving = false;
    if (err) {
      saveError = extractError(err, 'Failed to save program');
      return;
    }
    onsaved();
    onclose();
  }
</script>

<Modal {open} title="{editing ? 'Edit' : 'Create'} Transform Program" {onclose} maxWidth="max-w-3xl">
  <div class="space-y-4">
    {#if saveError}
      <div class="p-3 rounded-lg bg-(--error-bg) text-(--error) text-sm">{saveError}</div>
    {/if}
    <div>
      <label class="block text-sm text-(--text-secondary) mb-1">Name
        <input bind:value={formName} class="w-full px-3 py-2 rounded-lg bg-(--bg-primary) border border-(--border) text-(--text-primary) text-sm" placeholder="e.g. guardrail-injection" />
      </label>
    </div>

    <div>
      <label class="block text-sm text-(--text-secondary) mb-1">Description
        <textarea bind:value={formDescription} rows="3" class="w-full px-3 py-2 rounded-lg bg-(--bg-primary) border border-(--border) text-(--text-primary) text-sm resize-y" placeholder="Optional description"></textarea>
      </label>
    </div>

    <div class="flex gap-4">
      <div class="flex-1">
        <label class="block text-sm text-(--text-secondary) mb-1">Scope
          <SelectInput bind:value={formScope}>
            <option value="global">Global</option>
            {#if formPhase === 'response'}
              <option value="text">Text</option>
              <option value="tool">Tool</option>
              <option value="thinking">Thinking</option>
            {:else}
              <option value="system_prompt">System Prompt</option>
              <option value="messages">Messages</option>
              <option value="tools">Tools</option>
            {/if}
          </SelectInput>
        </label>
      </div>
      <div class="w-28">
        <label class="block text-sm text-(--text-secondary) mb-1">Priority
          <input type="number" bind:value={formPriority} class="w-full px-3 py-2 rounded-lg bg-(--bg-primary) border border-(--border) text-(--text-primary) text-sm" />
        </label>
      </div>
      <div class="flex items-end pb-1">
        <label class="flex items-center gap-2 text-sm text-(--text-secondary)">
          <input type="checkbox" bind:checked={formEnabled} class="rounded-sm" />
          Enabled
        </label>
      </div>
    </div>

    <div class="flex gap-4">
      <div class="flex-1">
        <label class="block text-sm text-(--text-secondary) mb-1">Model Filter
          <input bind:value={formModelFilter} class="w-full px-3 py-2 rounded-lg bg-(--bg-primary) border border-(--border) text-(--text-primary) text-sm" placeholder="e.g. gpt-4o, gpt-4o-mini (empty = all)" />
        </label>
      </div>
      <div class="flex-1">
        <label class="block text-sm text-(--text-secondary) mb-1">App Filter
          <input bind:value={formAppFilter} class="w-full px-3 py-2 rounded-lg bg-(--bg-primary) border border-(--border) text-(--text-primary) text-sm" placeholder="e.g. opencode, claude-code (empty = all)" />
        </label>
      </div>
    </div>

    {#if !lockProfile}
      <div>
        <label class="block text-sm text-(--text-secondary) mb-1">Profile scope
          <SelectInput bind:value={formProfileId}>
            <option value="">Shared — runs for every profile (baseline)</option>
            {#each profileLists.transform as p (p.id)}
              <option value={p.id}>{p.name}{p.is_default ? ' (default)' : ''}</option>
            {/each}
          </SelectInput>
        </label>
        <p class="mt-1 text-xs text-(--text-secondary)">
          Shared programs apply to every workspace's transform set. A profile-scoped program runs only
          for workspaces assigned that profile (in addition to the shared baseline).
        </p>
      </div>
    {/if}

    <div>
      <label class="block text-sm text-(--text-secondary) mb-1">Execution
        <SelectInput bind:value={formMatchMode}>
          <option value="full">Full context — script edits the whole scope</option>
          <option value="span">Per match (span) — script rewrites each match of the pattern</option>
        </SelectInput>
      </label>
      <p class="mt-1 text-xs text-(--text-secondary)">
        {#if formMatchMode === 'span'}
          Runs <code>fn transform(m)</code> once per match of the pattern below
          (<code>m.matched</code>, <code>m.groups</code>, <code>m.before</code>, <code>m.after</code> → replacement).
        {:else}
          Runs <code>fn transform(ctx)</code> once over the whole scope.
        {/if}
      </p>
    </div>

    <div>
      <label class="block text-sm text-(--text-secondary) mb-1">
        {formMatchMode === 'span' ? 'Match pattern' : 'Trigger Regex'}
        {#if formMatchMode === 'span'}<span class="text-(--error)">*</span>{/if}
        <input
          bind:value={formTriggerRegex}
          class="w-full px-3 py-2 rounded-lg bg-(--bg-primary) border border-(--border) text-(--text-primary) text-sm font-mono"
          placeholder={formMatchMode === 'span'
            ? 'Required — the script runs once per match of this pattern'
            : 'e.g. @ — fast-find; runs only when content matches (empty = always)'}
        />
      </label>
      {#if formSpanNeedsTrigger}
        <p class="mt-1 text-xs text-(--error)">Span mode requires a match pattern.</p>
      {/if}
    </div>

    <div>
      <div class="flex items-center justify-between mb-1">
        <label for="rhai-source" class="text-sm text-(--text-secondary)">Rhai Source</label>
        <div class="flex items-center gap-2">
          {#if validating}
            <span class="text-xs text-(--text-secondary)">Validating…</span>
          {:else if validationResult}
            {#if validationResult.valid}
              <span class="text-xs text-(--success)">Valid</span>
            {:else}
              <span class="text-xs text-(--error)">{validationResult.error}</span>
            {/if}
          {/if}
        </div>
      </div>
      <textarea
        id="rhai-source"
        bind:value={formSource}
        oninput={onSourceChange}
        class="w-full h-64 px-3 py-2 rounded-lg bg-(--bg-primary) border border-(--border) text-(--text-primary) text-sm font-mono resize-y"
        spellcheck="false"
      ></textarea>
    </div>

    <div class="flex justify-end gap-3">
      <button onclick={onclose} class="px-4 py-2 text-sm text-(--text-secondary) hover:text-(--text-primary)">Cancel</button>
      <button
        onclick={save}
        disabled={saving || !formName || !formSource || formSpanNeedsTrigger}
        class="px-4 py-2 text-sm bg-(--accent) text-(--accent-fg) rounded-lg hover:bg-(--accent-hover) disabled:opacity-50"
      >
        {saving ? 'Saving…' : (editing ? 'Update' : 'Create')}
      </button>
    </div>
  </div>
</Modal>
