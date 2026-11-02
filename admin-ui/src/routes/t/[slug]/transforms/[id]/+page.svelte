<script lang="ts">
  import { goto } from '$app/navigation';
  import { thref } from '#lib/tenant.js';
  import type { PageProps } from './$types';

  let { params }: PageProps = $props();

  let slug = $derived(params.slug);
  import type { TransformProgram } from '#lib/api-types.js';
  import { adminApi } from '#lib/api-client.js';
  import { extractError } from '#lib/api-helpers.js';
  import TagBadge from '#lib/components/TagBadge.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import { scopeColor, filterChipColor } from '#lib/colormaps/transforms.js';

  let program = $state<TransformProgram | null>(null);
  let loading = $state(true);
  let saving = $state(false);
  let error = $state('');
  let success = $state('');

  // Editor state
  let name = $state('');
  let description = $state('');
  let scope = $state('global');
  let priority = $state(100);
  let enabled = $state(false);
  let source = $state('');
  let modelFilter = $state('');
  let appFilter = $state('');
  let triggerRegex = $state('');
  let matchMode = $state<'full' | 'span'>('full');

  // Span mode uses trigger_regex as the per-match finder, so it is required.
  const spanNeedsTrigger = $derived(matchMode === 'span' && !triggerRegex.trim());

  // Validation
  let validationStatus = $state<'idle' | 'checking' | 'valid' | 'invalid'>('idle');
  let validationError = $state('');
  let validationTimer: ReturnType<typeof setTimeout> | null = null;

  // Test panel
  let showTestPanel = $state(false);
  let testContext = $state(`{
  "system_prompt": "You are a helpful assistant.",
  "messages": [
    {"role": "user", "content": "Hello, how are you?"},
    {"role": "assistant", "content": "I'm doing well, thanks!"},
    {"role": "user", "content": "What is 2+2?"}
  ],
  "tools": [],
  "model": "gpt-4o",
  "user_id": "test-user",
  "app_id": null,
  "api_version": "chat_completions",
  "metadata": {}
}`);
  let testResult = $state<unknown>(null);
  let testError = $state('');
  let testing = $state(false);

  const id = $derived(params.id);

  async function load() {
    loading = true;
    error = '';
    const { data: prog, error: err } = await adminApi.GET('/api/v1/admin/transforms/programs/{id}', {
      params: { path: { id } },
    });
    if (err) {
      error = extractError(err, 'Failed to load program');
    } else if (prog) {
      program = prog;
      name = prog.name;
      description = prog.description || '';
      scope = prog.scope || 'global';
      priority = prog.priority ?? 100;
      enabled = prog.enabled;
      source = prog.source;
      modelFilter = prog.model_filter || '';
      appFilter = prog.app_filter || '';
      triggerRegex = prog.trigger_regex || '';
      matchMode = prog.match_mode === 'span' ? 'span' : 'full';
    }
    loading = false;
  }

  $effect(() => {
    void id;
    load();
  });

  function onSourceChange() {
    validationStatus = 'checking';
    if (validationTimer) clearTimeout(validationTimer);
    validationTimer = setTimeout(async () => {
      const { data: res, error: err } = await adminApi.POST('/api/v1/admin/transforms/programs/actions/validate', {
        body: { source },
      });
      if (err) {
        validationStatus = 'idle';
      } else if (res?.valid) {
        validationStatus = 'valid';
        validationError = '';
      } else {
        validationStatus = 'invalid';
        validationError = res?.error || 'Unknown error';
      }
    }, 500);
  }

  async function save() {
    saving = true;
    error = '';
    success = '';
    const { error: err } = await adminApi.PATCH('/api/v1/admin/transforms/programs/{id}', {
      params: { path: { id } },
      body: { name, description, scope, priority, enabled, source, model_filter: modelFilter, app_filter: appFilter, trigger_regex: triggerRegex, match_mode: matchMode },
    });
    if (err) {
      error = extractError(err, 'Failed to save program');
    } else {
      success = 'Program saved successfully.';
      const { data: prog } = await adminApi.GET('/api/v1/admin/transforms/programs/{id}', {
        params: { path: { id } },
      });
      if (prog) program = prog;
      setTimeout(() => (success = ''), 3000);
    }
    saving = false;
  }

  async function handleDelete() {
    if (!confirm(`Delete program "${name}"?`)) return;
    const { error: err } = await adminApi.DELETE('/api/v1/admin/transforms/programs/{id}', {
      params: { path: { id } },
    });
    if (err) {
      error = extractError(err, 'Failed to delete program');
    } else {
      goto(thref(slug, '/transforms'));
    }
  }

  async function runTest() {
    testing = true;
    testResult = null;
    testError = '';
    try {
      const ctx = JSON.parse(testContext);
      const { data: res, error: err } = await adminApi.POST('/api/v1/admin/transforms/programs/actions/test', {
        body: { source, context: ctx, match_mode: matchMode, trigger_regex: triggerRegex },
      });
      if (err) {
        testError = extractError(err, 'Test failed');
      } else if (res?.success) {
        testResult = res.result;
      } else {
        testError = res?.error || 'Test failed';
      }
    } catch (e: unknown) {
      testError = e instanceof Error ? e.message : String(e);
    } finally {
      testing = false;
    }
  }
</script>

<svelte:head>
  <title>{name || 'Transform Program'} - Streamscope AI</title>
</svelte:head>

{#if loading}
  <div class="flex items-center justify-center py-20">
    <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-(--accent)"></div>
  </div>
{:else if error && !program}
  <div class="rounded-xl border border-(--error)/30 bg-(--error-bg) p-6 text-(--error)">
    {error}
  </div>
{:else if program}
  <div class="space-y-6 max-w-5xl">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div class="flex items-center gap-3">
        <a
          href={thref(slug, '/transforms')}
          aria-label="Back to transforms"
          class="p-2 rounded-lg text-(--text-secondary) hover:text-(--text-primary) hover:bg-(--bg-elevated) transition-colors"
        >
          <Icon name="chevronLeft" tone="neutral" />
        </a>
        <div>
          <h1 class="text-2xl font-bold text-(--text-primary)">{program.name}</h1>
          <p class="text-sm text-(--text-secondary) flex items-center gap-2 flex-wrap">
            Version {program.version} &middot;
            <TagBadge color={scopeColor(program.scope)} class="text-xs">{program.scope}</TagBadge>
            &middot; Priority {program.priority} &middot;
            {program.enabled ? 'Enabled' : 'Disabled'}
            {#if program.model_filter}
              &middot; <TagBadge color={filterChipColor.models}>models: {program.model_filter}</TagBadge>
            {/if}
            {#if program.app_filter}
              &middot; <TagBadge color={filterChipColor.apps}>apps: {program.app_filter}</TagBadge>
            {/if}
            {#if program.trigger_regex}
              &middot; <TagBadge color={filterChipColor.apps}>trigger: {program.trigger_regex}</TagBadge>
            {/if}
            {#if program.match_mode === 'span'}
              &middot; <TagBadge color={scopeColor(program.scope)}>per-match</TagBadge>
            {/if}
          </p>
        </div>
      </div>
      <div class="flex items-center gap-2">
        <button
          onclick={() => (showTestPanel = !showTestPanel)}
          class="px-4 py-2 rounded-lg border border-(--border) text-(--text-secondary) hover:text-(--text-primary) hover:bg-(--bg-elevated) transition-colors text-sm"
        >
          {showTestPanel ? 'Hide' : 'Show'} Test Panel
        </button>
        <button
          onclick={handleDelete}
          class="px-4 py-2 rounded-lg border border-(--error)/30 text-(--error) hover:bg-(--error-bg) transition-colors text-sm"
        >
          Delete
        </button>
      </div>
    </div>

    {#if error}
      <div class="rounded-lg border border-(--error)/30 bg-(--error-bg) px-4 py-3 text-sm text-(--error)">
        {error}
      </div>
    {/if}

    {#if success}
      <div class="rounded-lg border border-(--success)/30 bg-(--success-bg) px-4 py-3 text-sm text-(--success)">
        {success}
      </div>
    {/if}

    <div class="grid grid-cols-1 {showTestPanel ? 'lg:grid-cols-2' : ''} gap-6">
      <!-- Editor column -->
      <div class="space-y-4">
        <!-- Metadata fields -->
        <div class="rounded-xl border border-(--border) bg-(--bg-secondary) p-5 space-y-4">
          <div class="grid grid-cols-2 gap-4">
            <div>
              <label for="prog-name" class="block text-sm font-medium text-(--text-secondary) mb-1">Name</label>
              <input
                id="prog-name"
                type="text"
                bind:value={name}
                class="w-full px-3 py-2 rounded-lg bg-(--bg-primary) border border-(--border) text-(--text-primary) text-sm focus:outline-hidden"
              />
            </div>
            <div class="grid grid-cols-2 gap-2">
              <div>
                <label for="prog-scope" class="block text-sm font-medium text-(--text-secondary) mb-1">Scope</label>
                <SelectInput
                  id="prog-scope"
                  bind:value={scope}
                >
                  <option value="global">Global</option>
                  <option value="system_prompt">System Prompt</option>
                  <option value="messages">Messages</option>
                  <option value="tools">Tools</option>
                </SelectInput>
              </div>
              <div>
                <label for="prog-priority" class="block text-sm font-medium text-(--text-secondary) mb-1">Priority</label>
                <input
                  id="prog-priority"
                  type="number"
                  bind:value={priority}
                  class="w-full px-3 py-2 rounded-lg bg-(--bg-primary) border border-(--border) text-(--text-primary) text-sm focus:outline-hidden"
                />
              </div>
            </div>
          </div>

          <div>
            <label for="prog-match-mode" class="block text-sm font-medium text-(--text-secondary) mb-1">Execution</label>
            <SelectInput id="prog-match-mode" bind:value={matchMode}>
              <option value="full">Full context — script edits the whole scope</option>
              <option value="span">Per match (span) — script rewrites each match of the pattern</option>
            </SelectInput>
            <p class="mt-1 text-xs text-(--text-secondary)">
              {#if matchMode === 'span'}
                The engine finds every match of the pattern below and runs your script once per match:
                <code>fn transform(m)</code> with <code>m.matched</code>, <code>m.groups</code>,
                <code>m.before</code>, <code>m.after</code> — return the replacement string.
              {:else}
                Your script runs once over the whole scope: <code>fn transform(ctx)</code>.
              {/if}
            </p>
          </div>

          <div>
            <label for="prog-desc" class="block text-sm font-medium text-(--text-secondary) mb-1">Description</label>
            <textarea
              id="prog-desc"
              bind:value={description}
              rows="3"
              class="w-full px-3 py-2 rounded-lg bg-(--bg-primary) border border-(--border) text-(--text-primary) text-sm focus:outline-hidden resize-y"
              placeholder="Optional description"
            ></textarea>
          </div>

          <div class="flex gap-4">
            <div class="flex-1">
              <label for="prog-model-filter" class="block text-sm font-medium text-(--text-secondary) mb-1">Model Filter</label>
              <input
                id="prog-model-filter"
                type="text"
                bind:value={modelFilter}
                class="w-full px-3 py-2 rounded-lg bg-(--bg-primary) border border-(--border) text-(--text-primary) text-sm focus:outline-hidden"
                placeholder="e.g. gpt-4o, gpt-4o-mini (empty = all)"
              />
            </div>
            <div class="flex-1">
              <label for="prog-app-filter" class="block text-sm font-medium text-(--text-secondary) mb-1">App Filter</label>
              <input
                id="prog-app-filter"
                type="text"
                bind:value={appFilter}
                class="w-full px-3 py-2 rounded-lg bg-(--bg-primary) border border-(--border) text-(--text-primary) text-sm focus:outline-hidden"
                placeholder="e.g. opencode, claude-code (empty = all)"
              />
            </div>
          </div>

          <div>
            <label for="prog-trigger-regex" class="block text-sm font-medium text-(--text-secondary) mb-1">
              {matchMode === 'span' ? 'Match pattern' : 'Trigger Regex'}
              {#if matchMode === 'span'}<span class="text-(--error)">*</span>{/if}
            </label>
            <input
              id="prog-trigger-regex"
              type="text"
              bind:value={triggerRegex}
              class="w-full px-3 py-2 rounded-lg bg-(--bg-primary) border border-(--border) text-(--text-primary) text-sm font-mono focus:outline-hidden"
              placeholder={matchMode === 'span'
                ? 'Required — the script runs once per match of this pattern'
                : 'e.g. @ — fast-find; runs only when content matches (empty = always)'}
            />
            {#if spanNeedsTrigger}
              <p class="mt-1 text-xs text-(--error)">Span mode requires a match pattern.</p>
            {/if}
          </div>

          <div class="flex items-center gap-3">
            <label class="relative inline-flex items-center cursor-pointer">
              <input type="checkbox" bind:checked={enabled} class="sr-only peer" />
              <div class="w-9 h-5 bg-(--border) peer-focus:ring-2 peer-focus:ring-(--accent) rounded-full peer peer-checked:after:translate-x-full after:content-[''] after:absolute after:top-0.5 after:left-0.5 after:bg-white after:ring-1 after:ring-(--bg-primary)/60 after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-(--accent)"></div>
            </label>
            <span class="text-sm text-(--text-secondary)">Enabled</span>
          </div>
        </div>

        <!-- Source editor -->
        <div class="rounded-xl border border-(--border) bg-(--bg-secondary) overflow-hidden">
          <div class="flex items-center justify-between px-4 py-3 border-b border-(--border)">
            <span class="text-sm font-medium text-(--text-primary)">Rhai Source</span>
            <div class="flex items-center gap-2">
              {#if validationStatus === 'checking'}
                <span class="text-xs text-(--text-secondary)">Checking…</span>
              {:else if validationStatus === 'valid'}
                <span class="flex items-center gap-1 text-xs text-(--success)">
                  <Icon name="check" size="sm" tone="success" />
                  Valid
                </span>
              {:else if validationStatus === 'invalid'}
                <span class="flex items-center gap-1 text-xs text-(--error)" title={validationError}>
                  <Icon name="close" size="sm" tone="error" />
                  Error
                </span>
              {/if}
            </div>
          </div>
          <textarea
            bind:value={source}
            oninput={onSourceChange}
            rows="20"
            class="w-full px-4 py-3 bg-(--bg-primary) text-(--text-primary) font-mono text-sm resize-y focus:outline-hidden border-0"
            spellcheck="false"
          ></textarea>
          {#if validationStatus === 'invalid' && validationError}
            <div class="px-4 py-2 bg-(--error-bg) border-t border-(--error)/30 text-xs text-(--error) font-mono">
              {validationError}
            </div>
          {/if}
        </div>

        <!-- Save button -->
        <div class="flex items-center gap-3">
          <button
            onclick={save}
            disabled={saving || spanNeedsTrigger}
            class="px-6 py-2.5 rounded-lg bg-(--accent) text-(--accent-fg) font-medium text-sm hover:bg-(--accent-hover) transition-all disabled:opacity-50"
          >
            {saving ? 'Saving…' : 'Save Program'}
          </button>
          <span class="text-xs text-(--text-secondary)">
            Saving increments the version and pushes to all edge nodes.
          </span>
        </div>
      </div>

      <!-- Test panel column -->
      {#if showTestPanel}
        <div class="space-y-4">
          <div class="rounded-xl border border-(--border) bg-(--bg-secondary) overflow-hidden">
            <div class="flex items-center justify-between px-4 py-3 border-b border-(--border)">
              <span class="text-sm font-medium text-(--text-primary)">Test Context (JSON)</span>
              <button
                onclick={runTest}
                disabled={testing}
                class="px-3 py-1.5 rounded-lg bg-(--accent) text-(--accent-fg) text-xs font-medium hover:bg-(--accent-hover) transition-all disabled:opacity-50"
              >
                {testing ? 'Running…' : 'Run Test'}
              </button>
            </div>
            <textarea
              bind:value={testContext}
              rows="14"
              class="w-full px-4 py-3 bg-(--bg-primary) text-(--text-primary) font-mono text-xs resize-y focus:outline-hidden border-0"
              spellcheck="false"
            ></textarea>
          </div>

          {#if testError}
            <div class="rounded-xl border border-(--error)/30 bg-(--error-bg) p-4">
              <p class="text-sm font-medium text-(--error) mb-1">Test Error</p>
              <pre class="text-xs text-(--error) font-mono whitespace-pre-wrap">{testError}</pre>
            </div>
          {/if}

          {#if testResult}
            <div class="rounded-xl border border-(--success)/30 bg-(--success-bg) overflow-hidden">
              <div class="px-4 py-3 border-b border-(--success)/30">
                <p class="text-sm font-medium text-(--success)">Test Result</p>
              </div>
              <pre class="px-4 py-3 text-xs text-(--text-primary) font-mono whitespace-pre-wrap overflow-auto max-h-96">{JSON.stringify(testResult, null, 2)}</pre>
            </div>
          {/if}
        </div>
      {/if}
    </div>
  </div>
{/if}
