<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import { extractError, extractErrorCode, updateSettings, fetchAllPages } from '#lib/api-helpers.js';
  import { toast } from '#lib/toast.svelte.js';
  import type { AppInfo } from '#lib/api-types.js';
  import { usePeriodicLoad } from '#lib/hooks.svelte.js';

  interface Props { activate?: boolean; }
  let { activate = true }: Props = $props();

  const _urlParams = typeof window !== 'undefined' ? new URLSearchParams(window.location.search) : null;
  const _addUa = _urlParams?.get('add_ua') ?? '';
  const _editAppId = _urlParams?.get('edit_app') ?? '';

  let appRegistryAll = $state<AppInfo[]>([]);
  let appRegistryLoaded = $state(false);
  let appRegistrySaved = $state(false);
  let appSaveError = $state('');
  let appSaving = $state(false);

  let showAddApp = $state(false);
  let newAppId = $state('');
  let newAppName = $state('');
  let newAppDesc = $state('');
  let newAppUrl = $state('');
  let uaPatternsInput = $state('');
  let refererPatternsInput = $state('');
  let promptPatternsInput = $state('');

  let editingAppId = $state<string | null>(null);
  let editApp = $state({ name: '', description: '', url: '', ua_patterns: '', referer_patterns: '', prompt_patterns: '' });

  // Prompt patterns are sentences that contain commas, so they are entered one
  // per line rather than comma-separated like the header patterns.
  const promptLines = (text: string) => text.split('\n').map(s => s.trim()).filter(Boolean);

  // Only the latest read lands, and a save supersedes a read in flight: a
  // registry read before the save landing after it would be the base of the
  // next save, deleting what this one added.
  let registryGen = 0;
  async function loadAppRegistry() {
    const gen = ++registryGen;
    try {
      const items = await fetchAllPages<AppInfo>((offset, limit) =>
        adminApi.GET('/api/v1/admin/analytics/apps', { params: { query: { offset, limit } } }));
      if (gen !== registryGen) return;
      appRegistryAll = items.sort((a, b) => (a.name || a.id).localeCompare(b.name || b.id));
      appRegistryLoaded = true;
    } catch (e) {
      toast.error('Failed to load app registry', {
        body: extractError(e),
        code: extractErrorCode(e) ?? undefined,
      });
    }
  }

  /** Save `next` as the registry; true when the server accepted it. The
   *  local registry changes only then, so a refused save leaves the list as
   *  it was and the caller's form holds what was typed for a retry. A saved
   *  registry decides the app of new traffic; past rows keep theirs. */
  async function saveAppRegistry(next: AppInfo[]): Promise<boolean> {
    appSaveError = '';
    appSaving = true;
    try {
      const { error: saveErr } = await updateSettings({ app_registry: JSON.parse(JSON.stringify(next)) });
      if (saveErr) {
        appSaveError = extractError(saveErr) || 'Failed to save';
        return false;
      }
      // The saved list is the registry now: a read still in flight is older.
      ++registryGen;
      appRegistryAll = next;
      appRegistryLoaded = true;
      appRegistrySaved = true;
      setTimeout(() => appRegistrySaved = false, 2000);
      return true;
    } catch (e: unknown) {
      appSaveError = e instanceof Error ? e.message : 'Failed to save app registry';
      return false;
    } finally {
      appSaving = false;
    }
  }

  function findAppWithPattern(uaPatterns: string[], refPatterns: string[], promptPatterns: string[], excludeId?: string): AppInfo | undefined {
    const uaLower = uaPatterns.map(p => p.toLowerCase());
    const refLower = refPatterns.map(p => p.toLowerCase());
    const promptLower = promptPatterns.map(p => p.toLowerCase());
    return appRegistryAll.find(a => {
      if (excludeId && a.id === excludeId) return false;
      if (uaLower.length && a.ua_patterns?.some(p => uaLower.includes(p.toLowerCase()))) return true;
      if (refLower.length && a.referer_patterns?.some(p => refLower.includes(p.toLowerCase()))) return true;
      if (promptLower.length && a.prompt_patterns?.some(p => promptLower.includes(p.toLowerCase()))) return true;
      return false;
    });
  }

  async function addCustomApp() {
    if (!newAppId.trim() || !newAppName.trim()) return;
    const uaPatterns = uaPatternsInput.split(',').map(s => s.trim()).filter(Boolean);
    const refPatterns = refererPatternsInput.split(',').map(s => s.trim()).filter(Boolean);
    const promptPatterns = promptLines(promptPatternsInput);

    if (appRegistryAll.some(a => a.id === newAppId.trim())) {
      appSaveError = `App ID "${newAppId.trim()}" already exists`;
      return;
    }
    const dup = findAppWithPattern(uaPatterns, refPatterns, promptPatterns);
    if (dup) {
      appSaveError = `Pattern already used by "${dup.name || dup.id}" — edit that app instead`;
      return;
    }
    appSaveError = '';
    const next: AppInfo[] = [...appRegistryAll, {
      id: newAppId.trim(),
      name: newAppName.trim(),
      description: newAppDesc.trim(),
      url: newAppUrl.trim(),
      builtin: false,
      ua_patterns: uaPatterns.length > 0 ? uaPatterns : undefined,
      referer_patterns: refPatterns.length > 0 ? refPatterns : undefined,
      prompt_patterns: promptPatterns.length > 0 ? promptPatterns : undefined,
    }];
    // The form keeps what was typed until the server accepts it.
    if (!(await saveAppRegistry(next))) return;
    newAppId = ''; newAppName = ''; newAppDesc = ''; newAppUrl = '';
    uaPatternsInput = ''; refererPatternsInput = ''; promptPatternsInput = '';
    showAddApp = false;
  }

  function removeApp(id: string) {
    void saveAppRegistry(appRegistryAll.filter(a => a.id !== id));
  }

  function startEditApp(app: AppInfo) {
    editingAppId = app.id;
    editApp = {
      name: app.name ?? '',
      description: app.description ?? '',
      url: app.url ?? '',
      ua_patterns: (app.ua_patterns || []).join(', '),
      referer_patterns: (app.referer_patterns || []).join(', '),
      prompt_patterns: (app.prompt_patterns || []).join('\n'),
    };
  }

  async function saveEditApp() {
    if (!editingAppId) return;
    const ua = editApp.ua_patterns.split(',').map(s => s.trim()).filter(Boolean);
    const ref_ = editApp.referer_patterns.split(',').map(s => s.trim()).filter(Boolean);
    const prompt = promptLines(editApp.prompt_patterns);
    const next: AppInfo[] = appRegistryAll.map(a => a.id === editingAppId ? {
      ...a,
      builtin: false,
      name: editApp.name.trim(),
      description: editApp.description.trim(),
      url: editApp.url.trim(),
      ua_patterns: ua.length > 0 ? ua : undefined,
      referer_patterns: ref_.length > 0 ? ref_ : undefined,
      prompt_patterns: prompt.length > 0 ? prompt : undefined,
    } : a);
    // The edit form stays open with what was typed until the server accepts it.
    if (await saveAppRegistry(next)) editingAppId = null;
  }

  let _deepLinkHandled = false;
  $effect(() => {
    if (!activate || !appRegistryLoaded || _deepLinkHandled) return;
    _deepLinkHandled = true;

    if (_editAppId) {
      const match = appRegistryAll.find(a => a.id === _editAppId);
      if (match) startEditApp(match);
    } else if (_addUa) {
      const existing = appRegistryAll.find(a =>
        a.ua_patterns?.some(p => _addUa.toLowerCase().includes(p.toLowerCase()))
      );
      if (existing) {
        startEditApp(existing);
      } else {
        showAddApp = true;
        uaPatternsInput = _addUa;
      }
    }
    if (editingAppId || showAddApp) {
      requestAnimationFrame(() => {
        const el = document.querySelector('[data-app-edit]');
        el?.scrollIntoView({ behavior: 'smooth', block: 'center' });
      });
    }

    if (_addUa || _editAppId) {
      const url = new URL(window.location.href);
      url.searchParams.delete('add_ua');
      url.searchParams.delete('edit_app');
      history.replaceState(history.state, '', url.toString());
    }
  });

  usePeriodicLoad(loadAppRegistry);
</script>

<div class="bg-(--bg-card) rounded-xl border border-(--border)">
  <div class="flex items-center justify-between px-6 py-4 border-b border-(--border)">
    <div>
      <h3 class="text-sm font-semibold text-(--text-primary)">App Registry</h3>
      <p class="text-xs text-(--text-secondary) mt-0.5">An app is named by the client's X-App-Id header, then its Referer, then its User-Agent; a system prompt pattern is tried only when none of those matched. Saved patterns name new traffic; past traffic keeps its app.</p>
    </div>
    <div class="flex items-center gap-2">
      {#if appSaveError}
        <span class="text-xs text-(--error)">{appSaveError}</span>
      {/if}
      {#if appRegistrySaved}
        <span class="text-xs text-(--success)">Saved</span>
      {/if}
      <button
        onclick={() => showAddApp = !showAddApp}
        class="px-3 py-1.5 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-xs font-medium transition-colors"
      >
        {showAddApp ? 'Cancel' : '+ Add App'}
      </button>
    </div>
  </div>

  {#if showAddApp}
    <div data-app-edit class="px-6 py-4 border-b border-(--border) bg-(--bg-primary)/30">
      <div class="grid grid-cols-2 gap-3 mb-3">
        <label class="block text-xs text-(--text-secondary)">App ID
          <input bind:value={newAppId} placeholder="e.g. my-tool" class="w-full mt-1 px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm" />
        </label>
        <label class="block text-xs text-(--text-secondary)">Display Name
          <input bind:value={newAppName} placeholder="Display Name" class="w-full mt-1 px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm" />
        </label>
        <label class="block text-xs text-(--text-secondary)">Description
          <input bind:value={newAppDesc} placeholder="Description" class="w-full mt-1 px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm" />
        </label>
        <label class="block text-xs text-(--text-secondary)">URL
          <input bind:value={newAppUrl} placeholder="URL (optional)" class="w-full mt-1 px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm" />
        </label>
      </div>
      <div class="grid grid-cols-2 gap-3 mb-3">
        <label class="block text-xs text-(--text-secondary)">UA Patterns (comma-separated)
          <input type="text" bind:value={uaPatternsInput}
                 placeholder="e.g. my-tool/, mytool-cli"
                 class="w-full mt-1 px-3 py-2 text-sm bg-(--bg-secondary) border border-(--border) rounded-lg text-(--text-primary)" />
        </label>
        <label class="block text-xs text-(--text-secondary)">Referer Patterns (comma-separated)
          <input type="text" bind:value={refererPatternsInput}
                 placeholder="e.g. mytool.com, mytool.dev"
                 class="w-full mt-1 px-3 py-2 text-sm bg-(--bg-secondary) border border-(--border) rounded-lg text-(--text-primary)" />
        </label>
        <label class="col-span-2 block text-xs text-(--text-secondary)">System prompt patterns (one per line, at least 12 characters, matched in the prompt's opening)
          <textarea bind:value={promptPatternsInput} rows="2"
                    placeholder="e.g. you are mytool, a coding agent"
                    class="w-full mt-1 px-3 py-2 text-sm font-mono bg-(--bg-secondary) border border-(--border) rounded-lg text-(--text-primary)"></textarea>
        </label>
      </div>
      <button onclick={addCustomApp} disabled={appSaving || !newAppId.trim() || !newAppName.trim()} class="px-4 py-2 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-sm font-medium disabled:opacity-50">Add</button>
    </div>
  {/if}

  <div class="divide-y divide-(--border)">
    {#each appRegistryAll as app}
      {#if editingAppId === app.id}
        <div data-app-edit class="px-6 py-4 bg-(--bg-primary)/30">
          <div class="grid grid-cols-2 gap-3 mb-3">
            <div>
              <span class="block text-xs text-(--text-secondary) mb-1">ID (read-only)</span>
              <span class="text-sm font-mono text-(--text-primary)">{app.id}</span>
            </div>
            <label class="block text-xs text-(--text-secondary)">Display Name
              <input bind:value={editApp.name} placeholder="Display Name" class="w-full mt-1 px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm" />
            </label>
            <label class="block text-xs text-(--text-secondary)">Description
              <input bind:value={editApp.description} placeholder="Description" class="w-full mt-1 px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm" />
            </label>
            <label class="block text-xs text-(--text-secondary)">URL
              <input bind:value={editApp.url} placeholder="URL" class="w-full mt-1 px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm" />
            </label>
            <label class="block text-xs text-(--text-secondary)">UA patterns (comma-separated)
              <input bind:value={editApp.ua_patterns} placeholder="UA patterns" class="w-full mt-1 px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm" />
            </label>
            <label class="block text-xs text-(--text-secondary)">Referer patterns (comma-separated)
              <input bind:value={editApp.referer_patterns} placeholder="Referer patterns" class="w-full mt-1 px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm" />
            </label>
            <label class="col-span-2 block text-xs text-(--text-secondary)">System prompt patterns (one per line, at least 12 characters)
              <textarea bind:value={editApp.prompt_patterns} rows="2" placeholder="System prompt patterns" class="w-full mt-1 px-3 py-2 font-mono bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm"></textarea>
            </label>
          </div>
          <div class="flex gap-2">
            <button onclick={saveEditApp} disabled={appSaving} class="px-4 py-1.5 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-xs font-medium disabled:opacity-50">Save</button>
            <button onclick={() => editingAppId = null} class="px-4 py-1.5 bg-(--bg-secondary) border border-(--border) rounded-lg text-(--text-primary) text-xs font-medium">Cancel</button>
          </div>
        </div>
      {:else}
        <div class="px-6 py-3 flex items-center justify-between">
          <div class="flex items-center gap-2 min-w-0">
            <span class="text-sm font-medium text-(--text-primary)">{app.name}</span>
            <span class="text-xs text-(--text-secondary) font-mono">{app.id}</span>
            {#if app.builtin}
              <span class="px-1.5 py-0.5 text-[10px] rounded-sm bg-(--bg-primary) text-(--text-secondary) border border-(--border)">built-in</span>
            {:else}
              <span class="px-1.5 py-0.5 text-[10px] rounded-sm bg-(--info-bg) text-(--info-text) border border-(--info-border)">custom</span>
            {/if}
            {#if app.ua_patterns && app.ua_patterns.length > 0}
              <span class="font-mono text-[10px] text-(--text-secondary) truncate max-w-50" title="UA: {app.ua_patterns.join(', ')}">UA: {app.ua_patterns.join(', ')}</span>
            {/if}
            {#if app.referer_patterns && app.referer_patterns.length > 0}
              <span class="font-mono text-[10px] text-(--text-secondary) truncate max-w-50" title="Ref: {app.referer_patterns.join(', ')}">Ref: {app.referer_patterns.join(', ')}</span>
            {/if}
            {#if app.prompt_patterns && app.prompt_patterns.length > 0}
              <span class="font-mono text-[10px] text-(--text-secondary) truncate max-w-50" title="Prompt: {app.prompt_patterns.join(' | ')}">Prompt: {app.prompt_patterns.join(' | ')}</span>
            {/if}
          </div>
          <div class="flex items-center gap-3 shrink-0">
            {#if app.description}
              <span class="text-xs text-(--text-secondary)">{app.description}</span>
            {/if}
            <button onclick={() => startEditApp(app)} class="text-xs text-(--accent) hover:underline">Edit</button>
            <button onclick={() => removeApp(app.id)} disabled={appSaving} class="text-xs text-(--error) hover:underline disabled:opacity-50">Remove</button>
          </div>
        </div>
      {/if}
    {/each}
    {#if appRegistryAll.length === 0}
      <div class="px-6 py-8 text-center text-sm text-(--text-secondary)">
        No apps detected yet. Apps are identified automatically from proxy traffic.
      </div>
    {/if}
  </div>
</div>
