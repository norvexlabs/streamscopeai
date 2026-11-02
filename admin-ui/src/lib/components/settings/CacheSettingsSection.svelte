<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import { extractError, extractErrorCode } from '#lib/api-helpers.js';
  import { toast } from '#lib/toast.svelte.js';
  import type { components } from '#lib/generated/api-types.js';
  import Callout from '#lib/components/Callout.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import FormField from '#lib/components/forms/FormField.svelte';
  import Modal from '#lib/components/Modal.svelte';
  import NumberSetting from '#lib/components/forms/NumberSetting.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import TextInput from '#lib/components/forms/TextInput.svelte';
  import TagBadge from '#lib/components/TagBadge.svelte';
  import ToggleSetting from '#lib/components/forms/ToggleSetting.svelte';
  import { onMount } from 'svelte';

  type CachePreset = components['schemas']['CachePreset'];
  type ProbeResult = components['schemas']['ProbeEmbeddingResponse'];
  type AliasOption = components['schemas']['EmbeddingAliasOption'];

  // ── Tenant-wide backend settings ──
  let enabled = $state(true);
  let maxEntryKb = $state(256);
  let embeddingAlias = $state('');
  let embeddingTimeoutMs = $state(3000);
  let loading = $state(true);
  let saving = $state(false);

  // ── Embedding alias picker + probe ──
  let aliasOptions = $state<AliasOption[]>([]);
  let probing = $state(false);
  let probeResult = $state<ProbeResult | null>(null);
  // The SAVED alias, not the edit-in-progress one: readiness describes what the
  // gateway is running, so an unsaved edit must not flip a Semantic preset's
  // status to something no request would see.
  let savedEmbeddingAlias = $state('');

  /**
   * Whether similarity matching can actually happen, shown on the preset rows
   * that depend on it. The probe buys a real embedding, so it stays on-demand
   * and this reports the configuration state — the failure operators actually
   * hit. Observe is included deliberately: it scores by meaning too, so without
   * an embedding model it silently stops producing the very tuning signal it
   * exists for.
   */
  const SEMANTIC_MODES = ['semantic', 'observe'];

  function semanticStatus(mode: string) {
    if (!SEMANTIC_MODES.includes(mode)) return null;
    if (!savedEmbeddingAlias) {
      return {
        icon: 'triangleAlert' as const,
        tone: 'warning' as const,
        text:
          mode === 'observe'
            ? 'No embedding model is configured, so this preset cannot measure what matching by meaning would add — only what word-for-word already serves. Set one under Embedding Model below.'
            : 'No embedding model is configured, so this preset can only serve word-for-word matches. Set one under Embedding Model below.',
      };
    }
    if (!probeResult || probeResult.alias !== savedEmbeddingAlias) return null;
    return probeResult.ok
      ? {
          icon: 'checkCircle' as const,
          tone: 'success' as const,
          text: `Matching by meaning is ready via ${savedEmbeddingAlias}.`,
        }
      : {
          icon: 'triangleAlert' as const,
          tone: 'error' as const,
          text: `${savedEmbeddingAlias} did not check out, so this preset falls back to word-for-word matches.`,
        };
  }

  // ── Preset CRUD ──
  let presets = $state<CachePreset[]>([]);
  let presetsLoading = $state(true);
  let showPresetForm = $state(false);
  let editingPresetId = $state<string | null>(null);
  let presetName = $state('');
  let presetMode = $state('observe');
  let presetTtl = $state(3600);
  let presetThreshold = $state(0.9);
  let presetScope = $state('workspace');
  let presetError = $state('');
  let savingPreset = $state(false);
  let deleteTarget = $state<CachePreset | null>(null);
  let deleting = $state(false);

  async function loadSettings() {
    loading = true;
    const { data, error: err } = await adminApi.GET('/api/v1/admin/settings/cache');
    if (err) {
      toast.error('Failed to load response-cache settings', {
        body: extractError(err),
        code: extractErrorCode(err) ?? undefined,
      });
    } else if (data) {
      enabled = data.enabled ?? true;
      maxEntryKb = data.max_entry_kb ?? 256;
      embeddingAlias = data.embedding_alias ?? '';
      savedEmbeddingAlias = embeddingAlias;
      embeddingTimeoutMs = data.embedding_timeout_ms ?? 3000;
    }
    loading = false;
  }

  // A result describes the alias it was run against. Once the field moves on,
  // a lingering green banner would certify a value nobody checked.
  $effect(() => {
    if (probeResult && embeddingAlias.trim() !== probeResult.alias) probeResult = null;
  });

  async function loadAliasOptions() {
    const { data } = await adminApi.GET('/api/v1/admin/settings/cache/embedding-aliases', {});
    aliasOptions = data?.items ?? [];
  }

  async function probeAlias() {
    const alias = embeddingAlias.trim();
    if (!alias) return;
    probing = true;
    probeResult = null;
    const { data, error: err } = await adminApi.POST(
      '/api/v1/admin/settings/cache/actions/probe-embedding',
      { body: { alias } },
    );
    probing = false;
    if (err) {
      toast.error('Could not check this alias', {
        body: extractError(err),
        code: extractErrorCode(err) ?? undefined,
      });
      return;
    }
    probeResult = data ?? null;
    // A probe that succeeds classifies the model, so the picker's verified
    // marks are now out of date.
    if (probeResult?.classified?.length) await loadAliasOptions();
  }

  async function loadPresets() {
    presetsLoading = true;
    const { data, error: err } = await adminApi.GET('/api/v1/admin/cache-presets', {});
    if (err) {
      toast.error('Failed to load cache presets', { body: extractError(err) });
    } else {
      presets = data?.items ?? [];
    }
    presetsLoading = false;
  }

  async function saveSettings() {
    saving = true;
    const { error: err } = await adminApi.PATCH('/api/v1/admin/settings/cache', {
      body: {
        enabled,
        max_entry_kb: maxEntryKb,
        // Explicit null clears it; an omitted key would leave the old alias in
        // place, so an admin could never turn semantic matching back off.
        embedding_alias: embeddingAlias.trim() || null,
        embedding_timeout_ms: embeddingTimeoutMs,
      },
    });
    saving = false;
    if (err) {
      toast.error('Failed to save', {
        body: extractError(err),
        code: extractErrorCode(err) ?? undefined,
      });
      return;
    }
    savedEmbeddingAlias = embeddingAlias.trim();
    toast.success('Response-cache settings saved');
  }

  function openCreate() {
    editingPresetId = null;
    presetName = '';
    presetMode = 'observe';
    presetTtl = 3600;
    presetThreshold = 0.9;
    presetScope = 'workspace';
    presetError = '';
    showPresetForm = true;
  }

  function openEdit(p: CachePreset) {
    editingPresetId = p.id;
    presetName = p.name;
    presetMode = p.mode;
    presetTtl = p.ttl_seconds;
    presetThreshold = p.threshold;
    presetScope = p.share_scope;
    presetError = '';
    showPresetForm = true;
  }

  async function savePreset() {
    if (!presetName.trim()) {
      presetError = 'Name is required.';
      return;
    }
    savingPreset = true;
    presetError = '';
    const body = {
      name: presetName.trim(),
      mode: presetMode,
      ttl_seconds: presetTtl,
      threshold: presetThreshold,
      share_scope: presetScope,
    };
    const { error: err } = editingPresetId
      ? await adminApi.PATCH('/api/v1/admin/cache-presets/{id}', {
          params: { path: { id: editingPresetId } },
          body,
        })
      : await adminApi.POST('/api/v1/admin/cache-presets', { body });
    savingPreset = false;
    if (err) {
      presetError = extractError(err, 'Failed to save cache preset');
      return;
    }
    showPresetForm = false;
    toast.success(editingPresetId ? 'Cache preset updated' : 'Cache preset created');
    await loadPresets();
  }

  async function confirmDelete() {
    if (!deleteTarget) return;
    deleting = true;
    const { error: err } = await adminApi.DELETE('/api/v1/admin/cache-presets/{id}', {
      params: { path: { id: deleteTarget.id } },
    });
    deleting = false;
    if (err) {
      toast.error(extractError(err, 'Failed to delete cache preset'));
      return;
    }
    deleteTarget = null;
    toast.success('Cache preset deleted');
    await loadPresets();
  }

  async function flushTenantCache() {
    const { data, error: err } = await adminApi.POST(
      '/api/v1/admin/maintenance/flush-response-cache',
      {},
    );
    if (err) {
      toast.error(extractError(err, 'Failed to flush cached responses'));
      return;
    }
    toast.success(data?.message ?? 'Cached responses dropped');
  }

  const MODE_LABEL: Record<string, string> = {
    exact: 'Exact',
    semantic: 'Semantic',
    observe: 'Observe',
  };
  const SCOPE_LABEL: Record<string, string> = {
    workspace: 'Workspace',
    user: 'User',
    tenant: 'Tenant-wide',
  };

  function ttlLabel(seconds: number): string {
    if (seconds < 60) return `${seconds}s`;
    if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
    return `${(seconds / 3600).toFixed(seconds % 3600 === 0 ? 0 : 1)}h`;
  }

  onMount(() => {
    void loadSettings();
    void loadPresets();
    void loadAliasOptions();
  });
</script>

<section class="space-y-4 max-w-4xl">
  <!-- Overview -->
  <div class="bg-(--bg-card) rounded-xl border border-(--border) p-5">
    <h3 class="text-sm font-semibold text-(--text-primary)">Response Cache</h3>
    <p class="text-xs text-(--text-secondary) mt-1">
      Serve a repeated request from a stored answer instead of calling the provider again — cutting
      spend and latency on identical prompts. A cache hit is a normal audited turn: it appears in the
      audit log with a <strong>Cached</strong> badge showing what it saved, and it still counts
      toward request rate limits.
    </p>
    <p class="text-xs text-(--text-secondary) mt-2">
      Caching is off everywhere until you attach a preset to an alias. Define a preset below, then
      pick it in the alias editor under <span class="text-(--text-primary)">Gateways → LLM</span>.
      The recommended path is to start a preset in <strong>Observe</strong>, watch the audit log for
      Cache&nbsp;Observed badges, then switch it to Exact once the match rate looks right.
    </p>
  </div>

  <!-- Presets -->
  <div class="bg-(--bg-card) rounded-xl border border-(--border) p-5 space-y-3">
    <div class="flex items-center justify-between">
      <div>
        <h3 class="text-sm font-semibold text-(--text-primary)">Cache Presets</h3>
        <p class="text-xs text-(--text-secondary) mt-0.5">
          Named policies aliases point at. Change one here and every alias using it follows.
        </p>
      </div>
      <button
        onclick={openCreate}
        class="px-3 py-1.5 bg-(--accent) hover:bg-(--accent-hover) text-(--accent-fg) text-sm font-medium rounded-lg transition-colors"
      >
        New Preset
      </button>
    </div>

    {#if presetsLoading}
      <div class="w-32 h-4 bg-(--bg-primary) rounded-sm animate-pulse"></div>
    {:else if presets.length === 0}
      <p class="text-xs text-(--text-secondary) px-3 py-4 text-center">
        No cache presets yet. Create one, then attach it to an alias to start caching.
      </p>
    {:else}
      <div class="overflow-x-auto">
        <table class="w-full text-sm">
          <thead>
            <tr class="border-b border-(--border)">
              <th class="px-3 py-2 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Name</th>
              <th class="px-3 py-2 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Mode</th>
              <th class="px-3 py-2 text-right text-xs text-(--text-secondary) uppercase tracking-wider font-medium">TTL</th>
              <th class="px-3 py-2 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Shared With</th>
              <th class="px-3 py-2 text-right text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Aliases</th>
              <th class="px-3 py-2 text-right text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Actions</th>
            </tr>
          </thead>
          <tbody>
            {#each presets as p (p.id)}
              {@const status = semanticStatus(p.mode)}
              <tr class="border-b border-(--border) hover:bg-(--bg-elevated) transition-colors">
                <td class="px-3 py-2 font-medium text-(--text-primary)">{p.name}</td>
                <td class="px-3 py-2">
                  <TagBadge color={p.mode === 'observe' ? 'blue' : 'teal'}>
                    {MODE_LABEL[p.mode] ?? p.mode}
                  </TagBadge>
                  {#if status}
                    <span class="ml-1 align-middle" title={status.text}>
                      <Icon name={status.icon} size="xs" tone={status.tone} />
                    </span>
                  {/if}
                </td>
                <td class="px-3 py-2 text-right font-mono text-(--text-secondary)">{ttlLabel(p.ttl_seconds)}</td>
                <td class="px-3 py-2 text-(--text-secondary)">
                  {SCOPE_LABEL[p.share_scope] ?? p.share_scope}
                  {#if p.share_scope === 'tenant'}
                    <span title="Answers computed for one workspace can be served to another in this tenant.">
                      <Icon name="triangleAlert" size="xs" tone="warning" />
                    </span>
                  {/if}
                </td>
                <td class="px-3 py-2 text-right font-mono text-(--text-secondary)">{p.route_count}</td>
                <td class="px-3 py-2 text-right whitespace-nowrap">
                  <button onclick={() => openEdit(p)} class="text-xs text-(--accent) hover:underline">Edit</button>
                  <button onclick={() => (deleteTarget = p)} class="ml-3 text-xs text-(--error) hover:underline">Delete</button>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </div>

  <!-- Tenant-wide settings -->
  {#if loading}
    <div class="bg-(--bg-card) rounded-xl p-5 border border-(--border)">
      <div class="w-32 h-4 bg-(--bg-primary) rounded-sm animate-pulse"></div>
    </div>
  {:else}
    <div class="bg-(--bg-card) rounded-xl border border-(--border) p-5 space-y-4">
      <h3 class="text-sm font-semibold text-(--text-primary)">Tenant Settings</h3>
      <ToggleSetting
        label="Response Cache Enabled"
        description="Master switch. Turn it off to stop serving stored answers on every alias at once, without editing each preset."
        bind:value={enabled}
      />
      <NumberSetting
        label="Maximum Cached Response"
        description="Responses larger than this are served normally but never stored — a single huge answer would otherwise crowd out many small ones. The audit row records why it was skipped."
        bind:value={maxEntryKb}
        min={1}
        max={8192}
        unit="KB"
      />
      <FormField
        label="Embedding Alias"
        for="cache-embedding-alias"
        help="The model a Semantic preset uses to compare prompts by meaning. Enter one of your own embedding aliases — the same name a client would send as the model. Leave it empty and Semantic presets still serve word-for-word matches; each request then records that similarity matching was unavailable."
      >
        <div class="flex items-center gap-2">
          <TextInput
            id="cache-embedding-alias"
            bind:value={embeddingAlias}
            list="cache-embedding-alias-options"
            placeholder="e.g. text-embedding-3-small"
          />
          <button
            onclick={probeAlias}
            disabled={probing || !embeddingAlias.trim()}
            class="shrink-0 px-3 py-1.5 bg-(--bg-primary) border border-(--border) hover:border-(--accent) text-(--text-primary) text-sm font-medium rounded-lg transition-colors disabled:opacity-50"
          >
            {probing ? 'Checking…' : 'Check'}
          </button>
        </div>
        <datalist id="cache-embedding-alias-options">
          {#each aliasOptions as opt (opt.alias)}
            <option value={opt.alias} label={opt.verified ? 'known embedding model' : ''}></option>
          {/each}
        </datalist>
      </FormField>
      {#if probeResult}
        <Callout
          severity={probeResult.ok ? 'success' : 'error'}
          title={probeResult.ok ? 'Ready for similarity matching' : 'Not usable for similarity matching'}
        >
          {#if probeResult.targets.length === 0}
            <p class="text-sm">
              No enabled route serves <span class="font-mono">{probeResult.alias}</span>. Add a route
              for it under Gateways, or pick an alias from the list.
            </p>
          {:else}
            <p class="text-sm">
              {probeResult.ok
                ? 'This alias can produce embeddings on every target the cache may use.'
                : 'This alias cannot be used for similarity matching yet.'}
            </p>
            <ul class="mt-2 space-y-1">
              {#each probeResult.targets as t, i (i)}
                <li class="text-sm flex items-start gap-2">
                  <Icon name={t.ok ? 'checkCircle' : 'errorCircle'} size="sm" />
                  <span>
                    <span class="font-mono">{t.upstream_model}</span>
                    <span class="text-(--text-secondary)">· {t.server}</span>
                    {#if t.ok}
                      <span class="text-(--text-secondary)">
                        · {t.dimensions} dimensions · {t.elapsed_ms} ms
                      </span>
                    {:else if t.message}
                      <span class="block text-(--text-secondary)">{t.message}</span>
                    {/if}
                  </span>
                </li>
              {/each}
            </ul>
          {/if}
          {#each probeResult.warnings as w, i (i)}
            <p class="mt-2 text-sm text-(--text-secondary)">{w}</p>
          {/each}
        </Callout>
      {/if}
      <NumberSetting
        label="Embedding Time Limit"
        description="How long the gateway waits for the comparison model before giving up and answering from the provider instead. A cache must never be the slowest part of a request."
        bind:value={embeddingTimeoutMs}
        min={50}
        max={15000}
        step={50}
        unit="ms"
      />
      <div class="flex items-center gap-3 pt-1">
        <button
          onclick={saveSettings}
          disabled={saving}
          class="px-4 py-2 bg-(--accent) hover:bg-(--accent-hover) text-(--accent-fg) text-sm font-medium rounded-lg transition-colors disabled:opacity-50"
        >
          {saving ? 'Saving…' : 'Save Settings'}
        </button>
        <button
          onclick={flushTenantCache}
          class="px-4 py-2 bg-(--bg-primary) border border-(--border) hover:border-(--accent) text-(--text-primary) text-sm font-medium rounded-lg transition-colors"
        >
          Flush All Cached Responses
        </button>
      </div>
    </div>
  {/if}
</section>

<Modal
  open={showPresetForm}
  title={editingPresetId ? 'Edit Cache Preset' : 'New Cache Preset'}
  onclose={() => (showPresetForm = false)}
>
  <div class="space-y-4">
      <label class="block text-xs text-(--text-secondary) uppercase tracking-wider">Name
        <input
          bind:value={presetName}
          type="text"
          placeholder="Exact 1h"
          class="w-full mt-1 px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm placeholder:text-(--text-secondary)"
        />
      </label>

      <label class="block text-xs text-(--text-secondary) uppercase tracking-wider">Mode
        <SelectInput bind:value={presetMode} class="mt-1">
          <option value="observe">Observe — record would-be hits, never serve</option>
          <option value="exact">Exact — serve identical requests</option>
          <option value="semantic">Semantic — serve similar requests</option>
        </SelectInput>
        <span class="text-[10px] text-(--text-secondary) font-normal normal-case tracking-normal mt-0.5 block">
          Observe is the safe starting point: requests still go to the provider, but the audit log
          shows which ones would have been served from cache. With an embedding alias configured it
          also scores reworded questions, so one Observe run tells you what Exact alone would serve
          and how much more Semantic would add.
        </span>
      </label>

      <div class="grid grid-cols-2 gap-4">
        <label class="block text-xs text-(--text-secondary) uppercase tracking-wider">Lifetime (seconds)
          <input
            bind:value={presetTtl}
            type="number"
            min="1"
            max="2592000"
            class="w-full mt-1 px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm"
          />
          <span class="text-[10px] text-(--text-secondary) font-normal normal-case tracking-normal mt-0.5 block">
            How long a stored answer stays servable. Currently {ttlLabel(presetTtl)}.
          </span>
        </label>
        <!-- Observe scores reworded questions too — that is what makes it the
             tuning mode — so the threshold it measures against belongs here as
             well, not only on Semantic. -->
        {#if presetMode === 'semantic' || presetMode === 'observe'}
          <label class="block text-xs text-(--text-secondary) uppercase tracking-wider">Similarity Threshold
            <input
              bind:value={presetThreshold}
              type="number"
              min="0.01"
              max="1"
              step="0.01"
              class="w-full mt-1 px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm"
            />
            <span class="text-[10px] text-(--text-secondary) font-normal normal-case tracking-normal mt-0.5 block">
              How close a reworded question must be to reuse an answer. Start high and lower it only
              while watching answer quality.
            </span>
          </label>
        {/if}
      </div>

      <label class="block text-xs text-(--text-secondary) uppercase tracking-wider">Shared With
        <SelectInput bind:value={presetScope} class="mt-1">
          <option value="workspace">Workspace — reused within the workspace that produced it</option>
          <option value="user">User — reused only by the same person</option>
          <option value="tenant">Tenant-wide — reused across every workspace</option>
        </SelectInput>
      </label>

      {#if presetScope === 'tenant'}
        <Callout severity="warning" title="Answers cross workspace boundaries">
          A stored answer can contain content from the prompt that produced it. Tenant-wide sharing
          means one workspace's answer can be served to another. Choose this only where the aliases
          carry no workspace-private context.
        </Callout>
      {/if}

      {#if presetError}
        <div class="flex items-start gap-2 px-3.5 py-3 bg-(--error)/10 border border-(--error) rounded-lg">
          <span class="shrink-0 mt-0.5"><Icon name="errorCircle" size="sm" tone="error" /></span>
          <p class="text-sm text-(--error)">{presetError}</p>
        </div>
      {/if}

    <div class="flex justify-end gap-3">
      <button
        onclick={() => (showPresetForm = false)}
        class="px-4 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm transition-colors"
      >
        Cancel
      </button>
      <button
        onclick={savePreset}
        disabled={savingPreset}
        class="px-4 py-2 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-sm font-medium disabled:opacity-50 transition-colors"
      >
        {savingPreset ? 'Saving…' : 'Save Preset'}
      </button>
    </div>
  </div>
</Modal>

<Modal
  open={deleteTarget !== null}
  title="Delete cache preset"
  onclose={() => (deleteTarget = null)}
  maxWidth="max-w-md"
>
  {#if deleteTarget}
    <p class="text-sm text-(--text-primary)">
      Delete <strong>{deleteTarget.name}</strong>?
    </p>
    {#if deleteTarget.route_count > 0}
      <p class="text-sm text-(--text-secondary) mt-2 mb-4">
        {deleteTarget.route_count}
        {deleteTarget.route_count === 1 ? 'alias stops' : 'aliases stop'} caching and go back to
        calling the provider on every request. Nothing else changes, and no traffic is interrupted.
      </p>
    {:else}
      <p class="text-sm text-(--text-secondary) mt-2 mb-4">No alias is using it.</p>
    {/if}
  {/if}
  <div class="flex justify-end gap-3">
    <button
      onclick={() => (deleteTarget = null)}
      class="px-4 py-2 text-sm rounded-lg border border-(--border) text-(--text-secondary) hover:bg-(--bg-elevated) hover:text-(--text-primary) transition-colors"
    >Cancel</button>
    <button
      onclick={confirmDelete}
      disabled={deleting}
      class="px-4 py-2 text-sm rounded-lg bg-(--error) text-(--error-fg) hover:bg-(--error)/85 disabled:opacity-50"
    >{deleting ? 'Deleting…' : 'Delete'}</button>
  </div>
</Modal>
