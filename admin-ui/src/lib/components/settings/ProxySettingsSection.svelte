<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import { extractSettings, extractError, extractErrorCode, updateSettings } from '#lib/api-helpers.js';
  import { toast } from '#lib/toast.svelte.js';
  import HelpTooltip from '#lib/components/HelpTooltip.svelte';
  import { onMount } from 'svelte';

  let jsonHealing = $state(true);
  let debugMode = $state(false);
  let streamIdleTimeout = $state(300);
  let saving = $state(false);

  const FEATURE_KEYS: Record<string, string> = {
    jsonHealing: 'healing_enabled',
    debugMode: 'debug_mode',
  };

  async function loadConfig() {
    const { data, error: err } = await adminApi.GET('/api/v1/admin/settings');
    if (err) {
      toast.error('Failed to load config', { body: extractError(err), code: extractErrorCode(err) ?? undefined });
    } else if (data) {
      const s = extractSettings(data);
      jsonHealing = (s.healing_enabled as boolean) ?? true;
      debugMode = (s.debug_mode as boolean) ?? false;
      streamIdleTimeout = (s.stream_idle_timeout_secs as number) ?? 300;
    }
  }

  async function saveFeatureToggle(uiKey: string, value: boolean) {
    const dbKey = FEATURE_KEYS[uiKey];
    if (!dbKey) return;
    const { error: err } = await updateSettings({ [dbKey]: value });
    if (err) {
      toast.error(`Failed to save ${uiKey}`, { body: extractError(err), code: extractErrorCode(err) ?? undefined });
    } else {
      toast.success('Saved');
    }
  }

  async function handleSaveTimeout() {
    saving = true;
    const { error: err } = await updateSettings({ stream_idle_timeout_secs: streamIdleTimeout });
    if (err) {
      toast.error('Failed to save stream timeout', { body: extractError(err), code: extractErrorCode(err) ?? undefined });
    } else {
      toast.success('Stream timeout saved');
    }
    saving = false;
  }

  onMount(loadConfig);
</script>

<div class="space-y-4">
  <h3 class="text-lg font-semibold text-(--text-primary)">Proxy Configuration</h3>

  <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
    <div class="bg-(--bg-card) rounded-xl p-5 border border-(--border) flex items-center justify-between">
      <div>
        <p class="font-medium text-(--text-primary)">JSON Healing</p>
        <p class="text-xs text-(--text-secondary) mt-0.5">Auto-repair malformed JSON in structured responses</p>
      </div>
      <label class="relative inline-flex items-center cursor-pointer shrink-0 ml-4">
        <input type="checkbox" checked={jsonHealing} onchange={() => { jsonHealing = !jsonHealing; saveFeatureToggle('jsonHealing', jsonHealing); }} class="sr-only peer" />
        <div class="w-11 h-6 bg-(--border) peer-focus:outline-hidden rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-0.5 after:inset-s-0.5 after:bg-white after:ring-1 after:ring-(--bg-primary)/60 after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-(--success)"></div>
      </label>
    </div>
    <div class="bg-(--bg-card) rounded-xl p-5 border border-(--border) flex items-center justify-between">
      <div>
        <p class="font-medium text-(--text-primary)">Debug Mode</p>
        <p class="text-xs text-(--text-secondary) mt-0.5">Add debug headers and echo diagnostic info in responses</p>
      </div>
      <label class="relative inline-flex items-center cursor-pointer shrink-0 ml-4">
        <input type="checkbox" checked={debugMode} onchange={() => { debugMode = !debugMode; saveFeatureToggle('debugMode', debugMode); }} class="sr-only peer" />
        <div class="w-11 h-6 bg-(--border) peer-focus:outline-hidden rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-0.5 after:inset-s-0.5 after:bg-white after:ring-1 after:ring-(--bg-primary)/60 after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-(--success)"></div>
      </label>
    </div>
  </div>

  <div class="bg-(--bg-card) rounded-xl p-5 border border-(--border)">
    <div class="flex items-center justify-between">
      <div>
        <p class="font-medium text-(--text-primary) inline-flex items-center gap-1.5">
          SSE Stream Idle Timeout
          <HelpTooltip body="Resets on every chunk the upstream sends. If silence exceeds this window the proxy aborts the stream with a 504-equivalent error and stamps a streaming_idle_timeout audit badge. Raise it for chatty MCP servers, lower it to fail fast on stuck upstreams." />
        </p>
        <p class="text-xs text-(--text-secondary) mt-0.5">Max seconds to wait between SSE chunks before aborting</p>
      </div>
      <div class="flex items-center gap-2 shrink-0 ml-4">
        <input bind:value={streamIdleTimeout} type="number" min="30" max="3600" class="w-20 px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm text-right" />
        <span class="text-xs text-(--text-secondary)">sec</span>
        <button onclick={handleSaveTimeout} disabled={saving} class="px-4 py-2 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-sm font-medium disabled:opacity-50">Save</button>
      </div>
    </div>
  </div>
</div>
