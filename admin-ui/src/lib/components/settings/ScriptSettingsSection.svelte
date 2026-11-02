<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import { extractSettings, extractError, extractErrorCode, updateSettings } from '#lib/api-helpers.js';
  import { toast } from '#lib/toast.svelte.js';
  import { onMount } from 'svelte';

  type FailMode = 'open' | 'closed';

  let rhaiFailMode = $state<FailMode>('open');
  let settingsLoading = $state(true);
  let savingFailMode = $state(false);

  async function loadSettings() {
    settingsLoading = true;
    const { data, error: err } = await adminApi.GET('/api/v1/admin/settings');
    if (err) {
      toast.error('Failed to load settings', { body: extractError(err), code: extractErrorCode(err) ?? undefined });
    } else if (data) {
      const s = extractSettings(data);
      rhaiFailMode = s.rhai_fail_mode === 'closed' ? 'closed' : 'open';
    }
    settingsLoading = false;
  }

  async function setFailMode(next: FailMode) {
    if (next === rhaiFailMode || savingFailMode) return;
    savingFailMode = true;
    const previous = rhaiFailMode;
    rhaiFailMode = next;
    const { error: err } = await updateSettings({ rhai_fail_mode: next });
    if (err) {
      rhaiFailMode = previous;
      toast.error('Failed to save fail mode', { body: extractError(err), code: extractErrorCode(err) ?? undefined });
    } else {
      toast.success(`Script fail mode: ${next}`);
    }
    savingFailMode = false;
  }

  onMount(loadSettings);
</script>

<div class="space-y-6">
  <div class="border border-(--border) rounded-lg p-4">
    <div class="mb-3">
      <h3 class="text-sm font-medium text-(--text-primary)">Script Fail Mode</h3>
      <p class="text-xs text-(--text-secondary) mt-0.5">
        What happens when a Rhai transform script errors mid-pipeline. Applied uniformly to request-phase, streaming response-phase, and non-streaming response-phase scripts.
      </p>
    </div>

    {#if settingsLoading}
      <span class="text-xs text-(--text-secondary)">Loading…</span>
    {:else}
      <div class="space-y-2" role="radiogroup" aria-label="Rhai fail mode">
        <button
          type="button"
          role="radio"
          aria-checked={rhaiFailMode === 'open'}
          disabled={savingFailMode}
          onclick={() => setFailMode('open')}
          class="w-full text-left p-3 rounded-lg border transition-colors {rhaiFailMode === 'open'
            ? 'border-(--accent) bg-(--bg-elevated)'
            : 'border-(--border) hover:bg-(--bg-elevated)'} {savingFailMode ? 'opacity-60' : ''}"
        >
          <div class="flex items-start gap-3">
            <span
              class="mt-0.5 w-4 h-4 rounded-full border-2 shrink-0 flex items-center justify-center {rhaiFailMode === 'open'
                ? 'border-(--accent)'
                : 'border-(--text-tertiary)'}"
            >
              {#if rhaiFailMode === 'open'}
                <span class="w-2 h-2 rounded-full bg-(--accent)"></span>
              {/if}
            </span>
            <div class="min-w-0">
              <div class="text-sm font-medium text-(--text-primary)">Open (fail-open)</div>
              <div class="text-xs text-(--text-secondary) mt-0.5">
                Script failures log a warning, push a <code class="font-mono text-(--text-tertiary)">:error</code> tag, and continue with unmodified content. Safer default — preserves request flow.
              </div>
            </div>
          </div>
        </button>

        <button
          type="button"
          role="radio"
          aria-checked={rhaiFailMode === 'closed'}
          disabled={savingFailMode}
          onclick={() => setFailMode('closed')}
          class="w-full text-left p-3 rounded-lg border transition-colors {rhaiFailMode === 'closed'
            ? 'border-(--accent) bg-(--bg-elevated)'
            : 'border-(--border) hover:bg-(--bg-elevated)'} {savingFailMode ? 'opacity-60' : ''}"
        >
          <div class="flex items-start gap-3">
            <span
              class="mt-0.5 w-4 h-4 rounded-full border-2 shrink-0 flex items-center justify-center {rhaiFailMode === 'closed'
                ? 'border-(--accent)'
                : 'border-(--text-tertiary)'}"
            >
              {#if rhaiFailMode === 'closed'}
                <span class="w-2 h-2 rounded-full bg-(--accent)"></span>
              {/if}
            </span>
            <div class="min-w-0">
              <div class="text-sm font-medium text-(--text-primary)">Closed (fail-closed)</div>
              <div class="text-xs text-(--text-secondary) mt-0.5">
                Request-phase failures return HTTP 500 to the client. Response-phase failures suppress the affected block and emit an operator notice. Use when scripts enforce security or compliance invariants that must not be bypassed by a script bug.
              </div>
            </div>
          </div>
        </button>
      </div>
    {/if}
  </div>
</div>
