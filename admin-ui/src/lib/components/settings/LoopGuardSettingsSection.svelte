<script lang="ts">
  // The organisation's default agent loop guard — what every workspace runs
  // unless it sets its own (on the workspace's Limits tab). The Agent
  // workspace is never guarded.
  import { adminApi } from '#lib/api-client.js';
  import { extractSettings, extractError, extractErrorCode, updateSettings } from '#lib/api-helpers.js';
  import LoopGuardFields from '#lib/components/limits/LoopGuardFields.svelte';
  import { LOOP_GUARD_DEFAULT, LOOP_GUARD_HELP, loopGuardProblem, type LoopGuardSettings } from '#lib/loop-guard.js';
  import { toast } from '#lib/toast.svelte.js';
  import { onMount } from 'svelte';

  let guard = $state<LoopGuardSettings>({ ...LOOP_GUARD_DEFAULT });
  let loaded = $state(false);
  let saving = $state(false);

  async function loadConfig() {
    const { data, error: err } = await adminApi.GET('/api/v1/admin/settings');
    if (err) {
      toast.error('Failed to load the agent loop guard', {
        body: extractError(err),
        code: extractErrorCode(err) ?? undefined,
      });
      return;
    }
    if (!data) return;
    const s = extractSettings(data);
    guard = {
      mode: s.loop_guard_mode ?? LOOP_GUARD_DEFAULT.mode,
      nudge_at: s.loop_guard_nudge_at ?? LOOP_GUARD_DEFAULT.nudge_at,
      stop_at: s.loop_guard_stop_at ?? LOOP_GUARD_DEFAULT.stop_at,
    };
    loaded = true;
  }

  async function handleSave() {
    if (loopGuardProblem(guard)) return;
    saving = true;
    const { error: err } = await updateSettings({
      loop_guard_mode: guard.mode,
      loop_guard_nudge_at: guard.nudge_at,
      loop_guard_stop_at: guard.stop_at,
    });
    if (err) {
      toast.error('Failed to save the agent loop guard', {
        body: extractError(err),
        code: extractErrorCode(err) ?? undefined,
      });
    } else {
      toast.success('Agent loop guard saved');
    }
    saving = false;
  }

  onMount(loadConfig);
</script>

<div class="space-y-4" data-testid="loop-guard-settings">
  <div>
    <h3 class="text-lg font-semibold text-(--text-primary)">Agent Loop Guard</h3>
    <p class="text-sm text-(--text-secondary) mt-1">{LOOP_GUARD_HELP}</p>
    <p class="text-sm text-(--text-secondary) mt-1">
      This is the organisation default; a workspace can set its own on its Limits tab. The Agent workspace is never guarded.
    </p>
  </div>

  <div class="bg-(--bg-card) rounded-xl p-6 border border-(--border)">
    <LoopGuardFields bind:value={guard} idPrefix="tenant-loop-guard" disabled={!loaded} />
    <div class="flex items-center gap-3 mt-5">
      <button
        onclick={handleSave}
        disabled={saving || !loaded || loopGuardProblem(guard) !== null}
        data-testid="tenant-loop-guard-save"
        class="px-5 py-2 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-sm font-medium transition-colors disabled:opacity-50"
      >{saving ? 'Saving…' : 'Save'}</button>
    </div>
  </div>
</div>
