<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import { extractSettings, extractError, extractErrorCode, updateSettings } from '#lib/api-helpers.js';
  import { toast } from '#lib/toast.svelte.js';
  import NumberSetting from '#lib/components/forms/NumberSetting.svelte';
  import ToggleSetting from '#lib/components/forms/ToggleSetting.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import { onMount } from 'svelte';

  interface Props {
    /** Optional callback fired after `agent_enabled` is toggled — lets the host
     * page reload its dashboard so flagged-session listings reflect the new
     * agent state. Off by default. */
    onAgentToggled?: () => void | Promise<void>;
  }

  let { onAgentToggled }: Props = $props();

  let agentEnabled = $state(false);
  let agentInterval = $state(3600);
  let agentCooldown = $state(30);
  let runWindowEnabled = $state(false);
  let runWindowStart = $state(22);
  let runWindowEnd = $state(6);
  let settingsLoading = $state(true);

  // Local-timezone preview of the configured UTC window — helpful since the
  // setting is stored as UTC but operators usually think in local time.
  const localWindowPreview = $derived.by(() => {
    if (!runWindowEnabled) return '';
    const fmt = (utcHour: number) => {
      const d = new Date();
      d.setUTCHours(utcHour, 0, 0, 0);
      return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
    };
    return `Local time: ${fmt(runWindowStart)} → ${fmt(runWindowEnd)}`;
  });

  async function loadSettings() {
    settingsLoading = true;
    try {
      const { data: res } = await adminApi.GET('/api/v1/admin/settings');
      if (res) {
        const s = extractSettings(res);
        agentEnabled = s.agent_enabled === true;
        agentInterval = s.agent_interval_secs ?? 3600;
        agentCooldown = (s.agent_session_cooldown_mins as number) ?? 30;
        runWindowEnabled = s.agent_run_window_enabled === true;
        runWindowStart = s.agent_run_window_start_hour_utc ?? 22;
        runWindowEnd = s.agent_run_window_end_hour_utc ?? 6;
      }
    } catch (e) {
      console.warn('Failed to load settings:', e);
    } finally {
      settingsLoading = false;
    }
  }

  async function saveAgentEnabled(next: boolean) {
    const { error: err } = await updateSettings({ agent_enabled: next });
    if (err) {
      toast.error('Failed to save', { body: extractError(err), code: extractErrorCode(err) ?? undefined });
      agentEnabled = !next;
      return;
    }
    toast.success(next ? 'Agent enabled' : 'Agent disabled');
    if (onAgentToggled) await onAgentToggled();
  }

  async function saveInterval() {
    const { error: err } = await updateSettings({ agent_interval_secs: agentInterval });
    if (err) {
      toast.error('Failed to save interval', { body: extractError(err), code: extractErrorCode(err) ?? undefined });
      return;
    }
    toast.success('Interval saved');
  }

  async function saveCooldown() {
    const { error: err } = await updateSettings({ agent_session_cooldown_mins: agentCooldown });
    if (err) {
      toast.error('Failed to save cooldown', { body: extractError(err), code: extractErrorCode(err) ?? undefined });
      return;
    }
    toast.success('Cooldown saved');
  }

  async function saveRunWindow() {
    const start = Math.max(0, Math.min(23, Math.trunc(runWindowStart)));
    const end = Math.max(0, Math.min(23, Math.trunc(runWindowEnd)));
    runWindowStart = start;
    runWindowEnd = end;
    const { error: err } = await updateSettings({
      agent_run_window_enabled: runWindowEnabled,
      agent_run_window_start_hour_utc: start,
      agent_run_window_end_hour_utc: end,
    });
    if (err) {
      toast.error('Failed to save run window', { body: extractError(err), code: extractErrorCode(err) ?? undefined });
      return;
    }
    toast.success('Run window saved');
  }

  async function toggleRunWindow(next: boolean) {
    runWindowEnabled = next;
    await saveRunWindow();
  }

  onMount(() => {
    loadSettings();
  });
</script>

<section>
  <div class="mb-4">
    <h3 class="text-lg font-semibold text-(--text-primary)">Agent Settings</h3>
    <p class="text-xs text-(--text-secondary) mt-0.5">Configure the background agent that analyzes sessions and proposes transform programs. The judge model is set per expert profile (Experts → Profiles).</p>
  </div>

  {#if settingsLoading}
    <div class="bg-(--bg-card) rounded-xl p-5 border border-(--border)">
      <div class="w-32 h-4 bg-(--bg-primary) rounded-sm animate-pulse"></div>
    </div>
  {:else}
    <div class="bg-(--bg-card) rounded-xl p-5 border border-(--border) mb-4">
      <ToggleSetting
        label="Enable Agent"
        description="When enabled, the agent periodically analyzes sessions through expert lenses — flagging alerts, proposing transforms and tool rules, and detecting session linkage"
        bind:value={agentEnabled}
        onValueChange={saveAgentEnabled}
      />
    </div>

    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
      <div class="bg-(--bg-card) rounded-xl p-5 border border-(--border)">
        <div class="flex items-center gap-2">
          <div class="flex-1 min-w-0">
            <NumberSetting
              label="Analysis Interval"
              description="Seconds between analysis cycles"
              bind:value={agentInterval}
              min={60}
              max={86400}
              unit="sec"
            />
          </div>
          <button onclick={saveInterval} class="self-end px-4 py-2 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-sm font-medium transition-colors">Save</button>
        </div>
      </div>

      <div class="bg-(--bg-card) rounded-xl p-5 border border-(--border)">
        <div class="flex items-center gap-2">
          <div class="flex-1 min-w-0">
            <NumberSetting
              label="Session Cooldown"
              description="Minutes of inactivity before a session is eligible for analysis (0 = immediate)"
              bind:value={agentCooldown}
              min={0}
              max={1440}
              unit="min"
            />
          </div>
          <button onclick={saveCooldown} class="self-end px-4 py-2 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-sm font-medium transition-colors">Save</button>
        </div>
      </div>

      <div class="bg-(--bg-card) rounded-xl p-5 border border-(--border) md:col-span-2">
        <ToggleSetting
          label="Restrict to Run Window"
          description="When enabled, the agent only runs analysis cycles inside the configured UTC hour window. Outside the window, cycles skip with a log line. Useful for reserving on-premise LLM capacity for off-hours."
          bind:value={runWindowEnabled}
          onValueChange={toggleRunWindow}
        />
        {#if runWindowEnabled}
          <div class="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-4 pt-4 border-t border-(--border)">
            <div>
              <label for="agent-run-window-start" class="block text-xs text-(--text-secondary) mb-1 uppercase tracking-wider">Start hour (UTC)</label>
              <SelectInput
                id="agent-run-window-start"
                bind:value={runWindowStart}
                onchange={saveRunWindow}
              >
                {#each Array(24) as _, h (h)}
                  <option value={h}>{h.toString().padStart(2, '0')}:00</option>
                {/each}
              </SelectInput>
            </div>
            <div>
              <label for="agent-run-window-end" class="block text-xs text-(--text-secondary) mb-1 uppercase tracking-wider">End hour (UTC)</label>
              <SelectInput
                id="agent-run-window-end"
                bind:value={runWindowEnd}
                onchange={saveRunWindow}
              >
                {#each Array(24) as _, h (h)}
                  <option value={h}>{h.toString().padStart(2, '0')}:00</option>
                {/each}
              </SelectInput>
            </div>
          </div>
          <p class="text-xs text-(--text-secondary) mt-3">
            {#if runWindowStart === runWindowEnd}
              <span class="text-(--warning)">Start and end are equal — window is empty; the agent will never run.</span>
            {:else if runWindowStart < runWindowEnd}
              UTC window: {runWindowStart.toString().padStart(2, '0')}:00 → {runWindowEnd.toString().padStart(2, '0')}:00 ({runWindowEnd - runWindowStart}h).
            {:else}
              UTC window crosses midnight: {runWindowStart.toString().padStart(2, '0')}:00 → {runWindowEnd.toString().padStart(2, '0')}:00 ({24 - runWindowStart + runWindowEnd}h).
            {/if}
            {#if localWindowPreview}
              <br />{localWindowPreview}
            {/if}
          </p>
        {/if}
      </div>
    </div>
  {/if}
</section>
