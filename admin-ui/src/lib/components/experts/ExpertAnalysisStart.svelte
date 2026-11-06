<script lang="ts">
  /**
   * Where a profile's analysis stands, and the action that restarts it from a
   * date. The cursor is kept per expert and profile, so it moves for every
   * workspace using the profile: the section names them.
   */
  import { adminApi } from '#lib/api-client.js';
  import { extractError } from '#lib/api-helpers.js';
  import { analyzesAgain, leavesBehind, localDay, localInstant } from '#lib/analysisStart.js';
  import ConfirmDialog from '#lib/components/ConfirmDialog.svelte';
  import TextInput from '#lib/components/forms/TextInput.svelte';
  import { formatDateTime } from '#lib/formatters.js';
  import { toast } from '#lib/toast.svelte.js';
  import type { components } from '#lib/generated/api-types.js';

  type AnalysisStart = components['schemas']['AnalysisStartResponse'];

  interface Props {
    profileId: string;
    /** The Default also covers sessions attributed to no workspace. */
    isDefault: boolean;
    /** Changes when the page saved what this section reads (the profile's experts). */
    reloadKey?: number;
    /** The page holds unsaved expert changes: a restart moves the saved experts only. */
    unsaved?: boolean;
  }

  let { profileId, isDefault, reloadKey = 0, unsaved = false }: Props = $props();

  const opened = localDay(new Date());
  let today = $state(opened);
  let day = $state(opened);
  let time = $state('');
  // A time input reads '' until it is complete, which would mean no time at all.
  let timeIncomplete = $state(false);
  let current = $state<AnalysisStart | null>(null);
  let loadError = $state('');
  let confirming = $state(false);
  let saving = $state(false);

  // Today with no time means from now, so what is queued today is dropped; an
  // earlier day with no time starts at its first instant.
  const isToday = $derived(day === today && !time);
  const from = $derived(localInstant(day, time));
  // A time is the admin's own; a notification dates a session in UTC.
  const named = $derived(
    time && from ? `${day} ${time} your time (${from.toISOString().slice(0, 16).replace('T', ' ')} UTC)` : day,
  );
  const again = $derived(!isToday && !!from && analyzesAgain(from, current?.furthest_through));
  // Today already says everything so far is dropped; only an earlier date can
  // leave a lagging expert behind without saying so.
  const dropsLagging = $derived(
    !isToday && !!from && leavesBehind(from, current?.analyzed_through, current?.furthest_through),
  );
  const lagNote = $derived(
    dropsLagging ? ' An expert that is behind skips what it has not reached before this date.' : '',
  );
  const confirmMessage = $derived(
    (again
      ? `Sessions with activity since ${named} are analyzed again at the next cycle. This spends the Agent workspace's budget. Alerts never get downgraded. A note at the same level, or an issue over the same sessions, is stored again only if the model words it differently. A suggestion may surface sooner.`
      : isToday
        ? 'Sessions with no new activity from now on are not analyzed. This applies at the next cycle.'
        : `Sessions with no activity since ${named} are not analyzed. This applies at the next cycle.`) + lagNote,
  );

  // A page left open past midnight: a field still on the old today follows it.
  function refreshToday() {
    const now = localDay(new Date());
    if (now === today) return;
    if (day === today && !time) day = now;
    today = now;
  }

  // The position is read again: the warning is about where analysis stands now.
  async function askToRestart() {
    refreshToday();
    if (from && from.getTime() > Date.now()) {
      toast.error('That time is still to come. Pick a past time, or clear it to restart from now.');
      return;
    }
    await load();
    if (current?.restartable) confirming = true;
  }

  // Bumped per load: a response for an earlier profile id is dropped.
  let loadGen = 0;

  async function load() {
    const gen = ++loadGen;
    const { data, error } = await adminApi.GET('/api/v1/admin/profiles/{id}/analysis-start', {
      params: { path: { id: profileId } },
    });
    if (gen !== loadGen) return;
    // A failed read keeps the last position, and the button can read it again.
    if (data) current = data;
    loadError = error ? extractError(error, 'Failed to load the analysis position') : '';
  }

  $effect(() => {
    void profileId;
    void reloadKey;
    load();
  });

  async function restart() {
    confirming = false;
    if (!from) return;
    saving = true;
    const { data, error } = await adminApi.POST('/api/v1/admin/profiles/{id}/actions/set-analysis-start', {
      params: { path: { id: profileId } },
      body: isToday ? {} : { from: from.toISOString() },
    });
    saving = false;
    if (error) {
      toast.error('Could not restart the analysis', { body: extractError(error) });
      return;
    }
    toast.success(data?.message ?? 'Analysis restarted');
    time = '';
    await load();
  }
</script>

<section class="bg-(--bg-card) rounded-xl p-5 border border-(--border) mb-6">
  <div class="grid gap-4 md:grid-cols-[1fr_minmax(16rem,24rem)] md:items-start">
    <div>
      <h2 class="font-medium text-(--text-primary)">Analysis start</h2>
      <p class="text-xs text-(--text-secondary) mt-1 leading-relaxed">
        Skip a backlog by restarting from today, which means from now, or pick an earlier date to
        analyze sessions with activity since then again, for every enabled expert this profile runs.
        Add a time to restart from that minute, in your own time zone: just after a session the
        judge model's provider refuses, for one. A disabled expert keeps its own position.
      </p>
      {#if unsaved}
        <p class="text-xs text-(--warning) mt-1.5">Save or discard your expert changes first: a restart moves the saved experts.</p>
      {/if}
      {#if loadError}
        <p class="text-xs text-(--error-text) mt-1.5">{loadError}</p>
      {/if}
      {#if timeIncomplete}
        <p class="text-xs text-(--warning) mt-1.5">Finish the time, or clear it.</p>
      {:else if day && time && !from}
        <p class="text-xs text-(--warning) mt-1.5">That minute does not exist on this day: the clocks change. Pick another.</p>
      {/if}
      {#if current}
        <p class="text-xs text-(--text-secondary) mt-1.5">
          Applies to:
          <span class="text-(--text-primary)">{[...current.workspaces.map((w) => w.name), ...(isDefault ? ['sessions with no workspace'] : [])].join(', ') || 'no workspace'}</span>
        </p>
        <p class="text-xs text-(--text-secondary) mt-1">
          {#if !current.restartable}
            <span class="block mb-1">This profile has nothing to restart: it needs an enabled expert that reads sessions, and a workspace using it.</span>
          {/if}
          Analyzed up to:
          <span class="text-(--text-primary)">{current.analyzed_through ? formatDateTime(current.analyzed_through) : current.furthest_through ? 'not every expert has started' : 'not started'}</span>
        </p>
      {/if}
    </div>
    <div class="flex items-end gap-2 flex-wrap">
      <div class="flex-1 min-w-40">
        <label for="analysis-start-date" class="block text-sm text-(--text-secondary) mb-1">Analyze from</label>
        <TextInput id="analysis-start-date" type="date" max={today} bind:value={day} disabled={saving} onfocus={refreshToday} />
      </div>
      <div class="w-44">
        <label for="analysis-start-time" class="block text-sm text-(--text-secondary) mb-1">Time, yours (optional)</label>
        <TextInput
          id="analysis-start-time"
          type="time"
          bind:value={time}
          disabled={saving}
          oninput={(e) => (timeIncomplete = e.currentTarget.validity.badInput)}
          onblur={(e) => (timeIncomplete = e.currentTarget.validity.badInput)}
        />
      </div>
      <button
        type="button"
        onclick={askToRestart}
        disabled={saving || unsaved || current?.restartable === false || !from || day > today || timeIncomplete}
        class="px-3 py-2 border border-(--border) rounded-lg text-sm text-(--text-primary) hover:bg-(--bg-primary) disabled:opacity-50"
      >
        Restart from this date
      </button>
    </div>
  </div>
</section>

<ConfirmDialog
  open={confirming}
  title="Restart the analysis?"
  message={confirmMessage}
  confirmLabel="Restart"
  onconfirm={restart}
  oncancel={() => (confirming = false)}
/>
