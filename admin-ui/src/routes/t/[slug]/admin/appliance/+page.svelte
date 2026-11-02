<script lang="ts">
  import type { components } from '#lib/generated/api-types.js';
  import { adminApi } from '#lib/api-client.js';
  import { extractError, extractErrorCode } from '#lib/api-helpers.js';
  import { toast } from '#lib/toast.svelte.js';
  import { renderMarkdown } from '#lib/markdown.js';
  import { formatBytes, formatDateTime } from '#lib/formatters.js';
  import { untrack } from 'svelte';
  import { page } from '$app/state';
  import { goto } from '$app/navigation';
  import { thref } from '#lib/tenant.js';
  import { onRefresh, useTabState } from '#lib/hooks.svelte.js';
  import {
    jobName,
    jobSince,
    START,
    type FollowInput,
    type FollowState,
    mergeLog,
    wholeLog,
    release,
    sameVersion,
    type ApplianceJob,
  } from '#lib/appliance-follow.js';
  import { ApplianceReader } from '#lib/appliance-reader.js';
  import TabbedPage from '#lib/components/page/TabbedPage.svelte';
  import Skeleton from '#lib/components/Skeleton.svelte';
  import Callout from '#lib/components/Callout.svelte';
  import ConfirmDialog from '#lib/components/ConfirmDialog.svelte';
  import TextInput from '#lib/components/forms/TextInput.svelte';
  import TextArea from '#lib/components/forms/TextArea.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import NumberInput from '#lib/components/forms/NumberInput.svelte';
  import ToggleSetting from '#lib/components/forms/ToggleSetting.svelte';
  import type { PageProps } from './$types';

  let { params }: PageProps = $props();

  type ApplianceUpdates = components['schemas']['ApplianceUpdates'];
  type ApplianceRollbackPlan = components['schemas']['ApplianceRollbackPlan'];
  type HostVersion = components['schemas']['HostVersion'];
  type ApplianceStatus = components['schemas']['ApplianceStatus'];
  type BackupConfig = components['schemas']['BackupConfig'];
  type BackupStatus = components['schemas']['BackupStatus'];
  type ApplianceNetwork = components['schemas']['ApplianceNetwork'];
  type ApplianceNetworkMode = components['schemas']['ApplianceNetworkMode'];

  type ApplianceTab = 'management' | 'backup';
  const APPLIANCE_TABS = ['management', 'backup'] as const;
  const tab = useTabState<ApplianceTab>(APPLIANCE_TABS, 'management');

  let slug = $derived(params.slug);
  // Super-admin + appliance-only: a regular tenant or a non-appliance deploy is
  // bounced (the backend also 404s every route, this is just UX).
  $effect(() => {
    if (page.data.user && !page.data.user.appliance) {
      void goto(thref(slug, '/admin/overview'));
    }
  });

  let updates = $state<ApplianceUpdates | null>(null);
  let backupCfg = $state<BackupConfig | null>(null);
  let backupStatus = $state<BackupStatus | null>(null);
  let network = $state<ApplianceNetwork | null>(null);
  let rollbackPlan = $state<ApplianceRollbackPlan | null>(null);
  let loading = $state(true);

  // Confirm dialogs.
  let confirm = $state<
    null | 'restart' | 'shutdown' | 'rollback' | 'upgrade' | 'upgrade-restart' | 'network-reset'
  >(null);

  // The snapshot — the job, then the status — and the daemon's event journal
  // followed from the status's cursor (`#lib/appliance-follow.js`). What the page
  // says happened is a journal entry, never inferred from two snapshots, so a
  // reload, a second tab, the CLI and a timer's job all read the same.
  let status = $state<ApplianceStatus | null>(null);
  let job = $state.raw<ApplianceJob | null>(null);
  let jobLog = $state.raw<string[]>([]);
  // The follower's state (`#lib/appliance-follow.js`): the journal's cursor and
  // what the page knows of the appliance through it, written in one place.
  let fs = $state.raw<FollowState>(START);
  const watch = $derived(fs.watch);
  // Nothing answers, or the host service answers with an error: the actions wait.
  const offline = $derived(watch.kind === 'down' || watch.kind === 'faulty');
  // An action request is in flight.
  let starting = $state(false);
  // Set when this page instance is destroyed: the follower outlives the
  // component, and an orphan beside a new instance's would toast twice.
  let torndown = false;

  // Backup edit form.
  let editingBackup = $state(false);
  let bkDest = $state('');
  let bkRecipients = $state('');
  let bkProfile = $state('');
  let bkRetention = $state(30);
  let bkSchedule = $state('');
  let savingBackup = $state(false);

  // Network edit form. Seeded from the stored override when there is one, else
  // from what the interface is actually doing — so "edit" starts from the truth
  // on screen rather than from an empty form.
  let editingNetwork = $state(false);
  let netMode = $state<ApplianceNetworkMode>('dhcp');
  let netAddress = $state('');
  let netGateway = $state('');
  let netIpv6 = $state(false);
  let netAddress6 = $state('');
  let netGateway6 = $state('');
  let netDns = $state('');
  let netRevertSecs = $state(90);
  let savingNetwork = $state(false);
  // Local mirror of the daemon's countdown so the panel ticks without polling
  // every second; it re-reads the real state when it reaches zero.
  let netCountdown = $state(0);

  let netPending = $derived(network?.pending ?? null);

  // Each part of the rest of the page is numbered when its read starts, and
  // "Check now" when it answers: the latest stays, part by part, and a slow
  // part (the offer) never holds the others back.
  let restIssued = 0;
  const restApplied = { updates: 0, backupCfg: 0, backupStatus: 0, network: 0 };
  function landed(part: keyof typeof restApplied, n: number): boolean {
    if (torndown || n < restApplied[part]) return false;
    restApplied[part] = n;
    return true;
  }

  // `quiet` suppresses the error toast for reloads the operator did not ask for
  // (the countdown's own refresh) — a failing poll would otherwise raise a toast
  // per second.
  async function loadNetwork(quiet = false) {
    const n = ++restIssued;
    const { data, error } = await adminApi.GET('/api/v1/admin/global/appliance/network');
    if (error) {
      if (!quiet) toast.error(extractError(error));
      return;
    }
    if (data && landed('network', n)) network = data;
  }

  $effect(() => {
    const pending = netPending;
    if (!pending) {
      netCountdown = 0;
      return;
    }
    netCountdown = pending.secs_left;
    let refreshed = false;
    const id = setInterval(() => {
      netCountdown = Math.max(0, netCountdown - 1);
      // At zero the daemon has restored the previous configuration — re-read
      // rather than assume, since the revert itself can fail and retries. Once
      // only: the tick keeps running until the re-read lands, and a failing
      // appliance would otherwise be polled every second for as long as the page
      // is open.
      if (netCountdown === 0 && !refreshed) {
        refreshed = true;
        void loadNetwork(true);
      }
    }, 1000);
    return () => clearInterval(id);
  });

  function startEditNetwork() {
    // The form starts from what runs: the override, else the install's settings.
    // An appliance whose install did not record them predates opt-in IPv6: it
    // runs IPv6, and a static unit only when it reports `install` — its address,
    // gateway and resolvers then read from the live link, as a static network
    // without resolvers would have none.
    const source = network?.override_config ?? network?.install_config;
    const live = network?.live;
    netMode = source?.mode ?? (network?.source === 'install' ? 'static' : 'dhcp');
    netAddress = source?.address ?? live?.addresses?.find((a) => !a.includes(':')) ?? '';
    netGateway = source?.gateway ?? live?.gateway ?? '';
    netIpv6 = source?.ipv6 ?? true;
    netAddress6 = source?.address6 ?? '';
    netGateway6 = source?.gateway6 ?? '';
    netDns = (source ? (source.dns ?? []) : netMode === 'static' ? (live?.dns ?? []) : []).join(', ');
    netRevertSecs = 90;
    editingNetwork = true;
  }

  async function saveNetwork() {
    savingNetwork = true;
    const dns = netDns
      .split(',')
      .map((d) => d.trim())
      .filter((d) => d.length > 0);
    const { data, error } = await adminApi.PUT('/api/v1/admin/global/appliance/network', {
      body: {
        mode: netMode,
        address: netMode === 'static' ? netAddress.trim() : null,
        gateway: netMode === 'static' ? netGateway.trim() : null,
        ipv6: netIpv6,
        address6: netIpv6 && netAddress6.trim() ? netAddress6.trim() : null,
        gateway6: netIpv6 && netAddress6.trim() && netGateway6.trim() ? netGateway6.trim() : null,
        dns,
        revert_secs: netRevertSecs,
      },
    });
    savingNetwork = false;
    if (error) {
      toast.error(extractError(error));
      return;
    }
    editingNetwork = false;
    toast.success(
      data?.pending
        ? 'Network settings applied — confirm them below to keep them.'
        : 'Network settings applied.',
    );
    await loadNetwork();
  }

  // These three report the daemon's own message rather than a fixed string: the
  // auto-revert can fire between the operator pressing a button and the request
  // landing, so a hardcoded "kept" could claim the opposite of what happened.
  async function confirmNetwork() {
    const { data, error } = await adminApi.POST(
      '/api/v1/admin/global/appliance/network/actions/confirm',
      {},
    );
    if (error) toast.error(extractError(error));
    else toast.success(data?.message || 'The appliance answered.');
    await loadNetwork();
  }

  async function revertNetwork() {
    const { data, error } = await adminApi.POST(
      '/api/v1/admin/global/appliance/network/actions/revert',
      {},
    );
    if (error) toast.error(extractError(error));
    else toast.success(data?.message || 'The appliance answered.');
    await loadNetwork();
  }

  async function resetNetwork() {
    confirm = null;
    const { data, error } = await adminApi.POST(
      '/api/v1/admin/global/appliance/network/actions/reset',
      {},
    );
    if (error) toast.error(extractError(error));
    else toast.success(data?.message || 'The appliance answered.');
    await loadNetwork();
  }

  /** Read the whole page. `quiet` keeps what is on screen while it reads (a
   *  refresh after an action or an entry), instead of the skeleton. */
  async function load(quiet = false) {
    // Off-appliance the routes 404 (and the redirect above bounces the page);
    // don't fire the calls — a 404 would surface as a browser console error.
    if (!page.data.user?.appliance) {
      loading = false;
      return;
    }
    if (!quiet) loading = true;
    await ask('page');
    loading = false;
  }

  /** The rest of the page: what a job or a reboot may have changed besides the
   *  job and the status. A failed part keeps what is on screen. */
  function readRest() {
    const n = ++restIssued;
    void adminApi.GET('/api/v1/admin/global/appliance/updates').then(({ data }) => {
      if (data && landed('updates', n)) updates = data;
    });
    void adminApi.GET('/api/v1/admin/global/appliance/backup/config').then(({ data }) => {
      if (data && landed('backupCfg', n)) backupCfg = data;
    });
    readBackupStatus();
    void loadNetwork(true);
  }

  /** The backup status alone: what a backup job's end changes. */
  function readBackupStatus() {
    const n = ++restIssued;
    void adminApi.GET('/api/v1/admin/global/appliance/backup/status').then(({ data }) => {
      if (data && landed('backupStatus', n)) backupStatus = data;
    });
  }

  // -- the one reader -------------------------------------------------------
  //
  // Every read of the job and the status is the reader's (`#lib/appliance-reader.js`),
  // one at a time; this page gives it the reads and renders what they bring.

  /** The job, its log from the lines held when it is the job held. */
  async function readJobLog(): Promise<{ ok: boolean; ended: boolean; kind: string | null }> {
    const held = job;
    const since = jobSince(held);
    const jb = await adminApi.GET('/api/v1/admin/global/appliance/job', { params: { query: { since } } });
    if (torndown || !jb.data) return { ok: false, ended: false, kind: null };
    let next = jb.data;
    let log = mergeLog(held, jobLog, jb.data, since);
    if (!log) {
      // Another job than the one held, or lines the daemon no longer holds.
      const whole = await adminApi.GET('/api/v1/admin/global/appliance/job', { params: { query: { since: 0 } } });
      if (torndown || !whole.data) return { ok: false, ended: false, kind: null };
      next = whole.data;
      log = wholeLog(whole.data);
    }
    job = next;
    jobLog = log;
    return { ok: true, ended: held?.state === 'running' && next.state !== 'running', kind: next.kind ?? null };
  }

  /** The journal's answer after the cursor; null when the reader ended it. */
  async function readEvents(cursor: number, wait: number, signal: AbortSignal): Promise<FollowInput | null> {
    const asked = Date.now();
    try {
      const { data, error, response } = await adminApi.GET('/api/v1/admin/global/appliance/events', {
        params: { query: { after: cursor, wait } },
        signal,
      });
      if (data) {
        return { kind: 'events', events: data.events, next: data.next, truncated: data.truncated, elapsedMs: Date.now() - asked };
      }
      return { kind: 'events-failed', httpStatus: response.status, code: extractErrorCode(error) ?? null, reason: extractError(error) };
    } catch (e: unknown) {
      if (e instanceof DOMException && e.name === 'AbortError') return null;
      throw e;
    }
  }

  /** A status read, applied, as the follower's input. */
  async function readStatus(): Promise<FollowInput> {
    const r = await adminApi.GET('/api/v1/admin/global/appliance/status');
    if (r.data && !torndown) status = r.data;
    if (r.data) {
      return {
        kind: 'status',
        read: { kind: 'answered', events: r.data.events ?? null, eventsError: r.data.events_error ?? null, rebootPending: r.data.reboot_pending },
      };
    }
    return {
      kind: 'status',
      read: { kind: 'failed', httpStatus: r.response.status, code: extractErrorCode(r.error) ?? null, reason: extractError(r.error) },
    };
  }

  const reader = new ApplianceReader({
    events: readEvents,
    status: readStatus,
    job: readJobLog,
    rest: readRest,
    backupStatus: readBackupStatus,
    jobRunning: () => job?.state === 'running',
    notice: (n) => {
      if (n.tone === 'error') toast.error(n.text);
      else if (n.tone === 'warning') toast.warning(n.text);
      else toast.success(n.text);
    },
    state: (st) => {
      fs = st;
    },
    now: () => Date.now(),
    sleep: (ms, signal) =>
      new Promise((resolve) => {
        // The listener goes with the wait, whichever ends it.
        const end = () => {
          clearTimeout(t);
          signal.removeEventListener('abort', end);
          resolve();
        };
        const t = setTimeout(end, ms);
        signal.addEventListener('abort', end, { once: true });
      }),
  });

  function ask(kind: 'snapshot' | 'page'): Promise<void> {
    return reader.ask(kind);
  }

  // Once per page instance: `load()` reads `page.data`, which must not re-run
  // this effect — its cleanup ends the reader of the instance (its long poll
  // too: the request is aborted with it).
  $effect(() => {
    untrack(() => void load());
    return () => {
      torndown = true;
      reader.destroy();
    };
  });
  // The header's refresh reads the page again, and follows again if stopped.
  onRefresh(() => {
    // Off an appliance nothing is read (the page is being sent away).
    if (page.data.user?.appliance) void reader.resume();
  });

  // -- lifecycle actions ----------------------------------------------------

  /** Run an action, then read the page again: what follows (a job, a scheduled
   *  reboot) is followed from the daemon's answer, like any other. */
  async function act(run: () => Promise<{ error?: unknown }>, done: string): Promise<boolean> {
    starting = true;
    const { error } = await run();
    if (error) toast.error(extractError(error));
    else toast.success(done);
    // Read again either way: a refusal is the daemon's state having moved (a
    // job or a reboot another client started), which the page must show. The
    // actions stay held until that reading has landed.
    await load(true);
    starting = false;
    return !error;
  }

  async function doRestart() {
    confirm = null;
    await act(
      () => adminApi.POST('/api/v1/admin/global/appliance/actions/restart', { body: { drain_secs: 30 } }),
      'Restart scheduled — the appliance will reboot shortly.',
    );
  }

  async function doShutdown() {
    confirm = null;
    await act(
      () => adminApi.POST('/api/v1/admin/global/appliance/actions/shutdown', { body: { drain_secs: 30 } }),
      'Power-off scheduled — the appliance will shut down shortly.',
    );
  }

  /** Read what going back would run before asking: the dialog names it, and
   *  the rollback confirms exactly that release. A refusal (going back is not
   *  safe) is the daemon's reason, shown as is. */
  async function askRollback() {
    const { data, error } = await adminApi.GET('/api/v1/admin/global/appliance/rollback');
    if (error || !data) {
      toast.error(error ? extractError(error) : 'Could not read the rollback plan.');
      return;
    }
    rollbackPlan = data;
    confirm = 'rollback';
  }

  async function doRollback() {
    confirm = null;
    const plan = rollbackPlan;
    if (!plan) return;
    await act(
      () => adminApi.POST('/api/v1/admin/global/appliance/actions/rollback', { body: { confirm: plan.to } }),
      `Rollback to ${release(plan.to)} started — the appliance reboots into it.`,
    );
  }

  // The release the upgrade dialog names, fixed when it opens: a refresh that
  // lands meanwhile must not change what the operator confirms.
  let upgradeTarget = $state<HostVersion | null>(null);
  function askUpgrade(kind: 'upgrade' | 'upgrade-restart') {
    upgradeTarget = updates?.target ?? null;
    if (upgradeTarget) confirm = kind;
  }

  /** `reboot` makes activation part of this operation: the daemon reboots once
   *  the new system is written, so the upgrade costs one outage instead of
   *  leaving the operator to come back for a second one. Writing the new system
   *  is non-disruptive either way. The upgrade confirms the release on screen:
   *  the daemon refuses if the channel offers another by now. */
  async function doUpgrade(reboot: boolean) {
    confirm = null;
    const target = upgradeTarget;
    if (!target) return;
    // A refusal may be the channel offering another release by now: the page
    // read that follows shows what it offers, so the next confirmation is of it.
    await act(
      () =>
        adminApi.POST('/api/v1/admin/global/appliance/actions/upgrade', {
          body: { confirm: target, reboot },
        }),
      `Upgrade to ${release(target)} started.`,
    );
  }

  async function checkUpdates() {
    starting = true;
    const { data, error } = await adminApi.POST('/api/v1/admin/global/appliance/actions/check-updates', {});
    starting = false;
    if (error || !data) {
      toast.error(error ? extractError(error) : 'Update check failed.');
      return;
    }
    // Numbered when it answers: it is fresher than any read started before.
    if (landed('updates', ++restIssued)) updates = data;
    toast.success(data.available ? `Update available: ${release(data.target)}` : 'You are on the latest version.');
  }

  // Coarse phase label derived from the daemon's log — a lightweight stepper
  // above the raw log so the operator sees where the upgrade is.
  // The log joined once per change, for the phase and the panel alike.
  const joinedLog = $derived(jobLog.join('\n'));
  const upgradePhase = $derived.by(() => {
    const joined = joinedLog;
    if (/passive slot/.test(joined)) return 'Writing the new system…';
    if (/^a backup first:/m.test(joined)) return 'Backing up…';
    return 'Starting…';
  });

  // The daemon runs one job at a time and refuses another, or any power action,
  // while one runs or a reboot is scheduled; the buttons say so before it has to.
  const busy = $derived(starting || job?.state === 'running' || !!status?.reboot_pending || fs.rebootComing || offline);
  // An upgrade is written and waits for the restart that runs it.
  const upgradeWritten = $derived(job?.kind === 'upgrade' && job.state === 'done');
  // The Software card shows the system's own jobs; a backup and its test show
  // on the Backup tab.
  const systemJob = $derived(
    job && job.kind !== 'backup' && job.kind !== 'backup-verify' && job.state !== 'idle' ? job : null,
  );
  const testingBackup = $derived(job?.kind === 'backup-verify' && job.state === 'running');

  // The daemon keeps the saved keys when sent none, so an empty list would save
  // without the change it shows; at least one key is required.
  const bkRecipientsMissing = $derived(backupBody().recipients.length === 0);

  // -- backup ---------------------------------------------------------------

  function startEditBackup() {
    bkDest = backupCfg?.destination ?? '';
    bkRecipients = (backupCfg?.recipients ?? []).join('\n');
    bkProfile = backupCfg?.profile ?? '';
    bkRetention = backupCfg?.retention_days ?? 30;
    bkSchedule = backupCfg?.schedule ?? '';
    editingBackup = true;
  }

  function backupBody() {
    return {
      destination: bkDest.trim(),
      recipients: bkRecipients
        .split(/[\s,]+/)
        .map((r) => r.trim())
        .filter((r) => r.length > 0),
      profile: bkProfile,
      retention_days: bkRetention,
      schedule: bkSchedule.trim(),
    };
  }

  async function saveBackup() {
    savingBackup = true;
    const { error } = await adminApi.PUT('/api/v1/admin/global/appliance/backup/config', {
      body: backupBody(),
    });
    savingBackup = false;
    if (error) {
      toast.error(extractError(error));
      // The operator may have locked the settings since the page loaded: show it.
      if (extractErrorCode(error) === 'appliance_operator_only') await load(true);
      return;
    }
    toast.success('Backup configuration saved.');
    editingBackup = false;
    await load(true);
  }

  /** Tests the settings in the form, or with `saved` the saved ones (the only
   *  test the appliance runs while the operator locked them); nothing is saved.
   *  The test is a job: its verdict arrives through the journal. */
  async function testBackup(saved = false) {
    await act(
      () => adminApi.POST('/api/v1/admin/global/appliance/actions/backup-test', { body: saved ? undefined : backupBody() }),
      'Testing the destination…',
    );
  }

  async function runBackup() {
    await act(
      () => adminApi.POST('/api/v1/admin/global/appliance/actions/backup-run', { body: {} }),
      'Backup started.',
    );
  }
</script>

<TabbedPage
  title="Appliance"
  subtitle="Manage and back up this VM appliance."
  tabs={[
    { id: 'management', label: 'Management' },
    { id: 'backup', label: 'Backup' },
  ]}
  activeTab={tab.current}
  onTabChange={(t: ApplianceTab) => (tab.current = t)}
>
  {#snippet children(active: ApplianceTab)}
    <!-- What the page knows of the appliance, from the follower's one state. -->
    {#if watch.kind === 'down'}
      <!-- A restart the journal told of, or the status read last: never "lost contact". -->
      {#if fs.rebootComing || status?.reboot_pending || status?.on_trial}
        <Callout severity="info" title="Restarting">
          The appliance is restarting (or powering off) — as scheduled, or because the health
          check is taking it back to the previous version. The page reconnects on its own when
          it is back.
        </Callout>
      {:else}
        <Callout severity="warning" title="Lost contact with the appliance">
          No reboot was scheduled, so this is not expected. Still retrying.
          <span class="block mt-1 font-mono text-xs">{watch.reason}</span>
        </Callout>
      {/if}
    {:else if watch.kind === 'faulty'}
      <Callout severity="warning" title="The appliance's host service answers with an error">
        Its actions wait until it answers properly. Still asking.
        <span class="block mt-1 font-mono text-xs">{watch.reason}</span>
      </Callout>
    {:else if watch.kind === 'journal'}
      <Callout severity="warning" title="The appliance's event journal does not answer">
        {watch.reason.replace(/[.\s]+$/, '')}. Jobs, restarts and health checks are not shown as they happen; the actions
        still work. Still asking.
      </Callout>
    {:else if watch.kind === 'throttled'}
      <Callout severity="info" title="Reading the appliance more slowly">
        The console is limiting how often this page reads; it asks again shortly. {watch.reason}
      </Callout>
    {:else if watch.kind === 'stopped'}
      <Callout severity="warning" title="Not following the appliance">
        The page stopped reading what happens on the appliance ({watch.reason}): jobs, restarts and
        health checks are not shown as they happen. Refresh to follow again.
      </Callout>
    {/if}

    {#if loading}
      <Skeleton />
    {:else if active === 'management'}
      <!-- Software / update -->
      <section class="rounded-xl border border-(--border) bg-(--bg-secondary) p-5 space-y-4">
        <h2 class="text-sm font-semibold text-(--text-primary)">Software update</h2>
        <div class="text-sm space-y-1">
          <div class="flex justify-between"><span class="text-(--text-secondary)">Running</span><span class="font-mono">{release(status?.os)}{status?.fallback ? ' (fallback system)' : ''}</span></div>
          {#if status?.channel}
            <div class="flex justify-between"><span class="text-(--text-secondary)">Channel</span><span class="font-mono">{status.channel}</span></div>
          {/if}
          <div class="flex justify-between">
            <span class="text-(--text-secondary)">Available</span>
            <span class="font-mono {updates?.available ? 'text-(--accent)' : ''}">
              {release(updates?.target ?? status?.os)}
              {#if updates?.available}▲{/if}
            </span>
          </div>
        </div>

        <!-- The boot's state, rendered from the status alone so that a reload,
             a second tab or the two-step restart shows it the same way. -->
        {#if status?.install_failed}
          <Callout severity="error" title="The install did not finish">
            {status.install_failed}
          </Callout>
        {:else if status?.installing}
          <Callout severity="info" title="Finishing the install">
            The appliance is bringing its services up on {release(status.os)}.
          </Callout>
        {/if}
        {#if status?.on_trial}
          <Callout severity="info" title={`${release(status.os)} is on trial`}>
            The health check is judging the new version. If it comes up healthy it is kept;
            if not, the appliance restarts on the previous version.
          </Callout>
        {/if}
        <!-- The daemon reports the last failed boot ever kept. It is a warning only
             while that release runs (the gate kept it); otherwise it is history,
             dated, and never offered as the reason for a fallback — a rollback
             boots the fallback system the same way. -->
        {#if status?.failed_boot && sameVersion(status.failed_boot.release, status.os)}
          <Callout severity="warning" title={`${release(status.failed_boot.release)} did not come up healthy`}>
            {status.failed_boot.reason} ({formatDateTime(status.failed_boot.at)}).
            {#if status.failed_boot.kept}
              It was kept running because going back was refused: {status.failed_boot.kept}
            {/if}
          </Callout>
        {:else if status?.failed_boot}
          <p class="text-xs text-(--text-secondary)">
            Last failed boot: {release(status.failed_boot.release)}, {formatDateTime(status.failed_boot.at)} —
            {status.failed_boot.reason}
          </p>
        {/if}
        {#if updates?.left_by_rollback}
          <Callout severity="info" title={`${release(updates.target)} was rolled back`}>
            The appliance went back from this release and does not upgrade to it again.
          </Callout>
        {/if}

        {#if updates?.available && updates.changelog}
          <details class="text-sm" open>
            <summary class="cursor-pointer text-(--text-secondary) mb-2">What's new in {release(updates.target)}</summary>
            <div class="rounded-lg border border-(--border) bg-(--bg-primary) p-4 max-h-96 overflow-auto text-sm text-(--text-secondary) leading-relaxed">
              {@html renderMarkdown(updates.changelog)}
            </div>
          </details>
        {/if}

        <div class="flex flex-wrap gap-2">
          <button
            onclick={() => askUpgrade('upgrade')}
            disabled={!updates?.available || busy || upgradeWritten}
            class="px-3 py-1.5 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-xs font-medium disabled:opacity-50">
            {job?.kind === 'upgrade' && job.state === 'running' ? 'Upgrading…' : 'Upgrade'}
          </button>
          <button
            onclick={() => askUpgrade('upgrade-restart')}
            disabled={!updates?.available || busy || upgradeWritten}
            class="px-3 py-1.5 bg-(--bg-primary) border border-(--border) hover:border-(--accent) rounded-lg text-(--text-primary) text-xs font-medium disabled:opacity-50">
            Upgrade &amp; restart
          </button>
          <button
            onclick={() => void askRollback()}
            disabled={busy}
            class="px-3 py-1.5 bg-(--bg-primary) border border-(--border) hover:border-(--accent) rounded-lg text-(--text-primary) text-xs font-medium disabled:opacity-50">
            Rollback
          </button>
          <button
            onclick={checkUpdates}
            disabled={busy}
            class="disabled:opacity-50 px-3 py-1.5 bg-(--bg-primary) border border-(--border) hover:border-(--accent) rounded-lg text-(--text-primary) text-xs font-medium">
            Check now
          </button>
        </div>

        {#if job?.kind === 'backup' && job.state === 'running'}
          <p class="text-xs text-(--text-secondary)">
            A backup is running; the actions below wait for it to finish.
          </p>
        {/if}
        {#if systemJob}
          {#if systemJob.state === 'running'}
            <div class="rounded-lg bg-(--bg-primary) border border-(--border) p-3">
              <div class="text-xs text-(--text-secondary) mb-1">
                {#if systemJob.kind === 'upgrade'}
                  Upgrade in progress — {upgradePhase} · the gateway keeps serving
                {:else}
                  {jobName(systemJob.kind)} in progress
                {/if}
              </div>
              {#if jobLog.length}
                <pre class="whitespace-pre-wrap font-mono text-xs max-h-64 overflow-auto text-(--text-secondary)">{joinedLog}</pre>
              {/if}
            </div>
          {:else if systemJob.state === 'failed'}
            <Callout severity="error" title={`${jobName(systemJob.kind)} failed`}>
              {systemJob.error || jobLog.at(-1) || 'It did not complete.'}
            </Callout>
          {:else if systemJob.kind === 'upgrade' && (status?.reboot_pending || fs.rebootComing)}
            <Callout severity="success" title="Update written — restarting now">
              The new version is written to the standby system and the appliance is restarting to
              boot into it. This is the only interruption; the console reconnects on its own.
            </Callout>
          {:else if systemJob.kind === 'upgrade'}
            <Callout severity="success" title="Update written — restart to finish upgrade">
              The new version is written to the standby system and service was never interrupted.
              Restart the appliance to boot into it — a short outage.
              <div class="mt-2">
                <button
                  onclick={() => (confirm = 'restart')}
                  disabled={busy}
                  class="px-3 py-1.5 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-xs font-medium disabled:opacity-50">
                  Restart to finish upgrade
                </button>
              </div>
            </Callout>
          {:else if systemJob.kind === 'rollback' && (status?.reboot_pending || fs.rebootComing)}
            <Callout severity="success" title="Rollback written — restarting into it">
              The appliance is restarting into the previous version; the console reconnects on its own.
            </Callout>
          {:else if systemJob.kind === 'rollback'}
            <Callout severity="warning" title="Rollback written — restart to finish it">
              The previous version is set to run, but the restart into it did not happen. Restart the
              appliance to run it.
              <div class="mt-2">
                <button
                  onclick={() => (confirm = 'restart')}
                  disabled={busy}
                  class="px-3 py-1.5 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-xs font-medium disabled:opacity-50">
                  Restart to finish rollback
                </button>
              </div>
            </Callout>
          {/if}
        {/if}
      </section>

      <!-- Network -->
      <section class="rounded-xl border border-(--border) bg-(--bg-secondary) p-5 space-y-3">
        <h2 class="text-sm font-semibold text-(--text-primary)">Network</h2>

        {#if netPending}
          <Callout severity="warning" title="Confirm these settings to keep them">
            The appliance reverts to its previous network settings in
            <span class="font-mono">{netCountdown}s</span> unless you confirm. Check that you can
            still reach the appliance — at its new address, if you changed it — then confirm. If you
            cannot, do nothing: the previous settings come back on their own.
            <div class="flex flex-wrap gap-2 pt-2">
              <button
                onclick={confirmNetwork}
                class="px-3 py-1.5 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-xs font-medium">
                Keep these settings
              </button>
              <button
                onclick={revertNetwork}
                class="px-3 py-1.5 bg-(--bg-primary) border border-(--border) hover:border-(--accent) rounded-lg text-(--text-primary) text-xs font-medium">
                Revert now
              </button>
            </div>
          </Callout>
        {/if}

        {#if !editingNetwork}
          <div class="text-sm space-y-1">
            <div class="flex justify-between">
              <span class="text-(--text-secondary)">Interface</span>
              <span class="font-mono">{network?.live.interface ?? '—'}</span>
            </div>
            <div class="flex justify-between">
              <span class="text-(--text-secondary)">Address</span>
              <span class="font-mono">{network?.live.addresses?.length ? network.live.addresses.join(', ') : '—'}</span>
            </div>
            <div class="flex justify-between">
              <span class="text-(--text-secondary)">Gateway</span>
              <span class="font-mono">{network?.live.gateway ?? '—'}</span>
            </div>
            {#if network?.live.gateways6?.length}
              <div class="flex justify-between">
                <span class="text-(--text-secondary)">IPv6 gateway</span>
                <span class="font-mono">{network.live.gateways6.join(', ')}</span>
              </div>
            {/if}
            <div class="flex justify-between">
              <span class="text-(--text-secondary)">DNS</span>
              <span class="font-mono">{network?.live.dns?.length ? network.live.dns.join(', ') : '—'}</span>
            </div>
            <div class="flex justify-between">
              <span class="text-(--text-secondary)">Set by</span>
              <span>
                {#if network?.source === 'override'}
                  this page (overrides the install settings)
                {:else if network?.source === 'install'}
                  install-time settings
                {:else}
                  DHCP lease
                {/if}
              </span>
            </div>
          </div>
          <div class="flex flex-wrap items-center gap-2 pt-1">
            <button
              onclick={startEditNetwork}
              disabled={!network || !!netPending}
              class="px-3 py-1.5 bg-(--bg-primary) border border-(--border) hover:border-(--accent) rounded-lg text-(--text-primary) text-xs font-medium disabled:opacity-50">
              Edit…
            </button>
            {#if network?.override_config}
              <button
                onclick={() => (confirm = 'network-reset')}
                disabled={!!netPending}
                class="px-3 py-1.5 bg-(--bg-primary) border border-(--border) hover:border-(--accent) rounded-lg text-(--text-primary) text-xs font-medium disabled:opacity-50">
                Reset to install settings
              </button>
            {/if}
            <span class="text-[11px] text-(--text-secondary)">
              Changing the address moves the appliance — update the DNS records for its hostnames to match.
            </span>
          </div>
        {:else}
          <div class="space-y-3">
            <Callout severity="info" title="Changing the address will interrupt this session">
              The appliance keeps its current settings unless you confirm the new ones within the
              revert window, so a wrong address or gateway cannot lock you out. A DNS-only change
              cannot interrupt anything and applies straight away.
            </Callout>
            <div class="grid grid-cols-2 gap-2">
              <label class="block text-xs text-(--text-secondary)">Addressing
                <SelectInput bind:value={netMode}>
                  <option value="dhcp">Automatic (DHCP)</option>
                  <option value="static">Static</option>
                </SelectInput>
              </label>
              <label class="block text-xs text-(--text-secondary)">Revert if unconfirmed (seconds, 30–3600)
                <NumberInput bind:value={netRevertSecs} />
              </label>
            </div>
            {#if netMode === 'static'}
              <div class="grid grid-cols-2 gap-2">
                <label class="block text-xs text-(--text-secondary)">IP address with its prefix (24 = 255.255.255.0)
                  <TextInput bind:value={netAddress} mono placeholder="192.168.1.50/24" />
                </label>
                <label class="block text-xs text-(--text-secondary)">Gateway
                  <TextInput bind:value={netGateway} mono placeholder="192.168.1.1" />
                </label>
              </div>
            {/if}
            <ToggleSetting
              label="IPv6"
              description="Addresses from the network's router advertisements (and DHCPv6 with automatic addressing). Off, the appliance has no IPv6 at all."
              bind:value={netIpv6} />
            {#if netIpv6}
              <div class="grid grid-cols-2 gap-2">
                <label class="block text-xs text-(--text-secondary)">Static IPv6 address with its prefix (optional)
                  <TextInput bind:value={netAddress6} mono placeholder="2001:db8::50/64" />
                </label>
                {#if netAddress6.trim()}
                  <label class="block text-xs text-(--text-secondary)">Its IPv6 gateway (optional)
                    <TextInput bind:value={netGateway6} mono placeholder="fe80::1" />
                  </label>
                {/if}
              </div>
            {/if}
            <label class="block text-xs text-(--text-secondary)">
              DNS servers (comma-separated; with DHCP, empty uses the lease's)
              <TextInput bind:value={netDns} mono placeholder="192.168.1.1, 1.1.1.1" />
            </label>
            <div class="flex flex-wrap gap-2 pt-1">
              <button
                onclick={saveNetwork}
                disabled={savingNetwork}
                class="px-3 py-1.5 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-xs font-medium disabled:opacity-50">
                {savingNetwork ? 'Applying…' : 'Apply'}
              </button>
              <button
                onclick={() => (editingNetwork = false)}
                class="px-3 py-1.5 text-(--text-secondary) text-xs font-medium">
                Cancel
              </button>
            </div>
          </div>
        {/if}
      </section>

      <!-- Power -->
      <section class="rounded-xl border border-(--border) bg-(--bg-secondary) p-5 space-y-3">
        <h2 class="text-sm font-semibold text-(--text-primary)">Power</h2>
        <div class="flex flex-wrap items-center gap-2">
          <button
            onclick={() => (confirm = 'restart')}
            disabled={busy}
            class="px-3 py-1.5 bg-(--bg-primary) border border-(--border) hover:border-(--accent) rounded-lg text-(--text-primary) text-xs font-medium disabled:opacity-50">
            Restart
          </button>
          <button
            onclick={() => (confirm = 'shutdown')}
            disabled={busy}
            class="disabled:opacity-50 px-3 py-1.5 bg-(--bg-primary) border border-(--error) text-(--error) hover:bg-(--error) hover:text-(--error-fg) rounded-lg text-xs font-medium">
            Shut down
          </button>
          <span class="text-[11px] text-(--text-secondary)">
            Both drain in-flight work first. Shutting down powers the VM off until you start it again from your hypervisor.
          </span>
        </div>
      </section>
    {:else}
      <!-- Backup -->
      <section class="rounded-xl border border-(--border) bg-(--bg-secondary) p-5 space-y-3">
        <h2 class="text-sm font-semibold text-(--text-primary)">Backup</h2>
        {#if backupCfg?.locked}
          <Callout severity="info" title="Locked by the operator">
            The operator keeps these settings over SSH (<span class="font-mono">ssai-stow backup config --unlock</span> gives them back): nothing is saved here, and Test tries the saved settings.{#if backupCfg.configured} You can still run a backup.{/if}
          </Callout>
        {/if}
        {#if !editingBackup}
          {#if backupCfg && !backupCfg.rclone_config_set && !backupCfg.locked}
            <Callout severity="warning" title="No destination is set up">
              The operator sets the first destination and its credentials over SSH
              (<span class="font-mono">ssai-stow backup config --destination … --rclone-config … --recipient …</span>);
              this tab then changes the rest of the settings.
            </Callout>
          {/if}
          {#if backupCfg?.rclone_config_from === 'unknown'}
            <Callout severity="warning" title="Backups do not run with this rclone config">
              It is not known to have been saved by the operator (it was saved before the appliance kept that, perhaps from
              this console), so nothing runs with it until the operator saves it again over SSH
              (<span class="font-mono">ssai-stow backup config --rclone-config …</span>).
            </Callout>
          {/if}
          <div class="text-sm space-y-1">
            <div class="flex justify-between"><span class="text-(--text-secondary)">Destination</span><span class="font-mono">{backupCfg?.configured ? backupCfg.destination : 'not set'}</span></div>
            <div class="flex justify-between"><span class="text-(--text-secondary)">Schedule</span><span class="font-mono">{backupCfg?.schedule ?? '—'}</span></div>
            <div class="flex justify-between"><span class="text-(--text-secondary)">Profile / retention</span><span class="font-mono">{backupCfg?.profile ?? '—'} / {backupCfg?.retention_days ? `${backupCfg.retention_days}d` : 'keep all'}</span></div>
            <div class="flex justify-between"><span class="text-(--text-secondary)">Credentials</span><span>{backupCfg?.rclone_config_set ? (backupCfg.rclone_config_from === 'unknown' ? 'not known to be the operator’s — not run' : 'configured') : 'not set'}</span></div>
            <div class="flex justify-between"><span class="text-(--text-secondary)">Encrypted to</span><span class="font-mono">{backupCfg?.recipients?.length ? `${backupCfg.recipients.length} key${backupCfg.recipients.length > 1 ? 's' : ''}` : 'no key'}</span></div>
            {#if backupStatus}
              <div class="flex justify-between"><span class="text-(--text-secondary)">Next run</span><span>{backupStatus.running ? 'running now' : backupCfg?.rclone_config_from === 'unknown' ? 'none: the config is not run' : (backupStatus.next ?? '—')}</span></div>
              {#if backupStatus.last}
                <div class="flex justify-between">
                  <span class="text-(--text-secondary)">Last run</span>
                  <span>
                    {backupStatus.last.error ? 'failed' : 'succeeded'} · {formatDateTime(backupStatus.last.finished)}
                    {#if !backupStatus.last.error && backupStatus.last.bytes} · {formatBytes(backupStatus.last.bytes)}{/if}
                  </span>
                </div>
                {#if backupStatus.last.error}
                  <Callout severity="error" title="The last backup failed">{backupStatus.last.error}</Callout>
                {:else if backupStatus.last.prune_error}
                  <Callout severity="warning" title="Older backups were not pruned">{backupStatus.last.prune_error}</Callout>
                {/if}
              {/if}
            {/if}
          </div>
          <div class="flex flex-wrap gap-2 pt-1">
            <button onclick={startEditBackup} disabled={backupCfg?.locked || !backupCfg?.rclone_config_set} class="px-3 py-1.5 bg-(--bg-primary) border border-(--border) hover:border-(--accent) rounded-lg text-(--text-primary) text-xs font-medium disabled:opacity-50">Edit…</button>
            <button onclick={() => testBackup(true)} disabled={testingBackup || busy || !backupCfg?.configured || !backupCfg?.rclone_config_set || backupCfg?.rclone_config_from === 'unknown'} class="px-3 py-1.5 bg-(--bg-primary) border border-(--border) hover:border-(--accent) rounded-lg text-(--text-primary) text-xs font-medium disabled:opacity-50">{testingBackup ? 'Testing…' : 'Test'}</button>
            <button onclick={runBackup} disabled={!backupCfg?.configured || backupCfg?.rclone_config_from === 'unknown' || backupStatus?.running || busy} class="px-3 py-1.5 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-xs font-medium disabled:opacity-50">Run now</button>
          </div>
        {:else}
          <div class="space-y-3">
            <Callout severity="info" title="The destination's credentials are the operator's">
              Backups upload through <span class="font-mono">rclone</span>, whose remotes and credentials the
              operator sets over SSH (<span class="font-mono">ssai-stow backup config --rclone-config</span>): the
              appliance runs rclone as root, and its settings can name programs it runs. Here the
              <strong>Destination</strong> can move to another remote the operator defined
              (<span class="font-mono">remote:bucket/path</span>, the part before the colon a remote's name).
            </Callout>
            <label class="block text-xs text-(--text-secondary)">Destination (<span class="font-mono">remote:bucket/path</span>)
              <TextInput bind:value={bkDest} mono placeholder="backup:streamscope-backups/prod" />
            </label>
            <label class="block text-xs text-(--text-secondary)">Encrypt to (age public keys, one per line — any one's private key decrypts a backup; keep it off the appliance)
              <TextArea bind:value={bkRecipients} rows={2} placeholder="age1…" />
            </label>
            <div class="grid grid-cols-3 gap-2">
              <label class="block text-xs text-(--text-secondary)">Profile
                <SelectInput bind:value={bkProfile}>
                  {#each backupCfg?.profiles ?? [] as p, i (i)}
                    <option value={p}>{p}</option>
                  {/each}
                </SelectInput>
              </label>
              <label class="block text-xs text-(--text-secondary)">Retention (days, 0 keeps all)
                <NumberInput bind:value={bkRetention} />
              </label>
              <label class="block text-xs text-(--text-secondary)">Schedule (systemd calendar)
                <TextInput bind:value={bkSchedule} mono placeholder="*-*-* 03:00:00" />
              </label>
            </div>
            <div class="flex flex-wrap gap-2 pt-1">
              <button onclick={saveBackup} disabled={savingBackup || bkRecipientsMissing || backupCfg?.locked || !backupCfg?.rclone_config_set} class="px-3 py-1.5 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-xs font-medium disabled:opacity-50">{savingBackup ? 'Saving…' : 'Save'}</button>
              <button onclick={() => testBackup()} disabled={testingBackup || bkRecipientsMissing || busy || backupCfg?.locked || !backupCfg?.rclone_config_set || backupCfg?.rclone_config_from === 'unknown'} class="px-3 py-1.5 bg-(--bg-primary) border border-(--border) hover:border-(--accent) rounded-lg text-(--text-primary) text-xs font-medium disabled:opacity-50">{testingBackup ? 'Testing…' : 'Test'}</button>
              <button onclick={() => (editingBackup = false)} class="px-3 py-1.5 text-(--text-secondary) text-xs font-medium">Cancel</button>
            </div>
          </div>
        {/if}
      </section>
    {/if}
  {/snippet}
</TabbedPage>

<ConfirmDialog
  open={confirm === 'restart'}
  title="Restart appliance?"
  message="The appliance will drain in-flight work and reboot. It will be briefly unavailable."
  confirmLabel="Restart"
  onconfirm={doRestart}
  oncancel={() => (confirm = null)} />

<ConfirmDialog
  open={confirm === 'shutdown'}
  title="Shut down appliance?"
  message="The appliance will power OFF and needs to be powered back on from your hypervisor — there is no web way back."
  confirmLabel="Shut down"
  destructive
  requireText="SHUTDOWN"
  onconfirm={doShutdown}
  oncancel={() => (confirm = null)} />

<ConfirmDialog
  open={confirm === 'rollback'}
  title="Roll back to previous version?"
  message={`The appliance goes back from ${release(rollbackPlan?.from)} to ${release(rollbackPlan?.to)} and reboots into it.`}
  confirmLabel="Roll back"
  destructive
  onconfirm={doRollback}
  oncancel={() => (confirm = null)} />

<ConfirmDialog
  open={confirm === 'network-reset'}
  title="Reset to install settings?"
  message="The appliance drops the network settings made here and goes back to the ones supplied when it was installed. If those differ, its address changes — so this is confirmed the same way, and comes back on its own if you cannot reach the appliance afterwards."
  confirmLabel="Reset"
  destructive
  onconfirm={resetNetwork}
  oncancel={() => (confirm = null)} />

<ConfirmDialog
  open={confirm === 'upgrade'}
  title="Upgrade appliance?"
  message={`Upgrade to ${release(upgradeTarget)}? A backup runs first when one is configured, then the new version is downloaded and written without interrupting service. It runs from the next restart.`}
  confirmLabel="Upgrade"
  onconfirm={() => void doUpgrade(false)}
  oncancel={() => (confirm = null)} />

<ConfirmDialog
  open={confirm === 'upgrade-restart'}
  title="Upgrade and restart appliance?"
  message={`Upgrade to ${release(upgradeTarget)}? A backup runs first when one is configured, then the new version is downloaded and written without interrupting service — and the appliance restarts on its own to run it, briefly interrupting the gateway and this console.`}
  confirmLabel="Upgrade & restart"
  onconfirm={() => void doUpgrade(true)}
  oncancel={() => (confirm = null)} />
