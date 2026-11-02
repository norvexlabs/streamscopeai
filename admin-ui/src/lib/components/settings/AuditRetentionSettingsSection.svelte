<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import { extractSettings, extractError, updateSettings } from '#lib/api-helpers.js';
  import { formatBytes } from '#lib/formatters.js';
  import type { DbStatsResponse } from '#lib/api-types.js';
  import { onMount } from 'svelte';

  let contentLoggingEnabled = $state(false);
  let contentLoggingToggling = $state(false);
  let auditEnabled = $state(true);
  let retentionDays = $state(30);
  let retentionSaved = $state(false);
  let saving = $state(false);
  let purging = $state(false);
  let purgeResult = $state('');
  let dbStats = $state<DbStatsResponse | null>(null);
  let dbStatsLoading = $state(false);
  let wiping = $state(false);
  let wipeResult = $state('');
  let configError = $state('');

  let mediaStorageEnabled = $state(false);
  let mediaBlobMaxSizeMb = $state(10);

  const TABLE_LABELS: Record<string, string> = {
    audit_log: 'Audit Log',
    conversation_turns: 'Conversation Turns',
    conversation_messages: 'Messages Store',
    tool_definitions: 'Tool Definitions',
    sessions: 'Sessions',
    generation_records: 'Generations',
  };

  function formatNumber(n: number): string {
    return n.toLocaleString();
  }

  async function loadConfig() {
    const { data, error: err } = await adminApi.GET('/api/v1/admin/settings');
    if (err) {
      console.warn('Failed to load settings:', err);
      return;
    }
    if (data) {
      const s = extractSettings(data);
      auditEnabled = s.audit_enabled ?? true;
      retentionDays = s.retention_days ?? 30;
      contentLoggingEnabled = s.content_logging_enabled ?? false;
      mediaStorageEnabled = s.media_blob_storage_enabled ?? false;
      mediaBlobMaxSizeMb = s.media_blob_max_size_mb ?? 10;
    }
  }

  async function loadDbStats() {
    dbStatsLoading = true;
    const { data, error: err } = await adminApi.GET('/api/v1/admin/settings/db-stats');
    if (err) {
      console.warn('Failed to load DB stats:', err);
    } else if (data) {
      dbStats = data;
    }
    dbStatsLoading = false;
  }

  async function toggleAuditEnabled() {
    auditEnabled = !auditEnabled;
    const { error: err } = await updateSettings({ audit_enabled: auditEnabled });
    if (err) {
      configError = 'Failed to save audit setting';
      setTimeout(() => (configError = ''), 3000);
      auditEnabled = !auditEnabled;
    }
  }

  async function toggleContentLogging() {
    contentLoggingToggling = true;
    const newValue = !contentLoggingEnabled;
    const { error: err } = await updateSettings({ content_logging_enabled: newValue });
    if (err) {
      configError = 'Failed to toggle content logging';
      setTimeout(() => (configError = ''), 3000);
    } else {
      contentLoggingEnabled = newValue;
    }
    contentLoggingToggling = false;
  }

  async function toggleMediaStorage() {
    if (!contentLoggingEnabled || !auditEnabled) return;
    const newVal = !mediaStorageEnabled;
    const { error: err } = await updateSettings({ media_blob_storage_enabled: newVal });
    if (!err) mediaStorageEnabled = newVal;
  }

  async function saveMediaBlobMaxSize() {
    await updateSettings({ media_blob_max_size_mb: mediaBlobMaxSizeMb });
  }

  async function saveRetention() {
    saving = true;
    const { error: err } = await updateSettings({
      retention_days: retentionDays,
    });
    if (err) {
      configError = extractError(err, 'Failed to save retention settings');
      setTimeout(() => (configError = ''), 5000);
    } else {
      retentionSaved = true;
      setTimeout(() => (retentionSaved = false), 2000);
    }
    saving = false;
  }

  async function runPurge() {
    purging = true;
    purgeResult = '';
    const { data, error: err } = await adminApi.POST('/api/v1/admin/maintenance/purge-audit', {});
    if (err) {
      purgeResult = `Purge failed: ${extractError(err, 'Unknown error')}`;
      setTimeout(() => (purgeResult = ''), 5000);
    } else if (data) {
      const result = data as { summary: { sessions_deleted: number; audit_deleted: number; turns_deleted: number; messages_deleted: number } };
      const s = result.summary;
      const total = (s.sessions_deleted || 0) + (s.audit_deleted || 0) + (s.turns_deleted || 0) + (s.messages_deleted || 0);
      purgeResult = total > 0
        ? `Purged ${total} records (${s.audit_deleted} audit, ${s.turns_deleted} turns, ${s.sessions_deleted} sessions, ${s.messages_deleted} messages)`
        : 'Nothing to purge';
      setTimeout(() => (purgeResult = ''), 8000);
      loadDbStats();
    }
    purging = false;
  }

  async function wipeAll() {
    if (!confirm('Wipe ALL audit logs, sessions, and conversation data? This cannot be undone. Users, API keys, upstreams, and catalog will be preserved.')) return;
    wiping = true;
    wipeResult = '';
    const { error: wipeErr } = await adminApi.POST('/api/v1/admin/maintenance/wipe-sessions', {});
    if (wipeErr) {
      wipeResult = `Wipe failed: ${extractError(wipeErr, 'Unknown error')}`;
      setTimeout(() => (wipeResult = ''), 5000);
    } else {
      wipeResult = 'All audit and session data wiped';
      setTimeout(() => (wipeResult = ''), 5000);
      loadDbStats();
    }
    wiping = false;
  }


  onMount(() => {
    loadConfig();
    loadDbStats();
  });
</script>

<div class="space-y-8">
  <section>
    <h3 class="text-lg font-semibold text-(--text-primary) mb-4">Configuration</h3>

    {#if configError}
      <div class="mb-4 px-4 py-2 bg-(--error-bg) border border-(--error)/30 rounded-lg text-sm text-(--error)">
        {configError}
      </div>
    {/if}

    <div class="bg-(--bg-card) rounded-xl border border-(--border) mb-4 overflow-hidden">
      <div class="flex items-center justify-between p-5 border-b border-(--border)">
        <div>
          <p class="font-medium text-(--text-primary)">Audit Logging</p>
          <p class="text-xs text-(--text-secondary) mt-0.5">Record metadata for every request (model, tokens, cost, latency)</p>
        </div>
        <label class="relative inline-flex items-center cursor-pointer shrink-0 ml-4">
          <input type="checkbox" checked={auditEnabled} onchange={toggleAuditEnabled} class="sr-only peer" />
          <div class="w-11 h-6 bg-(--border) peer-focus:outline-hidden rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-0.5 after:inset-s-0.5 after:bg-white after:ring-1 after:ring-(--bg-primary)/60 after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-(--success)"></div>
        </label>
      </div>

      <div class="flex items-center justify-between p-5 pl-10 border-b border-(--border) {auditEnabled ? '' : 'opacity-40'}">
        <div>
          <p class="font-medium text-(--text-primary)">Content Logging</p>
          <p class="text-xs text-(--text-secondary) mt-0.5">Store conversation messages, system prompts, and responses for session replay</p>
        </div>
        <button
          onclick={toggleContentLogging}
          disabled={contentLoggingToggling || !auditEnabled}
          aria-label={contentLoggingEnabled ? 'Disable content logging' : 'Enable content logging'}
          class="relative inline-flex h-6 w-11 items-center rounded-full transition-colors shrink-0 ml-4 {contentLoggingEnabled && auditEnabled ? 'bg-(--success)' : 'bg-(--border)'}"
        >
          <span class="inline-block h-5 w-5 transform rounded-full bg-white ring-1 ring-(--bg-primary)/60 transition-transform {contentLoggingEnabled && auditEnabled ? 'translate-x-5' : 'translate-x-0.5'}"></span>
        </button>
      </div>

      <div class="p-5 pl-16 {contentLoggingEnabled && auditEnabled ? '' : 'opacity-40'}">
        <div class="flex items-center justify-between">
          <div>
            <p class="font-medium text-(--text-primary)">Store Media Blobs</p>
            <p class="text-xs text-(--text-secondary) mt-0.5">Extract images, audio, and documents into content-addressed blob storage</p>
          </div>
          <button
            onclick={toggleMediaStorage}
            disabled={!contentLoggingEnabled || !auditEnabled}
            aria-label={mediaStorageEnabled ? 'Disable media blob storage' : 'Enable media blob storage'}
            class="relative inline-flex h-6 w-11 items-center rounded-full transition-colors shrink-0 ml-4 {mediaStorageEnabled && contentLoggingEnabled && auditEnabled ? 'bg-(--success)' : 'bg-(--border)'} {contentLoggingEnabled && auditEnabled ? 'cursor-pointer' : 'cursor-not-allowed'}"
          >
            <span class="inline-block h-5 w-5 transform rounded-full bg-white ring-1 ring-(--bg-primary)/60 transition-transform {mediaStorageEnabled && contentLoggingEnabled && auditEnabled ? 'translate-x-5' : 'translate-x-0.5'}"></span>
          </button>
        </div>
        {#if mediaStorageEnabled && contentLoggingEnabled && auditEnabled}
          <div class="mt-3 flex items-center gap-3">
            <span class="text-xs text-(--text-secondary)">Max blob size</span>
            <input
              type="number" min="1" max="100"
              bind:value={mediaBlobMaxSizeMb}
              onchange={saveMediaBlobMaxSize}
              class="w-20 px-3 py-1.5 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm font-mono text-right"
            />
            <span class="text-xs text-(--text-secondary)">MB</span>
          </div>
        {/if}
      </div>
    </div>

    <div class="bg-(--bg-card) rounded-xl p-6 border border-(--border) mb-4">
      <div class="flex items-center justify-between mb-3">
        <div>
          <p class="font-medium text-(--text-primary)">Retention Policy</p>
          <p class="text-xs text-(--text-secondary) mt-0.5">Audit rows older than the retention period are purged every 6 hours. Media blobs follow their referencing audit rows — they are removed once no row points at them.</p>
        </div>
      </div>
      <div class="flex items-center justify-between bg-(--bg-primary) rounded-lg p-3 mb-4">
        <span class="text-xs text-(--text-secondary)">Audit, sessions, conversations, media</span>
        <div class="flex items-center gap-2">
          <input bind:value={retentionDays} type="number" min="1" max="365"
            class="w-20 px-3 py-1.5 bg-(--bg-card) border border-(--border) rounded-lg text-(--text-primary) text-sm text-right focus:outline-hidden focus:border-(--accent) transition-colors" />
          <span class="text-xs text-(--text-secondary)">days</span>
        </div>
      </div>
      <div class="flex flex-wrap items-center gap-3">
        <button
          onclick={saveRetention}
          disabled={saving}
          class="px-5 py-2 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-sm font-medium transition-colors disabled:opacity-50"
        >Save</button>
        <button
          onclick={runPurge}
          disabled={purging}
          class="px-5 py-2 border border-(--border) rounded-lg text-sm text-(--text-secondary) hover:text-(--text-primary) transition-colors disabled:opacity-50"
        >{purging ? 'Purging…' : 'Run Purge Now'}</button>
        <button
          onclick={wipeAll}
          disabled={wiping}
          class="px-5 py-2 border border-(--error)/30 rounded-lg text-sm text-(--error) hover:bg-(--error-bg) hover:border-(--error)/50 transition-colors disabled:opacity-50"
        >{wiping ? 'Wiping…' : 'Wipe All Data'}</button>
        {#if retentionSaved}
          <span class="text-sm text-(--success) animate-pulse">Saved</span>
        {/if}
        {#if purgeResult}
          <span class="text-sm text-(--text-secondary)">{purgeResult}</span>
        {/if}
        {#if wipeResult}
          <span class="text-sm text-(--error)">{wipeResult}</span>
        {/if}
      </div>
    </div>

    <div class="bg-(--bg-card) rounded-xl p-6 border border-(--border)">
      <div class="flex items-center justify-between mb-4">
        <div>
          <p class="font-medium text-(--text-primary)">Database Statistics</p>
          {#if dbStats}
            <p class="text-xs text-(--text-secondary) mt-0.5">Total database size: {formatBytes(dbStats.total_db_size_bytes)}</p>
          {/if}
        </div>
        <button
          onclick={loadDbStats}
          disabled={dbStatsLoading}
          class="px-3 py-1.5 border border-(--border) rounded-lg text-xs text-(--text-secondary) hover:text-(--text-primary) transition-colors disabled:opacity-50"
        >{dbStatsLoading ? 'Loading…' : 'Refresh'}</button>
      </div>
      {#if dbStats}
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {#each dbStats.tables as table}
            <div class="bg-(--bg-primary) rounded-lg p-4 border border-(--border)">
              <p class="text-xs text-(--text-secondary) uppercase tracking-wider">{TABLE_LABELS[table.name] || table.name}</p>
              <p class="text-xl font-semibold text-(--text-primary) mt-1">{formatNumber(table.rows)}</p>
              <div class="flex items-center gap-3 mt-1">
                <span class="text-xs text-(--text-secondary)">{formatBytes(table.size_bytes)}</span>
                {#if table.partitions != null}
                  <span class="text-xs text-(--text-secondary)">{table.partitions} partition{table.partitions !== 1 ? 's' : ''}</span>
                {/if}
              </div>
            </div>
          {/each}
        </div>
        {#if dbStats.content_dedup}
          {@const d = dbStats.content_dedup}
          {@const reuse = d.total_message_refs > 0 ? (d.total_message_refs / d.unique_messages).toFixed(1) : '0'}
          <div class="mt-4 bg-(--bg-primary) rounded-lg p-4 border border-(--border)">
            <p class="text-xs text-(--text-secondary) uppercase tracking-wider mb-3">Message Deduplication</p>
            <div class="flex flex-wrap items-baseline gap-x-6 gap-y-2">
              <div>
                <span class="text-xl font-semibold text-(--text-primary)">{formatNumber(d.unique_messages)}</span>
                <span class="text-xs text-(--text-secondary) ml-1">unique messages</span>
              </div>
              <div>
                <span class="text-xl font-semibold text-(--text-primary)">{formatNumber(d.total_message_refs)}</span>
                <span class="text-xs text-(--text-secondary) ml-1">references ({reuse}x reuse)</span>
              </div>
              <div>
                <span class="text-xl font-semibold text-(--success)">{d.savings_pct.toFixed(1)}%</span>
                <span class="text-xs text-(--text-secondary) ml-1">space saved</span>
              </div>
            </div>
            <div class="mt-3 flex items-center gap-3">
              <div class="flex-1 h-2 bg-(--bg-card) rounded-full overflow-hidden">
                <div
                  class="h-full bg-(--success) rounded-full transition-all"
                  style="width: {d.projected_bytes > 0 ? ((d.stored_bytes / d.projected_bytes) * 100).toFixed(1) : 100}%"
                ></div>
              </div>
              <span class="text-xs text-(--text-secondary) whitespace-nowrap">{formatBytes(d.stored_bytes)} / {formatBytes(d.projected_bytes)}</span>
            </div>
          </div>
        {/if}
        {#if dbStats.tools_dedup}
          {@const td = dbStats.tools_dedup}
          {@const reuse = td.total_tool_set_refs > 0 && td.unique_tool_sets > 0 ? (td.total_tool_set_refs / td.unique_tool_sets).toFixed(1) : '0'}
          <div class="mt-4 bg-(--bg-primary) rounded-lg p-4 border border-(--border)">
            <p class="text-xs text-(--text-secondary) uppercase tracking-wider mb-3">Tool Definition Deduplication</p>
            <div class="flex flex-wrap items-baseline gap-x-6 gap-y-2">
              <div>
                <span class="text-xl font-semibold text-(--text-primary)">{formatNumber(td.unique_tool_sets)}</span>
                <span class="text-xs text-(--text-secondary) ml-1">unique tool sets</span>
              </div>
              <div>
                <span class="text-xl font-semibold text-(--text-primary)">{formatNumber(td.total_tool_set_refs)}</span>
                <span class="text-xs text-(--text-secondary) ml-1">references ({reuse}x reuse)</span>
              </div>
              <div>
                <span class="text-xl font-semibold text-(--success)">{td.savings_pct.toFixed(1)}%</span>
                <span class="text-xs text-(--text-secondary) ml-1">space saved</span>
              </div>
            </div>
            <div class="mt-3 flex items-center gap-3">
              <div class="flex-1 h-2 bg-(--bg-card) rounded-full overflow-hidden">
                <div
                  class="h-full bg-(--chart-3) rounded-full transition-all"
                  style="width: {td.projected_bytes > 0 ? ((td.stored_bytes / td.projected_bytes) * 100).toFixed(1) : 100}%"
                ></div>
              </div>
              <span class="text-xs text-(--text-secondary) whitespace-nowrap">{formatBytes(td.stored_bytes)} / {formatBytes(td.projected_bytes)}</span>
            </div>
          </div>
        {/if}
        {#if dbStats.media_dedup}
          {@const md = dbStats.media_dedup}
          {@const dedupRatio = md.total_blobs > 0 ? (md.total_refs / md.total_blobs).toFixed(1) : '0'}
          {@const projectedBytes = md.total_blobs > 0 && md.unique_hashes > 0 ? Math.round(md.stored_bytes * md.total_refs / md.total_blobs) : md.stored_bytes}
          <div class="mt-4 bg-(--bg-primary) rounded-lg p-4 border border-(--border)">
            <p class="text-xs text-(--text-secondary) uppercase tracking-wider mb-3">Media Blob Storage</p>
            <div class="flex flex-wrap items-baseline gap-x-6 gap-y-2">
              <div>
                <span class="text-xl font-semibold text-(--text-primary)">{formatNumber(md.unique_hashes)}</span>
                <span class="text-xs text-(--text-secondary) ml-1">unique blobs</span>
              </div>
              <div>
                <span class="text-xl font-semibold text-(--text-primary)">{formatNumber(md.total_refs)}</span>
                <span class="text-xs text-(--text-secondary) ml-1">references ({dedupRatio}x reuse)</span>
              </div>
              <div>
                <span class="text-xl font-semibold text-(--success)">{md.savings_pct.toFixed(1)}%</span>
                <span class="text-xs text-(--text-secondary) ml-1">space saved</span>
              </div>
            </div>
            <div class="mt-3 flex items-center gap-3">
              <div class="flex-1 h-2 bg-(--bg-card) rounded-full overflow-hidden">
                <div
                  class="h-full bg-(--chart-2) rounded-full transition-all"
                  style="width: {projectedBytes > 0 ? ((md.stored_bytes / projectedBytes) * 100).toFixed(1) : 100}%"
                ></div>
              </div>
              <span class="text-xs text-(--text-secondary) whitespace-nowrap">{formatBytes(md.stored_bytes)} / {formatBytes(projectedBytes)}</span>
            </div>
          </div>
        {/if}
      {:else if dbStatsLoading}
        <p class="text-sm text-(--text-secondary)">Loading stats…</p>
      {:else}
        <p class="text-sm text-(--text-secondary)">Failed to load stats</p>
      {/if}
    </div>
  </section>
</div>
