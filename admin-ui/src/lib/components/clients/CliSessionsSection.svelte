<script lang="ts">
  /**
   * CLI device sessions — one row per `ssai login`, i.e. per machine
   * holding a provisioning credential. Revoking one row kills that device
   * alone; the alternative lever is disabling the whole user account.
   *
   * These live in the same table as MCP-issued tokens but are deliberately
   * absent from the MCP tokens view, which renders a virtual server and an
   * audience a CLI login does not have.
   */
  import { adminApi } from '#lib/api-client.js';
  import { extractError, extractErrorCode } from '#lib/api-helpers.js';
  import { toast } from '#lib/toast.svelte.js';
  import type { components } from '#lib/generated/api-types.js';
  import { formatTimeAgo } from '#lib/formatters.js';
  import { Pagination as PaginationState } from '#lib/hooks.svelte.js';
  import Pagination from '#lib/components/Pagination.svelte';
  import ConfirmDialog from '#lib/components/ConfirmDialog.svelte';
  import EmptyState from '#lib/components/EmptyState.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import FilterField from '#lib/components/filter/FilterField.svelte';
  import Spinner from '#lib/components/Spinner.svelte';

  type CliSessionRow = components['schemas']['CliSessionRow'];
  type StatusFilter = components['schemas']['TokenStatusFilter'];

  let { activate = true }: { activate?: boolean } = $props();

  const pager = new PaginationState({ limit: 50 });

  let rows = $state<CliSessionRow[]>([]);
  let loading = $state(false);
  let error = $state('');
  let status = $state<StatusFilter>('active');
  let pendingRevoke = $state<CliSessionRow | null>(null);

  async function load() {
    loading = true;
    error = '';
    const { data, error: err } = await adminApi.GET('/api/v1/admin/cli/sessions', {
      params: { query: { limit: pager.limit, offset: pager.offset, status } },
    });
    if (err) {
      error = extractError(err);
      rows = [];
    } else {
      rows = pager.absorbOffset(data);
    }
    loading = false;
  }

  $effect(() => {
    if (!activate) return;
    void status;
    // A filter change must land on page 1 — keeping a page-3 offset across it
    // renders an empty page that reads as "no sessions of this kind".
    pager.reset();
    void load();
  });

  async function confirmRevoke() {
    const session = pendingRevoke;
    if (!session) return;
    pendingRevoke = null;
    const { error: err } = await adminApi.POST(
      '/api/v1/admin/cli/sessions/{id}/actions/revoke',
      { params: { path: { id: session.id } } },
    );
    if (err) {
      toast.error('Failed to revoke the CLI session', {
        body: extractError(err),
        code: extractErrorCode(err) ?? undefined,
      });
      return;
    }
    toast.success('CLI session revoked');
    void load();
  }

  /** Lifecycle of one row, as a dot colour plus the phrase next to it. */
  function lifecycle(s: CliSessionRow): { kind: 'active' | 'revoked' | 'expired'; label: string } {
    if (s.revoked_at) return { kind: 'revoked', label: 'revoked' };
    const left = new Date(s.expires_at).getTime() - Date.now();
    if (left <= 0) return { kind: 'expired', label: 'expired' };
    const hours = left / 3_600_000;
    if (hours >= 24) return { kind: 'active', label: `${Math.round(hours / 24)}d left` };
    if (hours >= 1) return { kind: 'active', label: `${Math.round(hours)}h left` };
    return { kind: 'active', label: `${Math.round(left / 60_000)}m left` };
  }

  const DOT: Record<'active' | 'revoked' | 'expired', string> = {
    active: 'bg-(--success)',
    revoked: 'bg-(--error)',
    expired: 'bg-(--text-secondary)',
  };
</script>

<div class="space-y-4">
  <div class="bg-(--bg-card) rounded-xl border border-(--border) p-4">
    <div class="flex flex-wrap gap-3 items-end justify-between">
      <p class="text-sm text-(--text-secondary) max-w-2xl">
        Every <span class="font-mono text-(--text-primary)">ssai login</span> registers the
        machine it ran on. Revoke one to cut that device off at its next call, without touching the
        user's other devices or their account.
      </p>
      <FilterField label="Status" class="min-w-35">
        <SelectInput bind:value={status}>
          <option value="active">Active</option>
          <option value="revoked">Revoked</option>
          <option value="expired">Expired</option>
          <option value="all">All</option>
        </SelectInput>
      </FilterField>
    </div>
  </div>

  {#if error}
    <div class="bg-(--error-bg) border border-(--error-border) rounded-lg p-3 text-sm text-(--error-text)">
      {error}
    </div>
  {/if}

  <div class="bg-(--bg-card) rounded-xl border border-(--border) overflow-hidden">
    {#if loading && rows.length === 0}
      <div class="px-5 py-12 flex justify-center"><Spinner /></div>
    {:else if rows.length === 0}
      <EmptyState
        title="No CLI sessions"
        body="Nobody has run `ssai login` under this filter yet."
      />
    {:else}
      <div class="overflow-x-auto">
        <table class="w-full text-sm">
          <thead>
            <tr class="border-b border-(--border) bg-(--bg-primary)">
              <th class="px-5 py-3 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Device</th>
              <th class="px-5 py-3 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">User</th>
              <th class="px-5 py-3 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Signed in</th>
              <th class="px-5 py-3 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Last active</th>
              <th class="px-5 py-3 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Status</th>
              <th class="px-5 py-3 text-right text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Actions</th>
            </tr>
          </thead>
          <tbody>
            {#each rows as session (session.id)}
              {@const lc = lifecycle(session)}
              <tr class="border-b border-(--border) hover:bg-(--bg-elevated)">
                <td class="px-5 py-2.5 text-(--text-primary)">
                  {session.device_name ?? 'Unnamed device'}
                  <span class="ml-2 font-mono text-xs text-(--text-secondary)">{session.id.slice(0, 8)}…</span>
                </td>
                <td class="px-5 py-2.5 text-xs">{session.user_display_name ?? session.user_email}</td>
                <td class="px-5 py-2.5 text-xs text-(--text-secondary)">{formatTimeAgo(session.signed_in_at)}</td>
                <td
                  class="px-5 py-2.5 text-xs text-(--text-secondary)"
                  title={session.last_used_at
                    ? 'Recorded about once a minute, so this is when the device was last active rather than its exact last request.'
                    : 'This device has not called since last-activity was recorded.'}
                >{session.last_used_at ? formatTimeAgo(session.last_used_at) : '—'}</td>
                <td class="px-5 py-2.5">
                  <span class="inline-flex items-center gap-1.5 text-xs text-(--text-secondary)">
                    <span class="w-1.5 h-1.5 rounded-full {DOT[lc.kind]}"></span>
                    {lc.label}
                  </span>
                </td>
                <td class="px-5 py-2.5 text-right">
                  {#if !session.revoked_at}
                    <button
                      onclick={() => (pendingRevoke = session)}
                      class="text-xs text-(--error) hover:bg-(--error-bg) px-1.5 rounded-sm"
                    >Revoke</button>
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      <Pagination state={pager} onchange={load} itemsShown={rows.length} />
    {/if}
  </div>
</div>

<ConfirmDialog
  open={pendingRevoke !== null}
  title="Revoke CLI session"
  message={pendingRevoke
    ? `Revoke ${pendingRevoke.device_name ?? 'this device'} for ${pendingRevoke.user_email}? It stops working on its next call and the user must run ssai login again.`
    : ''}
  confirmLabel="Revoke"
  destructive
  onconfirm={confirmRevoke}
  oncancel={() => (pendingRevoke = null)}
/>
