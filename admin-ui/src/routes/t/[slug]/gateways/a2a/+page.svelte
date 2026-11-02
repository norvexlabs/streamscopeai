<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import { extractError, extractErrorCode, extractInheritedDefaults } from '#lib/api-helpers.js';
  import { toast } from '#lib/toast.svelte.js';
  import { page } from '$app/state';
  import { scopeHref } from '#lib/tenant.js';
  import { auditHref } from '#lib/deeplinks.js';
  import { formatCount, formatDuration } from '#lib/formatters.js';
  import type { A2aAgentRow } from '#lib/api-types.js';
  import type { components } from '#lib/generated/api-types.js';
  import Page from '#lib/components/page/Page.svelte';
  import EmptyState from '#lib/components/EmptyState.svelte';
  import ConfirmDialog from '#lib/components/ConfirmDialog.svelte';
  import ToggleSetting from '#lib/components/forms/ToggleSetting.svelte';
  import CopyButton from '#lib/components/CopyButton.svelte';
  import RawJsonBlock from '#lib/components/RawJsonBlock.svelte';
  import A2aAgentEditModal from '#lib/components/a2a/A2aAgentEditModal.svelte';
  import type { PageProps } from './$types';

  let { params }: PageProps = $props();

  function reportError(title: string, err: unknown): void {
    toast.error(title, { body: extractError(err), code: extractErrorCode(err) ?? undefined });
  }

  type PanelItem = components['schemas']['A2aBreakdownItem'];

  let agents = $state<A2aAgentRow[]>([]);
  let loading = $state(true);
  let loadError = $state('');
  let showModal = $state(false);
  let editing = $state<A2aAgentRow | null>(null);
  let pendingDelete = $state<A2aAgentRow | null>(null);
  let refreshingId = $state<string | null>(null);
  let expandedCard = $state<string | null>(null);
  /// Recent traffic per agent slug — a registry entry with no signal of whether
  /// anything is actually reaching the agent tells an admin only half the story.
  let traffic = $state<Record<string, PanelItem>>({});
  /// The gateway origin clients point at. Without it there is nothing to hand a
  /// user, and the mount is unreachable anyway (the card cannot be rewritten).
  let proxyUrl = $state('');

  let slug = $derived(params.slug);

  async function loadAgents() {
    loading = true;
    loadError = '';
    const [list, panel, settings] = await Promise.all([
      adminApi.GET('/api/v1/admin/a2a/agents', { params: { query: { limit: 200 } } }),
      adminApi.GET('/api/v1/admin/a2a/dashboard/by-agent', {
        params: { query: { days: 7, limit: 100 } },
      }),
      adminApi.GET('/api/v1/admin/settings'),
    ]);
    if (list.error) {
      loadError = extractError(list.error);
    } else if (list.data) {
      agents = list.data.items;
    }
    traffic = Object.fromEntries((panel.data?.items ?? []).map((i) => [i.key, i]));
    proxyUrl = (extractInheritedDefaults(settings.data).proxy_public_url ?? '').replace(/\/$/, '');
    loading = false;
  }

  $effect(() => {
    void loadAgents();
  });

  // What the gateway publishes for this agent — the two URLs an admin hands to a
  // user. The card URL is where a client discovers the agent; the mount is where
  // it then talks to it.
  const mountUrl = (row: A2aAgentRow) => (proxyUrl ? `${proxyUrl}/a2a/${row.slug}` : '');
  const cardUrl = (row: A2aAgentRow) =>
    proxyUrl ? `${proxyUrl}/a2a/${row.slug}/.well-known/agent-card.json` : '';

  function cardString(row: A2aAgentRow, key: string): string | null {
    const card = row.agent_card as Record<string, unknown>;
    const v = card?.[key];
    return typeof v === 'string' ? v : null;
  }
  /// The protocol version the agent advertises on its JSON-RPC interface — the
  /// one axis on which a remote agent can silently be a different thing than the
  /// gateway speaks.
  function cardProtocol(row: A2aAgentRow): string | null {
    const card = row.agent_card as Record<string, unknown>;
    const ifaces = card?.supportedInterfaces;
    if (!Array.isArray(ifaces)) return null;
    const jsonrpc = (ifaces as Record<string, unknown>[]).find(
      (i) => i.protocolBinding === 'JSONRPC',
    );
    return typeof jsonrpc?.protocolVersion === 'string' ? jsonrpc.protocolVersion : null;
  }

  // Skill catalog from the cached card — discovery metadata only (there is no
  // "invoke skill" operation on the A2A wire).
  type Skill = { id?: string; name?: string; description?: string; tags?: string[] };
  function skills(row: A2aAgentRow): Skill[] {
    const card = row.agent_card as Record<string, unknown>;
    const list = card?.skills;
    return Array.isArray(list) ? (list as Skill[]) : [];
  }
  function cardStreaming(row: A2aAgentRow): boolean {
    const card = row.agent_card as Record<string, unknown>;
    const caps = card?.capabilities as Record<string, unknown> | undefined;
    return caps?.streaming === true;
  }

  async function toggleEnabled(row: A2aAgentRow, enabled: boolean) {
    const { error } = await adminApi.PATCH('/api/v1/admin/a2a/agents/{id}', {
      params: { path: { id: row.id } },
      body: { enabled },
    });
    if (error) {
      reportError(`Failed to ${enabled ? 'enable' : 'disable'} agent`, error);
      return;
    }
    void loadAgents();
  }

  async function refreshCard(row: A2aAgentRow) {
    refreshingId = row.id;
    const { error } = await adminApi.POST('/api/v1/admin/a2a/agents/{id}/actions/refresh-card', {
      params: { path: { id: row.id } },
    });
    refreshingId = null;
    if (error) {
      reportError(`Failed to refresh card for "${row.name}"`, error);
      return;
    }
    toast.success('Agent card refreshed');
    void loadAgents();
  }

  function openNew() {
    editing = null;
    showModal = true;
  }
  function openEdit(row: A2aAgentRow) {
    editing = row;
    showModal = true;
  }
  async function confirmDelete() {
    const row = pendingDelete;
    if (!row) return;
    pendingDelete = null;
    const { error } = await adminApi.DELETE('/api/v1/admin/a2a/agents/{id}', {
      params: { path: { id: row.id } },
    });
    if (error) {
      reportError(`Failed to delete agent "${row.name}"`, error);
      return;
    }
    void loadAgents();
  }
</script>

<Page title="A2A Gateway">
  {#snippet description()}
    Remote A2A agents exposed at
    <code class="bg-(--bg-primary) px-1.5 py-0.5 rounded-sm text-(--text-primary)">/a2a/&lt;slug&gt;</code>.
    The gateway serves a rewritten agent card at the mount's well-known path, terminates client
    auth with gateway keys, and forwards to the upstream agent with its stored credential.
    Grant workspaces access from each workspace's Access tab.
  {/snippet}
  {#snippet actions()}
    <button
      onclick={openNew}
      class="px-4 py-1.5 text-sm rounded-lg bg-(--accent) text-(--accent-fg) hover:bg-(--accent-hover)"
    >Register agent</button>
  {/snippet}

{#if loading}
  <div class="text-sm text-(--text-secondary) py-8 text-center">Loading…</div>
{:else if loadError}
  <div class="bg-(--error-bg) border border-(--error-border) text-(--error-text) p-3 rounded-lg text-sm">
    {loadError}
  </div>
{:else if agents.length === 0}
  <EmptyState
    title="No A2A agents"
    body="Register a remote agent by its card URL to expose it through the gateway."
  />
{:else}
  <div class="space-y-4">
    {#each agents as row (row.id)}
      {@const t = traffic[row.slug]}
      <div class="bg-(--bg-card) rounded-xl border border-(--border) p-4 space-y-3">
        <div class="flex items-start justify-between gap-4">
          <div class="min-w-0">
            <div class="flex items-center gap-2 flex-wrap">
              <h3 class="text-sm font-semibold text-(--text-primary)">{row.name}</h3>
              <code class="text-xs bg-(--bg-primary) px-1.5 py-0.5 rounded-sm text-(--text-secondary)">/a2a/{row.slug}</code>
              {#if !row.enabled}
                <span class="px-2 py-0.5 text-[11px] rounded-full bg-(--bg-primary) border border-(--border) text-(--text-secondary)">disabled</span>
              {/if}
              {#if cardStreaming(row)}
                <span class="px-2 py-0.5 text-[11px] rounded-full bg-(--bg-primary) border border-(--border) text-(--text-secondary)">streaming</span>
              {/if}
              {#if row.auth_mode === 'service_account'}
                <span class="px-2 py-0.5 text-[11px] rounded-full bg-(--bg-primary) border border-(--border) text-(--text-secondary)">service account</span>
              {/if}
              {#if cardProtocol(row)}
                <span class="px-2 py-0.5 text-[11px] rounded-full bg-(--bg-primary) border border-(--border) text-(--text-secondary)">A2A {cardProtocol(row)}</span>
              {/if}
              {#if cardString(row, 'version')}
                <span class="px-2 py-0.5 text-[11px] rounded-full bg-(--bg-primary) border border-(--border) text-(--text-secondary)">v{cardString(row, 'version')}</span>
              {/if}
            </div>
            {#if row.description}
              <p class="text-xs text-(--text-secondary) mt-1">{row.description}</p>
            {/if}
            <p class="text-xs text-(--text-secondary) mt-1 font-mono truncate">{row.agent_url}</p>
          </div>
          <div class="flex items-center gap-2 shrink-0">
            <ToggleSetting label="" value={row.enabled} onValueChange={(v) => toggleEnabled(row, v)} />
            <button
              onclick={() => refreshCard(row)}
              disabled={refreshingId === row.id}
              class="px-2.5 py-1 text-xs rounded-lg border border-(--border) text-(--text-primary) hover:bg-(--bg-primary) disabled:opacity-50"
            >{refreshingId === row.id ? 'Refreshing…' : 'Refresh card'}</button>
            <button
              onclick={() => openEdit(row)}
              class="px-2.5 py-1 text-xs rounded-lg border border-(--border) text-(--text-primary) hover:bg-(--bg-primary)"
            >Edit</button>
            <button
              onclick={() => (pendingDelete = row)}
              class="px-2.5 py-1 text-xs rounded-lg border border-(--error-border) text-(--error-text) hover:bg-(--error-bg)"
            >Delete</button>
          </div>
        </div>

        <!-- ── What clients use ─────────────────────────────────────────────
             The two URLs an admin hands to a user. Nobody can reach this agent
             without them, and neither is derivable from anything else on screen. -->
        {#if mountUrl(row)}
          <div class="grid grid-cols-1 md:grid-cols-2 gap-2">
            <div class="flex items-center gap-2 px-3 py-2 rounded-lg bg-(--bg-primary) border border-(--border) min-w-0">
              <span class="text-[10px] uppercase tracking-wider text-(--text-tertiary) shrink-0">Endpoint</span>
              <code class="text-xs font-mono text-(--text-primary) truncate" title={mountUrl(row)}>{mountUrl(row)}</code>
              <span class="ml-auto shrink-0"><CopyButton text={mountUrl(row)} /></span>
            </div>
            <div class="flex items-center gap-2 px-3 py-2 rounded-lg bg-(--bg-primary) border border-(--border) min-w-0">
              <span class="text-[10px] uppercase tracking-wider text-(--text-tertiary) shrink-0">Card</span>
              <code class="text-xs font-mono text-(--text-primary) truncate" title={cardUrl(row)}>{cardUrl(row)}</code>
              <span class="ml-auto shrink-0"><CopyButton text={cardUrl(row)} /></span>
            </div>
          </div>
        {:else}
          <p class="text-xs text-(--warning)">
            Set the gateway's public URL under Settings → Defaults — until then this agent has no
            reachable mount and its card cannot be published.
          </p>
        {/if}

        <!-- ── Recent traffic ───────────────────────────────────────────────
             A registry entry says what an agent IS; this says whether anything is
             actually reaching it, and whether it is answering. -->
        <div class="flex items-center gap-4 text-xs text-(--text-secondary) flex-wrap">
          {#if t}
            <a
              href={scopeHref(slug, page.url.pathname, auditHref({ kind: 'a2a', agent_slug: row.slug, days: '7' }))}
              class="text-(--accent) hover:text-(--accent-hover)"
            >{formatCount(t.call_count)} {t.call_count === 1 ? 'call' : 'calls'} · 7d</a>
            {#if t.error_count > 0}
              <span class="text-(--error)">{formatCount(t.error_count)} errors</span>
            {/if}
            {#if t.p95_latency_ms != null}
              <span>P95 {formatDuration(t.p95_latency_ms)}</span>
            {/if}
            <span>last used {new Date(t.last_used).toLocaleString()}</span>
          {:else}
            <span>No calls in the last 7 days</span>
          {/if}
          <a
            href={scopeHref(slug, page.url.pathname, '/dashboard/a2a')}
            class="ml-auto text-(--accent) hover:text-(--accent-hover)"
          >A2A dashboard →</a>
        </div>

        <!-- ── What the agent says it can do ────────────────────────────────
             Skills are discovery metadata (there is no "invoke skill" operation on
             the wire), but they are the agent's own statement of purpose — the
             description is the part worth reading, so it is not hidden in a tooltip. -->
        {#if skills(row).length > 0}
          <div>
            <h4 class="text-xs font-semibold text-(--text-secondary) uppercase tracking-wide mb-1.5">Skills</h4>
            <div class="space-y-1">
              {#each skills(row) as skill, i (i)}
                <div class="flex items-baseline gap-2 min-w-0">
                  <span class="text-xs font-mono text-(--text-primary) shrink-0">{skill.name ?? skill.id}</span>
                  {#if skill.description}
                    <span class="text-xs text-(--text-secondary) truncate" title={skill.description}>{skill.description}</span>
                  {/if}
                  {#if skill.tags?.length}
                    <span class="ml-auto flex gap-1 shrink-0">
                      {#each skill.tags as tag, j (j)}
                        <span class="px-1.5 py-0.5 text-[10px] rounded-full bg-(--bg-primary) border border-(--border) text-(--text-secondary)">{tag}</span>
                      {/each}
                    </span>
                  {/if}
                </div>
              {/each}
            </div>
          </div>
        {/if}

        <div class="flex items-center gap-3 text-xs text-(--text-secondary) flex-wrap">
          {#if row.card_fetched_at}
            <span>
              Card fetched {new Date(row.card_fetched_at).toLocaleString()} from
              <span class="font-mono">{row.card_url}</span>
            </span>
          {/if}
          <button
            onclick={() => (expandedCard = expandedCard === row.id ? null : row.id)}
            class="text-(--accent) hover:text-(--accent-hover)"
          >{expandedCard === row.id ? 'Hide card' : 'View card'}</button>
        </div>

        <!-- The agent's own card, verbatim: what it advertises about itself —
             capabilities, provider, security schemes, extensions. The gateway
             republishes a rewritten version; this is the original. -->
        {#if expandedCard === row.id}
          <RawJsonBlock label="agent card (as published by the agent)" value={row.agent_card} />
        {/if}
      </div>
    {/each}
  </div>
{/if}
</Page>

<A2aAgentEditModal
  open={showModal}
  {editing}
  onclose={() => (showModal = false)}
  onsaved={() => { showModal = false; void loadAgents(); }}
/>

<ConfirmDialog
  open={pendingDelete !== null}
  title="Delete A2A agent"
  message={pendingDelete ? `Delete agent "${pendingDelete.name}" (/a2a/${pendingDelete.slug})? Workspace grants and the mount disappear immediately; audit history is retained.` : ''}
  confirmLabel="Delete"
  destructive
  requireText={pendingDelete?.slug}
  onconfirm={confirmDelete}
  oncancel={() => (pendingDelete = null)}
/>
