<script module lang="ts">
  /** One identity = one email with two independent capabilities. */
  export interface ConsoleCap {
    id: string;
    role: string; // 'admin' | 'read_only'
    isActive: boolean;
  }
  export interface WsRole {
    workspace_id: string;
    workspace_name: string;
    role: string; // 'member' | 'manager'
  }
  export interface GatewayCap {
    id: string;
    isActive: boolean;
    workspaces: WsRole[];
  }
  export interface Identity {
    email: string;
    displayName?: string;
    console?: ConsoleCap;
    gateway?: GatewayCap;
  }
</script>

<script lang="ts">
  // Identity card — one row of the Accounts list. Shows BOTH capabilities with
  // their full state inline (console role, gateway workspace memberships) and
  // carries Disable/Enable per capability right here in the list; the Edit
  // modal owns profile + access level, including removal ("No access").
  import TagBadge from '#lib/components/TagBadge.svelte';
  import { scopeLabel } from '#lib/keyScopes.js';
  import { page } from '$app/state';
  import { thref } from '#lib/tenant.js';

  let slug = $derived(page.params.slug ?? '');

  let {
    identity,
    busy = false,
    onEdit,
    onToggleConsole,
    onToggleGateway,
  }: {
    identity: Identity;
    busy?: boolean;
    onEdit: (identity: Identity) => void;
    onToggleConsole: (identity: Identity) => void;
    onToggleGateway: (identity: Identity) => void;
  } = $props();

  const avatarLetter = $derived((identity.email || '?')[0].toUpperCase());
</script>

<div class="px-4 py-3">
  <!-- Header: identity + edit -->
  <div class="flex items-center gap-3">
    <div class="w-8 h-8 rounded-full bg-(--accent)/10 flex items-center justify-center text-xs font-medium text-(--accent) shrink-0">
      {avatarLetter}
    </div>
    <div class="flex-1 min-w-0">
      <span class="text-sm text-(--text-primary) font-medium truncate">{identity.email}</span>
      {#if identity.displayName}
        <span class="text-xs text-(--text-secondary) truncate ml-2">({identity.displayName})</span>
      {/if}
    </div>
    <button
      onclick={() => onEdit(identity)}
      class="text-xs text-(--accent) hover:bg-(--accent)/10 px-2.5 py-1 rounded-sm shrink-0"
    >Edit</button>
  </div>

  <!-- Capabilities -->
  <div class="mt-2 ml-11 space-y-1.5">
    <!-- Console -->
    <div class="flex items-center gap-2 flex-wrap">
      <span class="text-[10px] text-(--text-secondary) uppercase tracking-wider w-16 shrink-0">Console</span>
      {#if identity.console}
        <TagBadge color={identity.console.role === 'read_only' ? 'amber' : 'blue'}>
          {scopeLabel(identity.console.role)}
        </TagBadge>
        {#if !identity.console.isActive}
          <TagBadge color="neutral">Disabled</TagBadge>
        {/if}
        <span class="ml-auto flex items-center gap-1 shrink-0">
          <button onclick={() => onToggleConsole(identity)} disabled={busy}
            class="text-xs px-2 py-0.5 rounded-sm text-(--text-secondary) hover:text-(--text-primary) hover:bg-(--bg-elevated) transition-colors disabled:opacity-50"
          >{identity.console.isActive ? 'Disable' : 'Enable'}</button>
        </span>
      {:else}
        <span class="text-xs text-(--text-secondary)">No access</span>
      {/if}
    </div>

    <!-- Gateway -->
    <div class="flex items-center gap-2 flex-wrap">
      <span class="text-[10px] text-(--text-secondary) uppercase tracking-wider w-16 shrink-0">Gateway</span>
      {#if identity.gateway}
        {#if !identity.gateway.isActive}
          <TagBadge color="neutral">Disabled</TagBadge>
        {/if}
        {#if identity.gateway.workspaces.length}
          {#each identity.gateway.workspaces as ws (ws.workspace_id)}
            <a href={thref(slug, `/workspaces/${ws.workspace_id}`)}
              class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs bg-(--bg-primary) border border-(--border) text-(--text-primary) hover:border-(--accent) transition-colors"
              title="Manage membership on the workspace page"
            >
              {ws.workspace_name}<span class="text-(--text-secondary)">· {ws.role}</span>
            </a>
          {/each}
        {:else}
          <span class="text-xs text-(--text-secondary)">No workspaces — add on a <a href={thref(slug, '/workspaces')} class="text-(--accent) hover:underline">workspace page</a></span>
        {/if}
        <span class="ml-auto flex items-center gap-1 shrink-0">
          <a href={thref(slug, `/users?owner=${identity.gateway.id}`)}
            class="text-xs px-2 py-0.5 rounded-sm text-(--accent) hover:underline">Keys</a>
          <button onclick={() => onToggleGateway(identity)} disabled={busy}
            class="text-xs px-2 py-0.5 rounded-sm text-(--text-secondary) hover:text-(--text-primary) hover:bg-(--bg-elevated) transition-colors disabled:opacity-50"
          >{identity.gateway.isActive ? 'Disable' : 'Enable'}</button>
        </span>
      {:else}
        <span class="text-xs text-(--text-secondary)">No access</span>
      {/if}
    </div>
  </div>
</div>
