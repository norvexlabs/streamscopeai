<script lang="ts">
  import Modal from './Modal.svelte';
  import Icon from './Icon.svelte';

  let {
    open = false,
    title,
    message,
    affectedKeys = 0,
    affectedUsers = 0,
    affectedSessions = 0,
    confirmLabel = 'Delete',
    onconfirm,
    oncancel,
  }: {
    open: boolean;
    title: string;
    message: string;
    affectedKeys?: number;
    affectedUsers?: number;
    /** Live OAuth grants the action ends — connected MCP clients and signed-in
     * CLI machines. Counted separately from keys because somebody can hold none
     * of one and several of the other, and a preview naming only keys reads as
     * "nothing else to lose". */
    affectedSessions?: number;
    confirmLabel?: string;
    onconfirm: () => void;
    oncancel: () => void;
  } = $props();

  const hasImpact = $derived(affectedKeys > 0 || affectedUsers > 0 || affectedSessions > 0);
</script>

<Modal {open} {title} onclose={oncancel} maxWidth="max-w-md">
  <p class="text-sm text-(--text-secondary) mb-4">{message}</p>

  {#if hasImpact}
    <div class="flex items-center gap-6 px-4 py-3 rounded-lg bg-(--error-bg) border border-(--error)/20 mb-4">
      {#if affectedKeys > 0}
        <div class="flex items-center gap-2 text-sm">
          <Icon name="key" size="sm" tone="error" />
          <span class="text-(--error) font-medium">{affectedKeys} key{affectedKeys !== 1 ? 's' : ''} revoked</span>
        </div>
      {/if}
      {#if affectedSessions > 0}
        <div class="flex items-center gap-2 text-sm">
          <Icon name="lock" size="sm" tone="error" />
          <span class="text-(--error) font-medium"
            >{affectedSessions} connected client{affectedSessions !== 1 ? 's' : ''} disconnected</span
          >
        </div>
      {/if}
      {#if affectedUsers > 0}
        <div class="flex items-center gap-2 text-sm">
          <Icon name="user" size="sm" tone="error" />
          <span class="text-(--error) font-medium">{affectedUsers} user{affectedUsers !== 1 ? 's' : ''}</span>
        </div>
      {/if}
    </div>
  {:else}
    <p class="text-sm text-(--text-tertiary) mb-4 italic">No keys or connected clients will be affected.</p>
  {/if}

  <div class="flex justify-end gap-3">
    <button
      onclick={oncancel}
      class="px-4 py-2 text-sm rounded-lg border border-(--border) text-(--text-secondary) hover:bg-(--bg-elevated) hover:text-(--text-primary) transition-colors"
    >Cancel</button>
    <button
      onclick={onconfirm}
      class="px-4 py-2 text-sm rounded-lg bg-(--error) text-(--error-fg) hover:bg-(--error)/85"
    >{confirmLabel}</button>
  </div>
</Modal>
