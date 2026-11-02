<script lang="ts">
  import { focusTrap } from '#lib/actions/focusTrap.js';

  let {
    open,
    title = 'Confirm',
    message,
    confirmLabel = 'Confirm',
    cancelLabel = 'Cancel',
    destructive = false,
    /** If set, the user must type this exact string before the confirm button
     * becomes enabled. Use for high-blast-radius operations (delete tenant,
     * drop policy rule, force-purge audit). */
    requireText,
    onconfirm,
    oncancel,
  }: {
    open: boolean;
    title?: string;
    message: string;
    confirmLabel?: string;
    cancelLabel?: string;
    destructive?: boolean;
    requireText?: string;
    onconfirm: () => void;
    oncancel: () => void;
  } = $props();

  let typed = $state('');
  const requireOk = $derived(!requireText || typed === requireText);

  // Reset the typed buffer whenever the dialog reopens so a previous
  // attempt doesn't auto-arm the next confirmation.
  $effect(() => {
    if (open) typed = '';
  });

  function handleBackdropClick(e: MouseEvent) {
    if (e.target === e.currentTarget) oncancel();
  }
  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') oncancel();
    if (e.key === 'Enter' && requireOk) onconfirm();
  }
</script>

{#if open}
  <!-- svelte-ignore a11y_no_static_element_interactions -->
  <div
    class="fixed inset-0 bg-(--bg-scrim) z-60 flex items-center justify-center p-4"
    onclick={handleBackdropClick}
    onkeydown={handleKeydown}
  >
    <div
      class="bg-(--bg-secondary) border border-(--border) rounded-xl w-full max-w-sm p-6 space-y-4 shadow-(--shadow-pop)"
      role="dialog"
      aria-modal="true"
      aria-label={title}
      tabindex="-1"
      use:focusTrap={{ autoFocus: requireText ? 'first-input' : 'close-button' }}
    >
      <h3 class="text-base font-semibold text-(--text-primary)">{title}</h3>
      <p class="text-sm text-(--text-secondary)">{message}</p>
      {#if requireText}
        <div class="space-y-1.5">
          <label for="confirm-typed" class="block text-xs text-(--text-secondary)">
            Type <code class="font-mono text-(--text-primary)">{requireText}</code> to confirm
          </label>
          <input
            id="confirm-typed"
            bind:value={typed}
            autocomplete="off"
            class="w-full px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm font-mono"
          />
        </div>
      {/if}
      <div class="flex justify-end gap-2 pt-2">
        <button onclick={oncancel}
          class="px-4 py-1.5 text-sm rounded-lg border border-(--border) text-(--text-secondary) hover:text-(--text-primary) transition-colors">
          {cancelLabel}
        </button>
        <button data-testid="confirm-ok" onclick={onconfirm} disabled={!requireOk}
          class="px-4 py-1.5 text-sm rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed {destructive ? 'bg-(--error) hover:bg-(--error)/85 text-(--error-fg)' : 'bg-(--accent) hover:bg-(--accent-hover) text-(--accent-fg)'}">
          {confirmLabel}
        </button>
      </div>
    </div>
  </div>
{/if}
