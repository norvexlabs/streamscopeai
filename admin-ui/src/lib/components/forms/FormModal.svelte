<script lang="ts">
  // Modal shell for edit/create forms: wraps Modal with the standard
  // error banner, Cancel + Save footer, and a useDirtyForm guard so the
  // X / Esc / Cancel paths all prompt before discarding edits. Backdrop
  // dismissal stays disabled (Modal's default) so a stray click never
  // loses an edit.
  //
  // Body content (form fields) is passed as children. The host owns the
  // form state and the save function; the host's `useDirtyForm` instance
  // is passed in so navigation away from the page is also guarded.
  import type { Snippet } from 'svelte';
  import Modal from '#lib/components/Modal.svelte';
  import ConfirmDialog from '#lib/components/ConfirmDialog.svelte';

  interface DirtyForm {
    readonly dirty: boolean;
    readonly confirmOpen: boolean;
    markDirty: () => void;
    markClean: () => void;
    confirmDiscard: () => Promise<boolean>;
    acceptDiscard: () => void;
    rejectDiscard: () => void;
  }

  interface Props {
    open: boolean;
    title: string;
    /** From `useDirtyForm()` — drives the Esc / backdrop / Cancel guard. */
    form: DirtyForm;
    /** Save in progress — disables the Save button and shows "Saving…". */
    saving?: boolean;
    /** Optional error to render above the body in a red banner. */
    error?: string | null;
    /** Save button label (e.g. "Create rule", "Save changes"). */
    saveLabel: string;
    /** Extra disable condition beyond `saving` (e.g. validation failures). */
    saveDisabled?: boolean;
    /** Tooltip shown on the disabled Save button (validation hints). */
    saveDisabledHint?: string;
    maxWidth?: string;
    onclose: () => void;
    onsave: () => void | Promise<void>;
    children: Snippet;
  }

  let {
    open,
    title,
    form,
    saving = false,
    error = null,
    saveLabel,
    saveDisabled = false,
    saveDisabledHint = '',
    maxWidth = 'max-w-2xl',
    onclose,
    onsave,
    children,
  }: Props = $props();

  async function cancel() {
    if (await form.confirmDiscard()) onclose();
  }
</script>

<Modal {open} {title} {onclose} {maxWidth} onCloseRequest={form.confirmDiscard}>
  <div class="space-y-4 py-2">
    {#if error}
      <div class="p-3 rounded-lg bg-(--error-bg) text-(--error) text-sm">{error}</div>
    {/if}
    {@render children()}
  </div>

  {#snippet footer()}
    <div class="flex items-center justify-end gap-2">
      <button
        type="button"
        onclick={cancel}
        class="px-4 py-2 text-sm border border-(--border) rounded-lg hover:bg-(--bg-elevated) transition-colors"
      >Cancel</button>
      <button
        type="button"
        onclick={onsave}
        disabled={saving || saveDisabled}
        title={saveDisabled ? saveDisabledHint : ''}
        class="px-4 py-2 bg-(--accent) text-(--accent-fg) text-sm rounded-lg hover:bg-(--accent-hover) disabled:opacity-50 transition-colors"
      >
        {saving ? 'Saving…' : saveLabel}
      </button>
    </div>
  {/snippet}
</Modal>

<ConfirmDialog
  open={form.confirmOpen}
  title="Discard changes?"
  message="You have unsaved edits. Discard them?"
  confirmLabel="Discard"
  cancelLabel="Keep editing"
  destructive
  onconfirm={form.acceptDiscard}
  oncancel={form.rejectDiscard}
/>
