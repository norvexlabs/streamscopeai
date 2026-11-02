<script lang="ts">
  import type { Snippet } from 'svelte';
  import { focusTrap } from '#lib/actions/focusTrap.js';
  import Icon from '#lib/components/Icon.svelte';

  let {
    open,
    title,
    onclose,
    maxWidth = 'max-w-2xl',
    /** When true, clicking the backdrop dismisses the modal. Defaults to false
     * so form-bearing modals don't lose data on a stray click. Set true for
     * confirmation-only modals. */
    dismissOnBackdrop = false,
    /** Initial focus target inside the modal. Defaults to the first form
     * control; pass 'close-button' for read-only dialogs, 'container' for
     * read-only content dialogs with no controls, or an HTMLElement to focus
     * a specific control (e.g. a primary footer button). */
    autoFocus = 'first-input',
    /** Optional pre-close hook — return false to veto. Used by dirty-form
     * guards to prompt before discarding edits. */
    onCloseRequest,
    children,
    footer,
  }: {
    open: boolean;
    title: string;
    onclose: () => void;
    maxWidth?: string;
    dismissOnBackdrop?: boolean;
    autoFocus?: 'first-input' | 'close-button' | 'container' | HTMLElement | false;
    onCloseRequest?: () => boolean | Promise<boolean>;
    children: Snippet;
    footer?: Snippet;
  } = $props();

  async function requestClose() {
    if (onCloseRequest) {
      const ok = await onCloseRequest();
      if (!ok) return;
    }
    onclose();
  }

  function handleBackdropClick(e: MouseEvent) {
    if (!dismissOnBackdrop) return;
    if (e.target === e.currentTarget) void requestClose();
  }

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      e.stopPropagation();
      void requestClose();
    }
  }
</script>

{#if open}
  <!-- svelte-ignore a11y_no_static_element_interactions -->
  <div
    class="fixed inset-0 bg-(--bg-scrim) z-50 flex items-center justify-center p-4"
    onclick={handleBackdropClick}
    onkeydown={handleKeydown}
  >
    <div
      class="bg-(--bg-secondary) border border-(--border) rounded-xl w-full {maxWidth} max-h-[90vh] flex flex-col shadow-(--shadow-pop)"
      role="dialog"
      aria-modal="true"
      aria-label={title}
      tabindex="-1"
      use:focusTrap={{ autoFocus }}
    >
      <div class="flex items-center justify-between p-6 pb-4 shrink-0">
        <h3 class="text-lg font-semibold text-(--text-primary)">{title}</h3>
        <button onclick={requestClose} aria-label="Close" class="text-(--text-secondary) hover:text-(--text-primary)">
          <Icon name="close" tone="neutral" />
        </button>
      </div>
      <!-- The bottom padding is not conditional on the footer: without it the
           last control sits flush on the footer's divider, and in a scrolling
           body there is nothing below the final row at all. -->
      <div class="overflow-y-auto px-6 pb-6">
        {@render children()}
      </div>
      {#if footer}
        <div class="shrink-0 px-6 py-4 border-t border-(--border)">
          {@render footer()}
        </div>
      {/if}
    </div>
  </div>
{/if}
