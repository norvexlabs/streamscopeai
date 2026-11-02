<script lang="ts">
  /**
   * Reveal-once key modal — `RevealKeyContent` in a Modal. Used by every
   * surface that mints/rotates a key OUTSIDE an already-open modal (Keys page
   * rotate, automation mint); `CreateKeyForm` renders the same content inline.
   */
  import Modal from '#lib/components/Modal.svelte';
  import RevealKeyContent from '#lib/components/RevealKeyContent.svelte';

  let {
    open,
    keyValue,
    snippet = '',
    title = 'Save this key now',
    onclose,
  }: {
    open: boolean;
    keyValue: string | null;
    snippet?: string;
    title?: string;
    onclose: () => void;
  } = $props();
</script>

<Modal {open} {title} {onclose} maxWidth="max-w-lg">
  {#if keyValue}
    <RevealKeyContent {keyValue} {snippet} onDone={onclose} />
  {/if}
</Modal>
