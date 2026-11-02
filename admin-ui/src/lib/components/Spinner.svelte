<script lang="ts">
  // Single source for the in-progress spinner shown on save / delete / sync
  // buttons. Render primitive (SVG inline by design, same exception as
  // `Icon` / `ProviderIcon` / `Sparkline`); never inline a new copy elsewhere.
  //
  // Default a11y: decorative (`aria-hidden`). Inside a `disabled` button
  // with its own label ("Delete User", "Save…") the disabled state already
  // communicates busy and the button text carries meaning — a second
  // `aria-label="Loading"` produces a double announce. For standalone use
  // (page-level loader, no surrounding label) set `ariaLabel="…"` to opt
  // into the polite live-region announce.

  let {
    size = 'sm',
    class: cls = '',
    ariaLabel,
  }: {
    size?: 'sm' | 'md';
    class?: string;
    ariaLabel?: string;
  } = $props();

  const sizeClass = $derived(size === 'sm' ? 'w-4 h-4' : 'w-5 h-5');
</script>

{#if ariaLabel}
  <svg
    class="animate-spin {sizeClass} {cls}"
    fill="none"
    viewBox="0 0 24 24"
    role="status"
    aria-label={ariaLabel}
  >
    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
  </svg>
{:else}
  <svg class="animate-spin {sizeClass} {cls}" fill="none" viewBox="0 0 24 24" aria-hidden="true">
    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
  </svg>
{/if}
