<script lang="ts">
  // Canonical label + control + helper-text triple. Adopt instead of
  // hand-rolling the `<label class="block text-xs uppercase tracking-wider …">`
  // + `<p class="text-[10px] text-(--text-secondary) mt-1">` pair on every
  // form field. Pair with TextInput / SelectInput / NumberInput / TextArea —
  // pass the control's `id` as `for` so clicking the label focuses it.
  import type { Snippet } from 'svelte';

  interface Props {
    /** Main label text. */
    label: string;
    /** Renders as `<label for=…>` so clicking it focuses the bound control.
     *  Omit only for groupings that don't wrap a single focusable input
     *  (radio sets, checkboxes paired with their own inline label, custom
     *  composite editors); the label then falls back to a plain `<span>`. */
    for?: string;
    /** Inline snippet rendered next to the label in lighter ink — typically
     *  an "(optional)" or short qualifier. */
    hint?: Snippet;
    /** Helper paragraph rendered under the control. Snippets accept inline
     *  HTML such as `<code>` spans; plain strings render verbatim. */
    help?: Snippet | string;
    /** Extra classes on the wrapping `<div>` (e.g. `col-span-2`). */
    class?: string;
    /** The control itself. */
    children: Snippet;
  }

  let { label, for: forId, hint, help, class: cls = '', children }: Props = $props();
</script>

<div class={cls}>
  {#if forId}
    <label
      class="block text-xs uppercase tracking-wider text-(--text-secondary) mb-1"
      for={forId}
    >
      {label}{#if hint}{' '}{@render hint()}{/if}
    </label>
  {:else}
    <span class="block text-xs uppercase tracking-wider text-(--text-secondary) mb-1">
      {label}{#if hint}{' '}{@render hint()}{/if}
    </span>
  {/if}
  {@render children()}
  {#if help}
    {#if typeof help === 'string'}
      <p class="text-[10px] text-(--text-secondary) mt-1">{help}</p>
    {:else}
      <p class="text-[10px] text-(--text-secondary) mt-1">{@render help()}</p>
    {/if}
  {/if}
</div>
