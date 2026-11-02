<script lang="ts">
  import type { Snippet } from 'svelte';

  // Label + value pair shown as one cell of the 3-col Identity & Context grid
  // in the audit detail drawers. Renders `{label}: {value}` with the label in
  // `--text-secondary` and the value mono-and-primary by default. Pass
  // `children` for rich values (links, code+copy, button-as-filter); pass
  // plain `value` for the common case.

  type ColSpan = 1 | 2 | 3;

  interface Props {
    label: string;
    /** Simple monospace value. Use `children` for rich content. */
    value?: string;
    children?: Snippet;
    /** Grid column span. */
    colSpan?: ColSpan;
    /** Lay out the cell with `flex items-center gap-2` instead of the inline
     *  default. Needed when the value renders alongside an adjacent affordance
     *  (CopyButton, button, icon). The default `ml-2` mono span is dropped in
     *  flex mode — provide your own value markup via `children`. */
    flex?: boolean;
  }

  let { label, value, children, colSpan = 1, flex = false }: Props = $props();

  const spanClass = $derived(
    colSpan === 2 ? 'md:col-span-2' : colSpan === 3 ? 'md:col-span-3' : ''
  );
</script>

<div class="{flex ? 'flex items-center gap-2' : ''} {spanClass}">
  <span class="text-(--text-secondary)">{label}</span>
  {#if children}
    {@render children()}
  {:else}
    <span class="{flex ? '' : 'ml-2'} font-mono text-(--text-primary)">{value}</span>
  {/if}
</div>
