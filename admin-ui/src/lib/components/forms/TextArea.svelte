<script lang="ts">
  // Plain styled textarea. Owns the canonical form-control class so
  // multi-line fields don't drift. No label — callers wrap it in a
  // <label> (or <FilterField>). Extra attributes (rows, placeholder,
  // oninput, disabled, …) ride the spread.
  import type { HTMLTextareaAttributes } from 'svelte/elements';

  interface Props extends Omit<HTMLTextareaAttributes, 'value'> {
    /** Two-way bound textarea value. */
    value?: string;
    /** Render the value in monospace (tokens, URIs, JSON). */
    mono?: boolean;
  }

  let { value = $bindable(''), mono = false, class: cls = '', ...rest }: Props = $props();
</script>

<textarea
  bind:value
  class="w-full px-2.5 py-1.5 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm placeholder:text-(--text-secondary) focus:outline-hidden focus:border-(--accent) transition-colors {mono ? 'font-mono' : ''} {cls}"
  {...rest}
></textarea>
