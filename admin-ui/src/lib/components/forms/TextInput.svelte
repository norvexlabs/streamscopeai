<script lang="ts">
  // Plain styled text input. Owns the canonical filter/form input class so
  // the copy-pasted filter-bar inputs don't drift. No label — callers wrap
  // it in <FilterField> (or a <label>) which supplies the label and the
  // height lock. Extra attributes (type, placeholder, onkeydown, disabled,
  // id, data-testid, …) ride the spread.
  import type { HTMLInputAttributes } from 'svelte/elements';

  interface Props extends Omit<HTMLInputAttributes, 'value'> {
    /** Two-way bound input value. */
    value?: string;
    /** Render the value in monospace (hosts, IDs, URIs). */
    mono?: boolean;
  }

  let { value = $bindable(''), mono = false, class: cls = '', ...rest }: Props = $props();
</script>

<input
  bind:value
  class="w-full px-2.5 py-1.5 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm placeholder:text-(--text-secondary) focus:outline-hidden focus:border-(--accent) transition-colors {mono ? 'font-mono' : ''} {cls}"
  {...rest}
/>
