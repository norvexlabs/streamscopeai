<script lang="ts">
  // Plain styled numeric input. Owns the canonical form-control class.
  // `value` is a number (two-way bound); `type` is fixed to "number".
  // Extra attributes (min, max, step, placeholder, disabled, …) ride the spread.
  import type { HTMLInputAttributes } from 'svelte/elements';

  interface Props extends Omit<HTMLInputAttributes, 'value' | 'type'> {
    /** Two-way bound numeric value. `undefined` renders an empty input — bind a
     *  `number | undefined` for an optional/unset field (a bindable fallback
     *  here would make Svelte reject binding `undefined`: props_invalid_value). */
    value?: number;
    /** Render the value in monospace. */
    mono?: boolean;
  }

  let { value = $bindable(), mono = false, class: cls = '', ...rest }: Props = $props();
</script>

<input
  type="number"
  bind:value
  class="w-full px-2.5 py-1.5 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm placeholder:text-(--text-secondary) focus:outline-hidden focus:border-(--accent) transition-colors {mono ? 'font-mono' : ''} {cls}"
  {...rest}
/>
