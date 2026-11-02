<script lang="ts" generics="T extends string | number | null = string">
  // Plain styled select — the canonical form/filter select. Owns the shared
  // control chrome (height via the --control-h base rule in app.css, padding,
  // border, focus, disabled); the <option>/<optgroup> markup is passed as
  // children so existing option markup moves over verbatim. No label — callers
  // wrap it in <FilterField>. Extra attributes (onchange, disabled, id,
  // aria-label, data-testid, …) ride the spread. Generic over the bound value
  // type so a string-literal union, a numeric option value or a `null` "none"
  // option binds without a cast.
  //
  // `fluid` (default) fills the container width — right for form fields and
  // FilterField columns. Set `fluid={false}` for an inline filter bar / toolbar
  // select that must size to its content instead of forcing a full-width row; a
  // `w-*` class in `cls` CANNOT override the baked-in `w-full` (Tailwind orders
  // `.w-full` after `.w-auto`, so it always wins), so this flag is the only way.
  import type { HTMLSelectAttributes } from 'svelte/elements';
  import type { Snippet } from 'svelte';

  interface Props extends Omit<HTMLSelectAttributes, 'value' | 'children'> {
    /** Two-way bound selected value. */
    value?: T;
    /** Fill the container width. Default true; false sizes to content. */
    fluid?: boolean;
    /** The <option> elements. */
    children: Snippet;
  }

  let { value = $bindable(), class: cls = '', fluid = true, children, ...rest }: Props = $props();
</script>

<select
  bind:value
  class="{fluid ? 'w-full ' : ''}px-2.5 py-1.5 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm focus:outline-hidden focus:border-(--accent) transition-colors disabled:opacity-50 disabled:cursor-not-allowed {cls}"
  {...rest}
>
  {@render children()}
</select>
