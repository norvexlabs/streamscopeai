<script lang="ts">
  // Shared layout for every search-bar field: one uppercase tracking-wider
  // label above an input / select / custom control. Control height is uniform
  // app-wide via the `--control-h` base rule (app.css), so inputs and selects
  // already align in the bar — this component only owns the label + flex shape.
  //
  // The `uppercase` lives on the label TEXT span, not the wrapping <label>:
  // custom-markup controls (the workspace multi-select <details> combo) render
  // inside this label and would otherwise inherit the transform and show their
  // own content all-caps. Native <input>/<select> don't inherit text-transform,
  // which is why only the custom combos were affected.
  //
  // A single native input/select field gets the implicit label association (no
  // `for`) so the caption focuses it. A CUSTOM composite control (a <details>
  // combo, a button group) must pass `for` = its focusable element's id: an
  // explicit `for` stops the <label> from activating the control's first
  // labelable descendant when the caption is clicked.

  import type { Snippet } from 'svelte';

  interface Props {
    label: string;
    /** Tailwind classes for the outer wrapper — typically a `min-w-[…]`
     *  or `flex-1 min-w-[…]` to control how the field flexes in the bar. */
    class?: string;
    /** Id of the focusable element when the child is a custom composite control
     *  (see above). Omit for a plain native input/select field. */
    for?: string;
    children: Snippet;
  }

  let { label, class: cls = '', for: forId, children }: Props = $props();
</script>

<div class={cls}>
  <label class="block" for={forId}>
    <span class="block text-xs text-(--text-secondary) mb-1 uppercase tracking-wider">{label}</span>
    {@render children()}
  </label>
</div>
