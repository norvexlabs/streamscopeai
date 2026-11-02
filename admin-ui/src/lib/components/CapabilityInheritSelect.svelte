<!--
  Tri-state capability override: Inherit / On / Off. The "Inherit" option shows
  the resolved value it would fall back to, and an optional source badge reveals
  where that resolved value comes from (you / synced / catalog / default).

  Shared by the upstream-model editor (inherits from the catalog) and the
  downstream-route editor (inherits from the model) — same control, different
  inheritance source. `value` is the wire tri-state: '' = inherit, 'true'/'false'
  = explicit override (matches the route PATCH and model PUT encodings).
-->
<script lang="ts" module>
  export type { FieldSource } from '#lib/components/SourceBadge.svelte';
</script>

<script lang="ts">
  import SourceBadge, { type FieldSource } from '#lib/components/SourceBadge.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';

  let {
    label,
    value = $bindable(''),
    inheritedOn,
    source,
    hint,
  }: {
    label: string;
    /** '' = inherit, 'true' | 'false' = explicit override. */
    value?: string;
    /** Resolved value shown in the Inherit option; undefined → just "Inherit". */
    inheritedOn?: boolean | null;
    /** Provenance of the resolved value, for the badge. */
    source?: FieldSource;
    /** A line under the control, for an effect the resolved value alone hides. */
    hint?: string;
  } = $props();

  const inheritText = $derived(
    inheritedOn === true ? 'Inherit (on)' : inheritedOn === false ? 'Inherit (off)' : 'Inherit',
  );
</script>

<label class="block text-xs text-(--text-secondary)">
  <span class="flex items-center gap-1.5">
    {label}
    {#if source}<SourceBadge {source} />{/if}
  </span>
  <SelectInput bind:value class="mt-1">
    <option value="">{inheritText}</option>
    <option value="true">On</option>
    <option value="false">Off</option>
  </SelectInput>
  {#if hint}<span class="mt-1 block text-[11px] text-(--text-tertiary)">{hint}</span>{/if}
</label>
