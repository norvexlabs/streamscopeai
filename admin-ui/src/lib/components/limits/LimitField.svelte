<script lang="ts">
  // Tri-state limit field — Inherit · Unlimited · Set a limit — for every limit
  // form (workspace pool, member default, member exception) in both planes.
  // The stored encoding (null / 0 / value) is never shown: `#lib/limits.js`
  // translates between the state and the column.
  import { m } from '#lib/paraglide/messages.js';
  import FormField from '#lib/components/forms/FormField.svelte';
  import NumberInput from '#lib/components/forms/NumberInput.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import { allowsInherit, isValidLimit, type LimitEncoding, type LimitState } from '#lib/limits.js';

  interface Props {
    label: string;
    /** Two-way bound field state. */
    limit: LimitState;
    encoding: LimitEncoding;
    /** What Inherit resolves to, rendered (e.g. "60", "$5.00"); omitted → "Inherit". */
    inheritedLabel?: string | null;
    step?: number;
    disabled?: boolean;
  }

  let { label, limit = $bindable(), encoding, inheritedLabel = null, step = 1, disabled = false }: Props = $props();
  const uid = $props.id();

  // Remembered so flipping to Unlimited and back restores what was typed.
  let lastValue = $state<number | undefined>(undefined);
  $effect.pre(() => {
    if (limit.kind === 'value') lastValue = limit.value;
  });

  function onMode(e: Event) {
    const kind = (e.currentTarget as HTMLSelectElement).value;
    if (kind === 'value') limit = { kind: 'value', value: lastValue !== undefined && lastValue > 0 ? lastValue : 1 };
    else if (kind === 'inherit' || kind === 'unlimited') limit = { kind };
  }

  // Whatever was typed is the field's state — an emptied or zero input is
  // shown as invalid and blocks the host's Save (`isValidLimit`), never
  // silently saved as the previous value or as unlimited.
  function onNumber(e: Event) {
    limit = { kind: 'value', value: (e.currentTarget as HTMLInputElement).valueAsNumber };
  }
</script>

<FormField {label} for="{uid}-mode">
  <div class="flex gap-2">
    <div class="w-44 shrink-0">
      <SelectInput id="{uid}-mode" value={limit.kind} onchange={onMode} {disabled}>
        {#if allowsInherit(encoding)}
          <option value="inherit">{inheritedLabel ? m.limits_state_inherit_value({ value: inheritedLabel }) : m.limits_state_inherit()}</option>
        {/if}
        <option value="unlimited">{encoding === 'member_default' ? m.limits_state_no_default() : m.limits_state_unlimited()}</option>
        <option value="value">{m.limits_state_value()}</option>
      </SelectInput>
    </div>
    {#if limit.kind === 'value'}
      <NumberInput value={Number.isFinite(limit.value) ? limit.value : undefined} min={0} {step} oninput={onNumber} {disabled} aria-label={label} aria-invalid={!isValidLimit(limit)} />
    {/if}
  </div>
  {#if !isValidLimit(limit)}<p class="text-[10px] text-(--error-text) mt-1">{m.limits_invalid_value()}</p>{/if}
</FormField>
