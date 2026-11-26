<script lang="ts">
  // The agent loop guard's three controls — mode, the note's threshold, the
  // refusal's threshold — shared by the tenant default (Settings → Budget) and
  // a workspace's own value (the workspace's Limits tab). Says why a save would
  // be refused; the admin API stays the authority on the bounds.
  import FormField from '#lib/components/forms/FormField.svelte';
  import NumberInput from '#lib/components/forms/NumberInput.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import { LOOP_GUARD_MAX_STOP_AT, LOOP_GUARD_MIN_NUDGE_AT, LOOP_GUARD_MODES, loopGuardProblem, type LoopGuardSettings } from '#lib/loop-guard.js';

  interface Props {
    value: LoopGuardSettings;
    /** Prefix of the controls' ids, unique on the page. */
    idPrefix: string;
    disabled?: boolean;
  }

  let { value = $bindable(), idPrefix, disabled = false }: Props = $props();

  const problem = $derived(loopGuardProblem(value));
</script>

<div class="space-y-2">
  <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
    <FormField label="Mode" for="{idPrefix}-mode">
      <SelectInput id="{idPrefix}-mode" bind:value={value.mode} {disabled} data-testid="{idPrefix}-mode">
        {#each LOOP_GUARD_MODES as m (m.value)}
          <option value={m.value}>{m.label}</option>
        {/each}
      </SelectInput>
    </FormField>
    <FormField label="Add the note from N times in a row" for="{idPrefix}-nudge-at">
      <NumberInput id="{idPrefix}-nudge-at" bind:value={value.nudge_at} min={LOOP_GUARD_MIN_NUDGE_AT} step="1" mono {disabled} data-testid="{idPrefix}-nudge-at" />
    </FormField>
    <FormField label="Refuse tool calls from N times in a row" for="{idPrefix}-stop-at">
      <NumberInput id="{idPrefix}-stop-at" bind:value={value.stop_at} min={LOOP_GUARD_MIN_NUDGE_AT + 2} max={LOOP_GUARD_MAX_STOP_AT} step="1" mono {disabled} data-testid="{idPrefix}-stop-at" />
    </FormField>
  </div>
  {#if problem && !disabled}
    <p class="text-xs text-(--error)" data-testid="{idPrefix}-problem">{problem}</p>
  {/if}
</div>
