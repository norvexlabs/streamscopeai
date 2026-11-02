<script lang="ts">
  import Modal from '#lib/components/Modal.svelte';
  import KeyBudgetFields from '#lib/components/KeyBudgetFields.svelte';
  import { buildKeyBudget, spendVsCap, type KeyBudget } from '#lib/keyBudget.js';
  import FormError from '#lib/components/forms/FormError.svelte';
  import { m } from '#lib/paraglide/messages.js';

  interface Props {
    open: boolean;
    /** Identity of the key being edited — re-seeds the form when it changes. */
    keyId: string | null;
    /** Key being edited — label + current budget for seeding the form. */
    keyName: string | null;
    daily: number | null | undefined;
    monthly: number | null | undefined;
    mode: string | null | undefined;
    /** Current fleet-estimate spend, in the accounting currency, shown vs cap. */
    dailySpent?: number | null;
    monthlySpent?: number | null;
    /** Persist the new budget. A `null` budget clears the per-key cap. */
    onSave: (budget: KeyBudget | null) => Promise<void>;
    onClose: () => void;
  }

  let { open, keyId, keyName, daily, monthly, mode, dailySpent, monthlySpent, onSave, onClose }: Props = $props();

  // Spend-vs-cap lines from the key's *current* (saved) caps — informational,
  // independent of the in-progress edits.
  const dailyLine = $derived(spendVsCap(daily, dailySpent));
  const monthlyLine = $derived(spendVsCap(monthly, monthlySpent));

  let dailyStr = $state<string | number>('');
  let monthlyStr = $state<string | number>('');
  let modeSel = $state<'enforce' | 'alert_only'>('enforce');
  let saving = $state(false);
  let error = $state('');

  // Seed the form from the key's current budget whenever the modal opens for a
  // (different) key. Keying on `keyId` re-seeds even if the modal is reused for
  // another key without an intervening close.
  let seededId = $state<string | null>(null);
  $effect(() => {
    if (open && keyId !== null && keyId !== seededId) {
      dailyStr = daily != null ? String(daily) : '';
      monthlyStr = monthly != null ? String(monthly) : '';
      modeSel = mode === 'alert_only' ? 'alert_only' : 'enforce';
      seededId = keyId;
    } else if (!open && seededId !== null) {
      seededId = null;
    }
  });

  async function save() {
    saving = true;
    error = '';
    try {
      // buildKeyBudget returns undefined when both caps are blank → clear (null).
      await onSave(buildKeyBudget(dailyStr, monthlyStr, modeSel) ?? null);
      onClose();
    } catch (e: unknown) {
      error = e instanceof Error ? e.message : m.portal_comp_failed_save_budget();
    } finally {
      saving = false;
    }
  }
</script>

<Modal {open} title={m.portal_comp_budget_title({ name: keyName ?? m.portal_comp_key_noun() })} onclose={onClose} maxWidth="max-w-md">
  <div class="space-y-4">
    <KeyBudgetFields bind:daily={dailyStr} bind:monthly={monthlyStr} bind:mode={modeSel} />
    {#if dailyLine || monthlyLine}
      <div class="text-[10px] text-(--text-secondary) space-y-0.5">
        <p class="font-medium text-(--text-primary)">{m.portal_comp_current_spend()}</p>
        {#if dailyLine}<p>{m.portal_comp_daily_label()} {dailyLine}</p>{/if}
        {#if monthlyLine}<p>{m.portal_comp_monthly_label()} {monthlyLine}</p>{/if}
      </div>
    {/if}
    <p class="text-[10px] text-(--text-secondary)">{m.portal_comp_clear_caps_hint()}</p>
    <FormError message={error} />
    <div class="flex justify-end gap-2">
      <button onclick={onClose} class="px-4 py-1.5 text-sm rounded-lg text-(--text-secondary) hover:text-(--text-primary) transition-colors">{m.portal_comp_cancel()}</button>
      <button onclick={save} disabled={saving} class="px-4 py-1.5 text-sm rounded-lg bg-(--accent) text-(--accent-fg) hover:bg-(--accent-hover) disabled:opacity-50">{saving ? m.portal_comp_saving() : m.portal_comp_save_budget()}</button>
    </div>
  </div>
</Modal>
