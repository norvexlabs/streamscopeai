<script lang="ts">
  // Add or edit one member's EXCEPTION — shared by the admin console and the
  // workspace manager's portal Team page. An exception replaces the workspace
  // default member limit per metric (higher or lower); each field left on
  // Inherit keeps the default, shown in its label. The host owns the API call
  // (each plane has its own endpoint) and receives the request body.
  import { untrack } from 'svelte';
  import { m } from '#lib/paraglide/messages.js';
  import type { components } from '#lib/generated/api-types.js';
  import FormModal from '#lib/components/forms/FormModal.svelte';
  import FormField from '#lib/components/forms/FormField.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import Callout from '#lib/components/Callout.svelte';
  import BudgetModeToggle from '#lib/components/BudgetModeToggle.svelte';
  import LimitField from './LimitField.svelte';
  import { decodeLimit, encodeLimit, exceedsPool, isValidLimit, type LimitState } from '#lib/limits.js';
  import { formatAmount, formatTokens } from '#lib/formatters.js';

  type Exception = components['schemas']['UserRateLimitOverride'];
  type Defaults = components['schemas']['MemberLimitDefaults'];
  type Body = components['schemas']['PutRateLimitOverrideRequest'];

  interface DirtyForm {
    readonly dirty: boolean;
    readonly confirmOpen: boolean;
    markDirty: () => void;
    markClean: () => void;
    confirmDiscard: () => Promise<boolean>;
    acceptDiscard: () => void;
    rejectDiscard: () => void;
  }

  interface Props {
    open: boolean;
    form: DirtyForm;
    /** Members an exception can be added for. */
    members: { user_id: string; email: string }[];
    /** The member being edited; `null` = pick one (adding). */
    userId: string | null;
    /** Existing exceptions, to seed the fields when a member is picked. */
    exceptions: Exception[];
    defaults: Defaults;
    /** The pool's effective caps (null = unlimited), for the above-pool note. */
    pool: { rpm: number | null; tpm: number | null; daily: number | null; monthly: number | null };
    currency: string;
    saving?: boolean;
    error?: string | null;
    onclose: () => void;
    onsave: (userId: string, body: Body) => void | Promise<void>;
  }

  let { open, form, members, userId, exceptions, defaults, pool, currency, saving = false, error = null, onclose, onsave }: Props = $props();

  let picked = $state('');
  let rpm = $state<LimitState>({ kind: 'inherit' });
  let tpm = $state<LimitState>({ kind: 'inherit' });
  let daily = $state<LimitState>({ kind: 'inherit' });
  let monthly = $state<LimitState>({ kind: 'inherit' });
  let mode = $state<'enforce' | 'alert_only'>('enforce');
  let seeded = $state('');

  function seed(forUser: string) {
    const e = exceptions.find((x) => x.user_id === forUser);
    rpm = decodeLimit(e?.requests_per_minute, 'exception');
    tpm = decodeLimit(e?.tokens_per_minute, 'exception');
    daily = decodeLimit(e?.daily_budget, 'exception');
    monthly = decodeLimit(e?.monthly_budget, 'exception');
    mode = e?.budget_mode === 'alert_only' ? 'alert_only' : 'enforce';
    seeded = JSON.stringify([rpm, tpm, daily, monthly, mode]);
    form.markClean();
  }

  // Each opening starts from its own member: the one being edited, or — when
  // adding — nobody, so the picker never opens on whoever was edited last.
  let wasOpen = false;
  $effect(() => {
    const isOpen = open;
    untrack(() => {
      if (isOpen && !wasOpen) {
        picked = userId ?? '';
        seed(picked);
      }
      wasOpen = isOpen;
    });
  });

  // When adding, picking a member seeds that member's existing exception: an
  // exception write is an upsert, so opening blank over one would wipe it.
  // Depends only on the pick — seeding reads the field states it writes, and
  // tracking them would re-seed (and wipe) on every keystroke.
  $effect(() => {
    if (!open || userId) return;
    const target = picked;
    untrack(() => seed(target));
  });

  $effect(() => {
    if (!open || !seeded) return;
    // Back to what was loaded is clean again — Cancel then asks nothing.
    if (JSON.stringify([rpm, tpm, daily, monthly, mode]) !== seeded) form.markDirty();
    else form.markClean();
  });

  const money = (n: number) => formatAmount(n, currency);
  const count = (n: number) => n.toLocaleString();
  const inheritLabel = (v: number | null | undefined, fmt: (n: number) => string) => (v != null && v > 0 ? fmt(v) : null);

  // Any field of this exception that would let the member past the pool — the
  // pool still applies.
  const abovePool = $derived.by(() => {
    const parts: string[] = [];
    if (pool.rpm != null && exceedsPool(rpm, pool.rpm)) parts.push(`${count(pool.rpm)} ${m.limits_rpm_short()}`);
    if (pool.tpm != null && exceedsPool(tpm, pool.tpm)) parts.push(`${formatTokens(pool.tpm)} ${m.limits_tpm_short()}`);
    if (pool.daily != null && exceedsPool(daily, pool.daily)) parts.push(`${money(pool.daily)} ${m.limits_daily_short()}`);
    if (pool.monthly != null && exceedsPool(monthly, pool.monthly)) parts.push(`${money(pool.monthly)} ${m.limits_monthly_short()}`);
    return parts.join(', ');
  });

  const email = $derived(members.find((x) => x.user_id === (userId ?? picked))?.email ?? '');

  async function save() {
    const target = userId ?? picked;
    if (!target || ![rpm, tpm, daily, monthly].every(isValidLimit)) return;
    await onsave(target, {
      requests_per_minute: encodeLimit(rpm, 'exception'),
      tokens_per_minute: encodeLimit(tpm, 'exception'),
      daily_budget: encodeLimit(daily, 'exception'),
      monthly_budget: encodeLimit(monthly, 'exception'),
      budget_mode: mode,
    });
  }
</script>

<FormModal
  {open}
  {form}
  {saving}
  {error}
  title={userId ? m.limits_exception_title_edit({ email }) : m.limits_exception_title_new()}
  saveLabel={m.limits_save()}
  saveDisabled={!(userId ?? picked) || ![rpm, tpm, daily, monthly].every(isValidLimit)}
  maxWidth="max-w-lg"
  {onclose}
  onsave={save}
>
  {#if !userId}
    <FormField label={m.limits_member()} for="exception-member">
      <SelectInput id="exception-member" bind:value={picked}>
        <option value="" disabled>{m.limits_select_member()}</option>
        {#each members as mem (mem.user_id)}<option value={mem.user_id}>{mem.email}</option>{/each}
      </SelectInput>
    </FormField>
  {/if}
  <p class="text-xs text-(--text-secondary)">{m.limits_exception_replaces()}</p>
  <LimitField label={m.limits_rpm()} bind:limit={rpm} encoding="exception" inheritedLabel={inheritLabel(defaults.requests_per_minute, count)} />
  <LimitField label={m.limits_tpm()} bind:limit={tpm} encoding="exception" inheritedLabel={inheritLabel(defaults.tokens_per_minute, formatTokens)} />
  <LimitField label={m.limits_daily({ currency })} bind:limit={daily} encoding="exception" step={0.01} inheritedLabel={inheritLabel(defaults.daily_budget, money)} />
  <LimitField label={m.limits_monthly({ currency })} bind:limit={monthly} encoding="exception" step={0.01} inheritedLabel={inheritLabel(defaults.monthly_budget, money)} />
  <FormField label={m.limits_budget_mode()}>
    <BudgetModeToggle bind:mode />
    <p class="text-[10px] text-(--text-secondary) mt-1">{mode === 'alert_only' ? m.limits_mode_alert_hint() : m.limits_mode_enforce_hint()}</p>
  </FormField>
  {#if abovePool}
    <Callout severity="info" title={m.limits_above_pool({ pool: abovePool })} />
  {/if}
</FormModal>
