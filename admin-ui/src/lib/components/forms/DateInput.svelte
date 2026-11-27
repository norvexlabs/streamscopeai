<script lang="ts">
  // The console's date field: a `YYYY-MM-DD` text input with a themed month
  // calendar — the stand-in for `<input type="date">`, whose picker is the
  // browser's own and unstyled (`lint-form-controls.sh` refuses one). Typing
  // a date stays possible; the value is `''` or a real `YYYY-MM-DD` date, as a
  // native date input's is. The calendar opens in the top layer (`popover`),
  // so no `overflow` ancestor clips it. Days outside `min`/`max` are not
  // offered, and one typed is no value.
  import Icon from '#lib/components/Icon.svelte';
  import { m } from '#lib/paraglide/messages.js';
  import { getLocale } from '#lib/paraglide/runtime.js';

  let {
    value = $bindable(''),
    min,
    max,
    id,
    disabled = false,
    'aria-label': ariaLabel,
  }: {
    value?: string;
    min?: string;
    max?: string;
    id?: string;
    disabled?: boolean;
    'aria-label'?: string;
  } = $props();

  const uid = $props.id();
  let field = $state<HTMLDivElement | null>(null);
  let panel = $state<HTMLDivElement | null>(null);
  let open = $state(false);
  // The month shown: its first day, local time.
  let month = $state(new Date());

  const ISO = /^\d{4}-\d{2}-\d{2}$/;
  function iso(d: Date): string {
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
  }
  function parse(s: string | undefined): Date | null {
    if (!s || !ISO.test(s)) return null;
    const [y, mo, d] = s.split('-').map(Number);
    const out = new Date(y, mo - 1, d);
    return iso(out) === s ? out : null;
  }
  // What is typed, kept apart from `value`: the value is `''` until the text
  // is a real date, as a native date input's is — `2025-13-01` or `2025-02-31`
  // never reaches it. A value set from outside (or by the calendar) shows.
  let text = $state(value);
  $effect(() => {
    if (value !== (parse(text) && allowed(text) ? text : '')) text = value;
  });
  // A real date outside `min`/`max` stays as typed, marked, never erased.
  const outOfRange = $derived(parse(text) !== null && !allowed(text));
  // A phone's numeric keypad has no `-`: eight digits are read as a date too,
  // and written back with its dashes.
  // A date outside `min`/`max` is no value either, typed as the calendar
  // offers it.
  function typed(s: string): void {
    const t = s.trim();
    const digits = /^(\d{4})(\d{2})(\d{2})$/.exec(t);
    const date = digits ? `${digits[1]}-${digits[2]}-${digits[3]}` : t;
    const real = parse(date) !== null;
    text = real ? date : s;
    value = real && allowed(date) ? date : '';
  }

  // A calendar open when the field turns disabled (a form saving) closes.
  $effect(() => {
    if (disabled) close();
  });

  function allowed(s: string): boolean {
    return (!min || s >= min) && (!max || s <= max);
  }

  // Read again each time the calendar opens: a page left open past midnight
  // outlines the day it is now.
  let today = $state(iso(new Date()));
  const title = $derived(
    new Intl.DateTimeFormat(getLocale(), { month: 'long', year: 'numeric' }).format(month)
  );
  // Monday-first weekday initials in the UI locale.
  const weekdays = $derived(
    Array.from({ length: 7 }, (_, i) =>
      new Intl.DateTimeFormat(getLocale(), { weekday: 'narrow' }).format(new Date(2024, 0, 1 + i))
    )
  );
  const days = $derived.by(() => {
    const first = new Date(month.getFullYear(), month.getMonth(), 1);
    const lead = (first.getDay() + 6) % 7;
    const count = new Date(month.getFullYear(), month.getMonth() + 1, 0).getDate();
    const out: ({ iso: string; day: number } | null)[] = Array(lead).fill(null);
    for (let d = 1; d <= count; d++) {
      out.push({ iso: iso(new Date(month.getFullYear(), month.getMonth(), d)), day: d });
    }
    return out;
  });

  function place(): void {
    if (!field || !panel) return;
    const r = field.getBoundingClientRect();
    const below = window.innerHeight - r.bottom;
    const up = below < panel.scrollHeight + 8 && r.top > below;
    // Never past the viewport: the calendar scrolls within the room it gets,
    // and its height is read once capped.
    panel.style.maxHeight = `${Math.max(120, (up ? r.top : below) - 12)}px`;
    const height = panel.offsetHeight;
    panel.style.left = `${Math.max(8, Math.min(r.left, window.innerWidth - panel.offsetWidth - 8))}px`;
    panel.style.top = up ? `${Math.max(8, r.top - height - 4)}px` : `${r.bottom + 4}px`;
  }

  function toggle(): void {
    if (disabled || !panel) return;
    if (open) {
      panel.hidePopover();
      open = false;
      return;
    }
    today = iso(new Date());
    const at = parse(value) ?? parse(max) ?? new Date();
    month = new Date(at.getFullYear(), at.getMonth(), 1);
    panel.showPopover();
    open = true;
    place();
    // The calendar takes the focus: a click on its button focuses nothing in
    // Safari, and Escape then reaches the calendar's own handler.
    panel.focus({ preventScroll: true });
  }

  function close(): void {
    if (!open || !panel) return;
    panel.hidePopover();
    open = false;
  }

  let input = $state<HTMLInputElement | null>(null);

  function choose(s: string): void {
    if (disabled) return;
    value = s;
    close();
    // The picked day's button is gone with the calendar: the field keeps the
    // focus, so the next Tab moves on from it.
    input?.focus();
  }

  function shift(n: number): void {
    month = new Date(month.getFullYear(), month.getMonth() + n, 1);
  }

  function onWindowDown(e: PointerEvent): void {
    if (!open || !(e.target instanceof Node)) return;
    if (panel?.contains(e.target) || field?.contains(e.target)) return;
    close();
  }
  // The focus leaving both the field and the calendar (a Tab away) closes it.
  // A press inside the field or the calendar: Safari and macOS Firefox focus
  // no button on click, so the focus leaves for nowhere (`relatedTarget`
  // null) while the press is still ours — a click outside is closed by
  // `onWindowDown`.
  let pressing = false;
  function onFocusOut(e: FocusEvent): void {
    const to = e.relatedTarget;
    if (pressing) return;
    if (to instanceof Node && (field?.contains(to) || panel?.contains(to))) return;
    close();
  }

  // Escape closes the calendar and stops there, on the field or the calendar
  // it was pressed in — an enclosing modal never sees it.
  function onKey(e: KeyboardEvent): void {
    if (open && e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      close();
      input?.focus();
    }
  }
</script>

<svelte:window
  onpointerdown={onWindowDown}
  onpointerup={() => (pressing = false)}
  onpointercancel={() => (pressing = false)}
  onresize={() => open && place()}
  onscrollcapture={() => open && place()}
/>

<!-- svelte-ignore a11y_no_static_element_interactions -->
<div
  bind:this={field}
  class="di"
  class:off={disabled}
  onkeydown={onKey}
  onfocusout={onFocusOut}
  onpointerdown={() => (pressing = true)}
>
  <input
    {id}
    type="text"
    inputmode="numeric"
    placeholder="YYYY-MM-DD"
    maxlength={10}
    aria-label={ariaLabel}
    {disabled}
    bind:this={input}
    aria-invalid={outOfRange || undefined}
    class:out={outOfRange}
    value={text}
    oninput={(e) => typed(e.currentTarget.value)}
  />
  <button type="button" onclick={toggle} {disabled} aria-label={m.period_date_open()} aria-expanded={open} aria-controls="{uid}-cal">
    <Icon name="calendar" size="sm" color="currentColor" />
  </button>
</div>
<div bind:this={panel} id="{uid}-cal" class="di-cal" popover="manual" role="dialog" aria-label={title} tabindex="-1" onkeydown={onKey} onfocusout={onFocusOut} onpointerdown={() => (pressing = true)}>
  <div class="di-head">
    <button type="button" onclick={() => shift(-1)} aria-label={m.period_date_previous()}>
      <Icon name="chevronLeft" size="xs" color="currentColor" />
    </button>
    <span>{title}</span>
    <button type="button" onclick={() => shift(1)} aria-label={m.period_date_next()}>
      <Icon name="chevronRight" size="xs" color="currentColor" />
    </button>
  </div>
  <div class="di-grid">
    {#each weekdays as w, i (i)}<span class="di-wd">{w}</span>{/each}
    {#each days as d, i (i)}
      {#if d}
        <button
          type="button"
          class="di-day"
          class:selected={d.iso === value}
          class:today={d.iso === today}
          disabled={!allowed(d.iso)}
          onclick={() => choose(d.iso)}
        >{d.day}</button>
      {:else}
        <span></span>
      {/if}
    {/each}
  </div>
</div>

<style>
  .di {
    display: flex;
    align-items: center;
    height: var(--control-h);
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 0.5rem;
    transition: border-color 0.15s;
  }
  .di:focus-within {
    border-color: var(--accent);
  }
  .di.off {
    opacity: 0.5;
  }
  .di > input {
    flex: 1;
    min-width: 0;
    height: 100%;
    padding: 0 0.625rem;
    background: transparent;
    border: 0;
    color: var(--text-primary);
    font-size: 0.875rem;
    font-variant-numeric: tabular-nums;
    outline: none;
  }
  /* A real date outside the days offered: kept as typed, never taken. */
  .di > input.out {
    color: var(--error);
  }
  .di > input::placeholder {
    color: var(--text-secondary);
  }
  .di > button {
    display: flex;
    align-items: center;
    padding: 0 0.5rem;
    height: 100%;
    color: var(--text-secondary);
    cursor: pointer;
  }
  .di > button:hover:not(:disabled) {
    color: var(--text-primary);
  }
  .di-cal:focus {
    outline: none;
  }
  .di-cal {
    position: fixed;
    inset: auto;
    margin: 0;
    overflow-y: auto;
    width: 15.5rem;
    padding: 0.5rem;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 0.5rem;
    box-shadow: var(--shadow-pop);
    color: var(--text-primary);
    font-size: 0.8125rem;
  }
  .di-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 0 0.375rem;
    font-weight: 600;
    text-transform: capitalize;
  }
  .di-head > button {
    display: flex;
    padding: 0.25rem;
    border-radius: 0.375rem;
    color: var(--text-secondary);
    cursor: pointer;
  }
  .di-head > button:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }
  .di-grid {
    display: grid;
    grid-template-columns: repeat(7, 1fr);
    gap: 0.125rem;
  }
  .di-wd {
    padding: 0.25rem 0;
    text-align: center;
    color: var(--text-secondary);
    font-size: 0.6875rem;
    text-transform: uppercase;
  }
  .di-day {
    height: 1.875rem;
    border-radius: 0.375rem;
    color: var(--text-primary);
    font-variant-numeric: tabular-nums;
    cursor: pointer;
  }
  .di-day:hover:not(:disabled) {
    background: var(--bg-hover);
  }
  .di-day.today {
    box-shadow: inset 0 0 0 1px var(--border);
  }
  .di-day.selected {
    background: var(--accent);
    color: var(--accent-fg);
  }
  .di-day:disabled {
    opacity: 0.3;
    cursor: default;
  }
</style>
