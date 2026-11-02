<script lang="ts">
  // The header refresh control of both planes, on every view. Two controls:
  //  - ↻ — or the R key anywhere outside a text field — refreshes once.
  //  - the "auto" toggle (console only: given `autoRefresh`; the portal
  //    refreshes by hand) — or Shift+R — switches auto-refresh on and off, on
  //    a viewing page (`live`, `#lib/liveViews.js`). On, it refreshes now and
  //    then every 30 s for an hour of visible time, paused while the tab is
  //    hidden (the timing rules are in `#lib/autoRefresh.js`), and shows the time
  //    left ("auto · 42m"). It follows the viewer across the plane's views
  //    until switched off or run out, and holds on an editing page — never a
  //    timed reload around a save — where it cannot be switched on.
  // A tick never lands while the viewer is editing — a modal dialog open, or
  // focus in a field being typed into: a reload under an edit would reset it. The tick
  // stays due and lands at the first clock tick after. R does nothing while a
  // modal dialog is open, for the same reason. `refreshCycle.autoRefreshing` publishes the
  // state, for the views that poll on their own.
  import { onDestroy } from 'svelte';
  import Icon from '#lib/components/Icon.svelte';
  import { refreshCycle } from '#lib/refreshCycle.svelte.js';
  import {
    hideAuto,
    minutesLeft,
    remainingMs,
    showAuto,
    startAuto,
    tickAuto,
    type AutoRefresh,
  } from '#lib/autoRefresh.js';

  interface AutoRefreshOptions {
    /** The current view is one auto-refresh runs on. */
    live: boolean;
    /** The toggle's text ("auto"). */
    label: string;
    /** The toggle's accessible name — constant: `aria-pressed` carries its state. */
    name: string;
    /** Tooltip of the toggle while auto-refresh is off. */
    startLabel: string;
    /** Tooltip of the toggle while auto-refresh is on. */
    stopLabel: string;
    /** Shown in place of the minutes left while a tick is held by an edit. */
    pausedLabel: string;
    /** Tooltip while a tick is held by an edit. */
    pausedTitle: string;
    /** Tooltip of the toggle on an editing page, while off. */
    manualTitle: string;
    /** Tooltip of the toggle on an editing page, while running (held there). */
    heldHereTitle: string;
  }

  let {
    label,
    title,
    autoRefresh,
  }: {
    /** Accessible name of the refresh button (the plane's own wording). */
    label: string;
    /** Tooltip of the refresh button. */
    title: string;
    autoRefresh?: AutoRefreshOptions;
  } = $props();

  const live = $derived(autoRefresh?.live ?? false);

  /** The clock only runs while auto-refresh is on and the tab is visible; it
   *  drives both the 30 s ticks and the minutes shown in the toggle. */
  const CLOCK_MS = 5_000;

  let auto = $state<AutoRefresh | null>(null);
  let now = $state(Date.now());
  /** The last clock tick found the viewer editing: said on the toggle, so a
   *  held auto-refresh never passes for a running one. */
  let held = $state(false);
  // Leaving a viewing page holds at once; coming back releases at the next
  // clock tick, which then refreshes if a tick fell due.
  $effect(() => {
    if (!live && auto) held = true;
  });
  let clock: ReturnType<typeof setInterval> | null = null;

  // Published as "a view may poll on its own now": running and not held, so a
  // view's own poll pauses under an edit exactly as the ticks do.
  $effect(() => {
    refreshCycle.autoRefreshing = auto !== null && !held;
  });

  const visible = () => document.visibilityState === 'visible';

  const modalOpen = () => document.querySelector('[aria-modal="true"]') !== null;

  /** Focus where R is a keystroke, not a shortcut — a select included (a
   *  letter picks an option). */
  function keyTarget(t: EventTarget | null): boolean {
    return t instanceof HTMLElement && (t.isContentEditable || t.closest('input, textarea, select, [contenteditable]') !== null);
  }

  /** Inputs typed into. Not a picker, a checkbox or a button — focus stays on
   *  one after a pick, and auto-refresh must not stall on it. */
  const TYPED_INPUTS = new Set(['text', 'search', 'email', 'url', 'tel', 'password', 'number']);

  /** Focus in a field being typed into. */
  function typing(): boolean {
    const t = document.activeElement;
    if (!(t instanceof HTMLElement)) return false;
    if (t.isContentEditable) return true;
    if (t instanceof HTMLTextAreaElement) return !t.readOnly;
    return t instanceof HTMLInputElement && TYPED_INPUTS.has(t.type) && !t.readOnly;
  }

  /** An auto tick must wait: an editing page, or the viewer editing. */
  const editing = () => !live || modalOpen() || typing();

  function bump() {
    refreshCycle.refresh();
    // Any refresh restarts the interval: a tick never follows a manual one
    // within seconds.
    if (auto) auto = { ...auto, lastRefreshAt: Date.now() };
  }

  function stopClock() {
    if (clock !== null) clearInterval(clock);
    clock = null;
  }

  function onTick() {
    if (!auto) return stopClock();
    now = Date.now();
    held = editing();
    const next = tickAuto(auto, now, held);
    auto = next.state;
    if (!auto) held = false;
    if (next.refresh) bump();
    if (!auto) stopClock();
  }

  function startClock() {
    stopClock();
    clock = setInterval(onTick, CLOCK_MS);
  }

  function start() {
    held = false;
    bump();
    now = Date.now();
    auto = startAuto(now, visible());
    if (visible()) startClock();
    else stopClock();
  }

  function stop() {
    auto = null;
    held = false;
    stopClock();
  }

  function toggle() {
    if (!autoRefresh) return;
    if (auto) stop();
    else if (live) start();
  }

  function onVisibilityChange() {
    if (!auto) return;
    now = Date.now();
    if (visible()) {
      held = editing();
      const back = showAuto(auto, now, held);
      auto = back.state;
      if (!auto) held = false;
      if (back.refresh) bump();
      if (auto) startClock();
      else stopClock();
    } else {
      // No wake-ups for a tab nobody can see.
      auto = hideAuto(auto, now);
      stopClock();
    }
  }

  /** R refreshes and Shift+R toggles auto-refresh — never while typing, never
   *  with another modifier (Ctrl+R is the browser's reload), never on key
   *  repeat, never under a modal dialog. Caps Lock alone still counts as R: it
   *  changes `key`, not the modifiers. */
  function onKeydown(e: KeyboardEvent) {
    if (e.key?.toLowerCase() !== 'r' || e.ctrlKey || e.metaKey || e.altKey || e.repeat || e.defaultPrevented) return;
    if (keyTarget(e.target) || modalOpen()) return;
    e.preventDefault();
    if (e.shiftKey) toggle();
    else bump();
  }

  onDestroy(() => {
    stopClock();
    refreshCycle.autoRefreshing = false;
  });

  const minutes = $derived(auto ? minutesLeft(remainingMs(auto, now)) : 0);
</script>

<svelte:window onkeydown={onKeydown} />
<svelte:document onvisibilitychange={onVisibilityChange} />

<div class="inline-flex items-center rounded-lg bg-(--bg-primary) border border-(--border)">
  <button
    onclick={bump}
    data-refresh
    aria-label={label}
    {title}
    class="px-2 py-1.5 rounded-lg text-(--text-secondary) hover:text-(--text-primary) transition-colors"
  >
    <Icon name="refresh" size="sm" tone="neutral" />
  </button>
  {#if autoRefresh}
    <button
      onclick={toggle}
      data-auto-refresh
      aria-pressed={auto !== null}
      aria-disabled={!auto && !live}
      title={auto ? (!live ? autoRefresh.heldHereTitle : held ? autoRefresh.pausedTitle : autoRefresh.stopLabel) : live ? autoRefresh.startLabel : autoRefresh.manualTitle}
      aria-label={autoRefresh.name}
      class="inline-flex items-center gap-1.5 pr-2 py-1.5 text-[10px] font-medium font-mono transition-colors {auto
        ? 'text-(--text-secondary) hover:text-(--text-primary)'
        : live
          ? 'text-(--text-tertiary) hover:text-(--text-secondary)'
          : 'text-(--text-tertiary) opacity-50 cursor-default'}"
    >
      <span class="w-1.5 h-1.5 rounded-full {auto ? 'bg-(--success) animate-pulse' : 'bg-(--border)'}"></span>
      {#if auto}{autoRefresh.label} · {held ? autoRefresh.pausedLabel : `${minutes}m`}{:else}{autoRefresh.label}{/if}
    </button>
  {/if}
</div>
