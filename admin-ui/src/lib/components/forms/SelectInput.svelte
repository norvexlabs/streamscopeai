<script lang="ts" generics="T extends string | number | null = string">
  // The console's one select — every form, filter-bar and header select goes
  // through it (`lint-form-controls.sh` refuses a `<select>` anywhere else).
  // A native <select> opens the OPERATING SYSTEM's popup, which no stylesheet
  // reaches in every browser: this component keeps the native element as the
  // source of truth and draws the closed control and the open list itself, in
  // the theme's tokens.
  //
  // How it holds together (keep each when changing it):
  // - The native <select> stays in the page, transparent, over the drawn
  //   control, with no pointer events: it carries `bind:value`, the caller's
  //   attributes (`onchange`, `id`, `aria-label`, `disabled`, `data-testid`…),
  //   the keyboard focus, the label association and the accessible combobox —
  //   so a screen reader, a `<label for>` and a test's `select_option` meet a
  //   real select. Its own popup is never opened: the keys that would open it
  //   open the drawn list instead (`onkeydown`), and no pointer reaches it.
  // - A pick writes `selectedIndex` and dispatches `input` then `change`, as
  //   the browser does, so `bind:value` (typed values included: Svelte reads
  //   the option's own value) and the caller's `onchange` run as for a native
  //   pick.
  // - The drawn list is read from the native options (a MutationObserver keeps
  //   it current), so callers pass plain <option>/<optgroup> markup.
  // - The list opens in the top layer (`popover`), placed by the control's
  //   rect: no `overflow` ancestor (a modal, a table) clips it.
  //
  // `fluid` (default) fills the container width — right for form fields and
  // FilterField columns. `fluid={false}` sizes to the widest option, as a
  // native select does. `variant="bare"` drops the border and background, for
  // a select set in header chrome.
  import type { HTMLSelectAttributes } from 'svelte/elements';
  import type { Snippet } from 'svelte';
  import { onMount } from 'svelte';
  import Icon from '#lib/components/Icon.svelte';

  interface Props extends Omit<HTMLSelectAttributes, 'value' | 'children' | 'multiple' | 'size'> {
    /** Two-way bound selected value. */
    value?: T;
    /** Fill the container width. Default true; false sizes to the widest option. */
    fluid?: boolean;
    /** `field` (default): bordered form control. `bare`: no border or background. */
    variant?: 'field' | 'bare';
    /** The <option> elements. */
    children: Snippet;
  }

  let {
    value = $bindable(),
    class: cls = '',
    fluid = true,
    variant = 'field',
    children,
    onkeydown: callerKeydown,
    onblur: callerBlur,
    ...rest
  }: Props = $props();

  type Row =
    | { kind: 'group'; label: string }
    | { kind: 'option'; index: number; label: string; disabled: boolean; title: string };

  const uid = $props.id();
  let native = $state<HTMLSelectElement | null>(null);
  let control = $state<HTMLDivElement | null>(null);
  let list = $state<HTMLDivElement | null>(null);
  let rows = $state<Row[]>([]);
  let selectedIndex = $state(-1);
  let disabled = $state(false);
  let open = $state(false);
  let active = $state(-1);

  const shown = $derived.by(() => {
    const row = rows.find((r) => r.kind === 'option' && r.index === selectedIndex);
    return row?.label ?? '';
  });
  const widths = $derived(fluid ? [] : rows.filter((r) => r.kind === 'option').map((r) => r.label));

  function read(): void {
    const el = native;
    if (!el) return;
    const next: Row[] = [];
    for (const child of Array.from(el.children)) {
      if (child instanceof HTMLOptGroupElement) {
        next.push({ kind: 'group', label: child.label });
        for (const o of Array.from(child.children)) {
          if (o instanceof HTMLOptionElement) next.push(optionRow(o, o.disabled || child.disabled));
        }
      } else if (child instanceof HTMLOptionElement) {
        next.push(optionRow(child, child.disabled));
      }
    }
    rows = next;
    selectedIndex = el.selectedIndex;
    // Disabled on its own or by a disabled `<fieldset>` around it; a list open
    // when the select turns disabled (a form saving) closes.
    disabled = el.matches(':disabled');
    if (disabled) hide();
  }

  function optionRow(o: HTMLOptionElement, off: boolean): Row {
    return { kind: 'option', index: o.index, label: o.label || o.text, disabled: off, title: o.title };
  }

  onMount(() => {
    read();
    if (!native) return;
    const observer = new MutationObserver(read);
    observer.observe(native, { childList: true, subtree: true, attributes: true, characterData: true });
    return () => observer.disconnect();
  });

  // A value set from outside (the binding, a reset) moves the native select
  // without an event: re-read it once the binding has written the DOM.
  $effect(() => {
    void value;
    queueMicrotask(read);
  });

  const enabledIndexes = $derived(
    rows.flatMap((r) => (r.kind === 'option' && !r.disabled ? [r.index] : []))
  );

  function place(): void {
    if (!control || !list) return;
    const r = control.getBoundingClientRect();
    const below = window.innerHeight - r.bottom;
    const height = Math.min(list.scrollHeight, 288);
    const up = below < height + 8 && r.top > below;
    list.style.minWidth = `${r.width}px`;
    list.style.left = `${Math.max(8, Math.min(r.left, window.innerWidth - list.offsetWidth - 8))}px`;
    list.style.top = up ? `${Math.max(8, r.top - height - 4)}px` : `${r.bottom + 4}px`;
    // Never past the viewport: the list scrolls within the room it gets.
    list.style.maxHeight = `${Math.max(96, Math.min(288, (up ? r.top : below) - 12))}px`;
  }

  function show(): void {
    if (open || !list) return;
    // Read first: an enclosing `<fieldset>` turned disabled is seen here.
    read();
    if (disabled) return;
    active = enabledIndexes.includes(selectedIndex) ? selectedIndex : (enabledIndexes[0] ?? -1);
    list.showPopover();
    open = true;
    place();
    scrollActive();
  }

  function hide(): void {
    if (!open || !list) return;
    list.hidePopover();
    open = false;
  }

  // `focus`: give the native select the focus back — not after a touch, where
  // focusing it opens the platform's own picker over the drawn list (iOS).
  function pick(index: number, focus = true): void {
    const el = native;
    hide();
    if (!el || index < 0 || el.matches(':disabled')) return;
    if (focus) el.focus({ preventScroll: true });
    // Typeahead on the closed list steps on from the option it picked.
    active = index;
    if (index === el.selectedIndex) return;
    el.selectedIndex = index;
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
    read();
  }

  function move(step: number): void {
    if (enabledIndexes.length === 0) return;
    const at = enabledIndexes.indexOf(active);
    const next = at < 0 ? 0 : Math.min(enabledIndexes.length - 1, Math.max(0, at + step));
    active = enabledIndexes[next];
    scrollActive();
  }

  function scrollActive(): void {
    queueMicrotask(() => list?.querySelector(`[data-index="${active}"]`)?.scrollIntoView({ block: 'nearest' }));
  }

  let typed = '';
  let typedAt = 0;
  /** A search is under way: a key typed in the last 700 ms. */
  function searching(): boolean {
    return typed !== '' && Date.now() - typedAt <= 700;
  }
  function typeahead(key: string): void {
    const now = Date.now();
    typed = now - typedAt > 700 ? key : typed + key;
    typedAt = now;
    // One letter typed again steps to the next label starting with it, as a
    // native select does; anything else searches from the top.
    const cycling = typed.length > 1 && [...typed].every((c) => c === typed[0]);
    const q = (cycling ? typed[0] : typed).toLowerCase();
    const matches = rows.filter(
      (r) => r.kind === 'option' && !r.disabled && r.label.trim().toLowerCase().startsWith(q)
    );
    const hit = cycling
      ? (matches.find((r) => r.kind === 'option' && r.index > active) ?? matches[0])
      : matches[0];
    if (hit && hit.kind === 'option') {
      if (open) {
        active = hit.index;
        scrollActive();
      } else {
        pick(hit.index);
      }
    }
  }

  function onkeydown(e: KeyboardEvent & { currentTarget: EventTarget & HTMLSelectElement }): void {
    callerKeydown?.(e);
    if (e.defaultPrevented) return;
    const opening = e.key === ' ' || e.key === 'Enter' || e.key === 'F4' || e.key === 'ArrowDown' || e.key === 'ArrowUp';
    if (!open) {
      // A space inside a search is part of it, the list closed as well.
      if (e.key === ' ' && searching()) {
        e.preventDefault();
        typeahead(' ');
      } else if (opening) {
        e.preventDefault();
        show();
      } else if (e.key.length === 1 && !e.ctrlKey && !e.metaKey && !e.altKey) {
        e.preventDefault();
        typeahead(e.key);
      }
      return;
    }
    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        move(1);
        break;
      case 'ArrowUp':
        e.preventDefault();
        move(-1);
        break;
      case 'Home':
      case 'PageUp':
        e.preventDefault();
        move(-enabledIndexes.length);
        break;
      case 'End':
      case 'PageDown':
        e.preventDefault();
        move(enabledIndexes.length);
        break;
      // A key the open list takes is the list's alone: an enclosing modal or
      // dialog never sees it (an Escape closes the list, not the modal; an
      // Enter picks the option, it confirms nothing), as a native popup's
      // keys never reached the page.
      case ' ':
        // A space inside a search is part of it ("last 7"), as on a native select.
        e.preventDefault();
        e.stopPropagation();
        if (searching()) typeahead(' ');
        else pick(active);
        break;
      case 'Enter':
        e.preventDefault();
        e.stopPropagation();
        pick(active);
        break;
      case 'Escape':
        e.preventDefault();
        e.stopPropagation();
        hide();
        break;
      case 'Tab':
        hide();
        break;
      default:
        if (e.key.length === 1 && !e.ctrlKey && !e.metaKey && !e.altKey) {
          e.preventDefault();
          typeahead(e.key);
        }
    }
  }

  // A mouse opens the list on press, as a native select does; a touch or a
  // pen on release (`click`), so a swipe that starts on the control scrolls
  // the page instead of opening it.
  // The press is not cancelled: the control's `mousedown` handler keeps the
  // focus where it is (cancelling `pointerdown` would suppress that
  // `mousedown`, and Firefox would then move the focus off the select, whose
  // blur closes the list again).
  // The pointer that pressed the control: the click that follows a tap is
  // reported as a mouse click by WebKit, so the press decides.
  let pressedBy = '';
  // The same for an option: a tapped option never focuses the native select.
  let optionPressedBy = '';
  function onControlDown(e: PointerEvent): void {
    pressedBy = e.pointerType;
    if (e.pointerType !== 'mouse' || e.button !== 0 || disabled) return;
    toggleFromPointer(true);
  }
  function onControlClick(e: MouseEvent): void {
    // A click inside an enclosing `<label>` would activate its control — the
    // native select — focusing it: on iOS that opens the platform's picker,
    // and WebKit's activation click closes the drawn list again.
    e.preventDefault();
    if (disabled || pressedBy === 'mouse' || pressedBy === '') return;
    pressedBy = '';
    toggleFromPointer(false);
  }
  // `focus`: a mouse focuses the native select, which keeps the keyboard on
  // it; a touch does not — on iOS that would open its own picker as well.
  function toggleFromPointer(focus: boolean): void {
    if (focus) native?.focus({ preventScroll: true });
    if (open) hide();
    else show();
  }

  function onWindowDown(e: PointerEvent): void {
    if (!open || !(e.target instanceof Node)) return;
    if (list?.contains(e.target) || control?.contains(e.target)) return;
    hide();
  }

  function onScroll(e: Event): void {
    if (!open) return;
    if (e.target instanceof Node && list?.contains(e.target)) return;
    place();
  }
</script>

<svelte:window onpointerdown={onWindowDown} onresize={() => open && place()} onscrollcapture={onScroll} />

<div class="ss {fluid ? 'w-full' : 'inline-grid'} {cls}" class:bare={variant === 'bare'} class:off={disabled}>
  <!-- svelte-ignore a11y_no_static_element_interactions, a11y_click_events_have_key_events -->
  <div
    bind:this={control}
    class="ss-control"
    class:open
    aria-hidden="true"
    title={rest.title ?? undefined}
    onpointerdown={onControlDown}
    onclick={onControlClick}
    onmousedown={(e) => e.preventDefault()}
  >
    {#if fluid}
      <span class="ss-value">{shown}</span>
    {:else}
      <span class="ss-sizer">
        <span class="ss-value">{shown}</span>
        {#each widths as w, i (i)}<span class="ss-ghost">{w}</span>{/each}
      </span>
    {/if}
    <Icon name="chevronDown" size="xs" color="currentColor" class="ss-chevron" />
  </div>
  <select
    bind:this={native}
    bind:value
    class="ss-native"
    {...rest}
    {onkeydown}
    onblur={(e) => {
      hide();
      callerBlur?.(e);
    }}
  >
    {@render children()}
  </select>
  <div bind:this={list} id="{uid}-list" class="ss-list" popover="manual" aria-hidden="true" onmousedown={(e) => e.preventDefault()}>
    {#each rows as row, i (i)}
      {#if row.kind === 'group'}
        <div class="ss-group">{row.label}</div>
      {:else}
        <!-- svelte-ignore a11y_no_static_element_interactions, a11y_click_events_have_key_events -->
        <div
          class="ss-option"
          class:selected={row.index === selectedIndex}
          class:active={row.index === active}
          class:disabled={row.disabled}
          data-index={row.index}
          title={row.title || undefined}
          onpointerenter={() => !row.disabled && (active = row.index)}
          onpointerdown={(e) => (optionPressedBy = e.pointerType)}
          onclick={(e) => {
            // The list sits inside an enclosing `<label>` too: its activation
            // would focus the native select (`onControlClick`).
            e.preventDefault();
            if (!row.disabled) pick(row.index, optionPressedBy === 'mouse');
          }}
        >
          <span class="ss-label">{row.label}</span>
          {#if row.index === selectedIndex}
            <Icon name="check" size="xs" color="var(--accent)" />
          {/if}
        </div>
      {/if}
    {/each}
  </div>
</div>

<style>
  .ss {
    position: relative;
    min-width: 0;
  }
  /* The control's text size, in the components layer: a caller's size class
     (`class="text-xs"`, a Tailwind utility, in the later utilities layer) wins
     over it — an unlayered rule would win over every utility. */
  @layer components {
    :where(.ss) {
      font-size: 0.875rem;
    }
  }
  .ss-control {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.5rem;
    height: var(--control-h);
    padding: 0 0.625rem;
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 0.5rem;
    color: var(--text-primary);
    font-size: inherit;
    cursor: pointer;
    user-select: none;
    transition: border-color 0.15s;
  }
  .ss-control:hover,
  .ss-control.open {
    border-color: var(--accent);
  }
  .ss:has(.ss-native:focus-visible) .ss-control {
    border-color: var(--accent);
    outline: 2px solid var(--focus-ring);
    outline-offset: 1px;
  }
  .bare .ss-control {
    padding: 0;
    background: transparent;
    border-color: transparent;
    font-weight: 500;
  }
  .bare .ss-control:hover,
  .bare .ss-control.open {
    border-color: transparent;
    color: var(--accent);
  }
  /* Disabled on its own or by an enclosing `<fieldset>`: drawn from the native
     select's own state, so a fieldset turning disabled shows at once. */
  .off .ss-control,
  .ss:has(.ss-native:disabled) .ss-control {
    opacity: 0.5;
    cursor: not-allowed;
  }
  .off .ss-control:hover,
  .ss:has(.ss-native:disabled) .ss-control:hover {
    border-color: var(--border);
  }
  .ss-value {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    min-width: 0;
  }
  .ss-sizer {
    display: inline-grid;
    min-width: 0;
  }
  .ss-sizer > * {
    grid-area: 1 / 1;
  }
  .ss-ghost {
    visibility: hidden;
    height: 0;
    white-space: nowrap;
  }
  .ss-control :global(.ss-chevron) {
    flex: none;
    color: var(--text-secondary);
  }
  /* The native select sits over the drawn control, invisible and without
     pointer events: it holds focus, value and the accessible role, never its
     own popup. */
  .ss-native {
    position: absolute;
    inset: 0;
    width: 100%;
    height: 100%;
    opacity: 0;
    pointer-events: none;
    appearance: none;
  }
  .ss-list {
    position: fixed;
    inset: auto;
    margin: 0;
    max-height: 18rem;
    max-width: min(32rem, calc(100vw - 1rem));
    overflow-y: auto;
    padding: 0.25rem;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 0.5rem;
    box-shadow: var(--shadow-pop);
    color: var(--text-primary);
    /* It is a child of the control's wrapper: the caller's size reaches it. */
    font-size: inherit;
  }
  .ss-group {
    padding: 0.5rem 0.5rem 0.25rem;
    color: var(--text-secondary);
    font-size: 0.625rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  .ss-option {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.75rem;
    padding: 0.375rem 0.5rem;
    border-radius: 0.375rem;
    cursor: pointer;
    white-space: nowrap;
  }
  .ss-option.active {
    background: var(--bg-hover);
  }
  .ss-option.selected .ss-label {
    color: var(--accent);
    font-weight: 500;
  }
  .ss-option.disabled {
    opacity: 0.45;
    cursor: default;
  }
  .ss-label {
    overflow: hidden;
    text-overflow: ellipsis;
  }
</style>
