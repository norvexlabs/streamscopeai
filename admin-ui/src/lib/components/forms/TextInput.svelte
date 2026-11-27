<script lang="ts" module>
  export interface Suggestion {
    value: string;
    /** Shown beside the value. */
    label?: string;
  }
</script>

<script lang="ts">
  // Plain styled text input. Owns the canonical filter/form input class so
  // the copy-pasted filter-bar inputs don't drift. No label — callers wrap
  // it in <FilterField> (or a <label>) which supplies the label and the
  // height lock. Extra attributes (type, placeholder, onkeydown, disabled,
  // id, data-testid, …) ride the spread.
  //
  // `suggestions` offers values to pick while the field stays free text — the
  // console's themed stand-in for a `<datalist>`, whose popup is the browser's
  // own and unstyled (`lint-form-controls.sh` refuses one). A pick writes the
  // value and dispatches `input` then `change` on the input, as typing and
  // leaving the field would. The list opens in the top layer (`popover`), so
  // no `overflow` ancestor clips it.
  import type { HTMLInputAttributes } from 'svelte/elements';

  interface Props extends Omit<HTMLInputAttributes, 'value' | 'list'> {
    /** Two-way bound input value. */
    value?: string;
    /** Render the value in monospace (hosts, IDs, URIs). */
    mono?: boolean;
    /** Values offered while typing; any other text stays accepted. */
    suggestions?: readonly Suggestion[];
  }

  let {
    value = $bindable(''),
    mono = false,
    class: cls = '',
    suggestions,
    onkeydown: callerKeydown,
    onblur: callerBlur,
    onfocus: callerFocus,
    oninput: callerInput,
    ...rest
  }: Props = $props();

  const uid = $props.id();
  let input = $state<HTMLInputElement | null>(null);
  let list = $state<HTMLDivElement | null>(null);
  let open = $state(false);
  let active = $state(-1);

  const matches = $derived.by(() => {
    if (!suggestions) return [];
    const q = (value ?? '').trim().toLowerCase();
    if (!q) return suggestions;
    return suggestions.filter(
      (s) => s.value.toLowerCase().includes(q) || (s.label ?? '').toLowerCase().includes(q)
    );
  });

  // Close once nothing matches, or the only match is what is typed already.
  $effect(() => {
    if (open && (matches.length === 0 || (matches.length === 1 && matches[0].value === value))) hide();
  });

  function place(): void {
    if (!input || !list) return;
    const r = input.getBoundingClientRect();
    const below = window.innerHeight - r.bottom;
    const height = Math.min(list.scrollHeight, 256);
    const up = below < height + 8 && r.top > below;
    list.style.minWidth = `${r.width}px`;
    list.style.left = `${Math.max(8, Math.min(r.left, window.innerWidth - list.offsetWidth - 8))}px`;
    list.style.top = up ? `${Math.max(8, r.top - height - 4)}px` : `${r.bottom + 4}px`;
  }

  function show(): void {
    if (!suggestions || open || !list || rest.disabled || rest.readonly) return;
    if (matches.length === 0 || (matches.length === 1 && matches[0].value === value)) return;
    active = -1;
    list.showPopover();
    open = true;
    place();
  }

  function hide(): void {
    if (!open || !list) return;
    list.hidePopover();
    open = false;
  }

  function pick(s: Suggestion): void {
    hide();
    if (!input) return;
    input.value = s.value;
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
  }

  function onkeydown(e: KeyboardEvent & { currentTarget: EventTarget & HTMLInputElement }): void {
    callerKeydown?.(e);
    if (e.defaultPrevented || !suggestions) return;
    if (!open) {
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        show();
      }
      return;
    }
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      const n = matches.length;
      active = e.key === 'ArrowDown' ? (active + 1) % n : (active - 1 + n) % n;
      queueMicrotask(() =>
        list?.querySelector(`[data-i="${active}"]`)?.scrollIntoView({ block: 'nearest' })
      );
    } else if (e.key === 'Enter' && active >= 0 && matches[active]) {
      e.preventDefault();
      pick(matches[active]);
    } else if (e.key === 'Escape') {
      e.preventDefault();
      hide();
    } else if (e.key === 'Tab') {
      hide();
    }
  }

  function onScroll(e: Event): void {
    if (!open) return;
    if (e.target instanceof Node && list?.contains(e.target)) return;
    place();
  }
</script>

<svelte:window onresize={() => open && place()} onscrollcapture={onScroll} />

<input
  bind:this={input}
  bind:value
  class="w-full px-2.5 py-1.5 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm placeholder:text-(--text-secondary) focus:outline-hidden focus:border-(--accent) transition-colors {mono ? 'font-mono' : ''} {cls}"
  role={suggestions ? 'combobox' : undefined}
  aria-autocomplete={suggestions ? 'list' : undefined}
  aria-expanded={suggestions ? open : undefined}
  aria-controls={suggestions ? `${uid}-list` : undefined}
  aria-activedescendant={open && active >= 0 ? `${uid}-o${active}` : undefined}
  {...rest}
  {onkeydown}
  oninput={(e) => {
    callerInput?.(e);
    if (suggestions) {
      if (open) queueMicrotask(place);
      else show();
    }
  }}
  onfocus={(e) => {
    callerFocus?.(e);
    show();
  }}
  onblur={(e) => {
    hide();
    callerBlur?.(e);
  }}
/>
{#if suggestions}
  <div
    bind:this={list}
    id="{uid}-list"
    class="ts-list"
    popover="manual"
    role="listbox"
    tabindex="-1"
    onmousedown={(e) => e.preventDefault()}
  >
    {#each matches as s, i (s.value)}
      <!-- svelte-ignore a11y_click_events_have_key_events -->
      <div
        id="{uid}-o{i}"
        class="ts-option"
        class:active={i === active}
        role="option"
        tabindex="-1"
        aria-selected={i === active}
        data-i={i}
        onpointerenter={() => (active = i)}
        onclick={() => pick(s)}
      >
        <span class="ts-value" class:font-mono={mono}>{s.value}</span>
        {#if s.label}<span class="ts-label">{s.label}</span>{/if}
      </div>
    {/each}
  </div>
{/if}

<style>
  .ts-list {
    position: fixed;
    inset: auto;
    margin: 0;
    max-height: 16rem;
    max-width: min(32rem, calc(100vw - 1rem));
    overflow-y: auto;
    padding: 0.25rem;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 0.5rem;
    box-shadow: var(--shadow-pop);
    color: var(--text-primary);
    font-size: 0.875rem;
  }
  .ts-option {
    display: flex;
    align-items: baseline;
    gap: 0.75rem;
    padding: 0.375rem 0.5rem;
    border-radius: 0.375rem;
    cursor: pointer;
    white-space: nowrap;
  }
  .ts-option.active {
    background: var(--bg-hover);
  }
  .ts-label {
    color: var(--text-secondary);
    font-size: 0.75rem;
    overflow: hidden;
    text-overflow: ellipsis;
  }
</style>
