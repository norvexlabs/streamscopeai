/**
 * Focus-trap Svelte action for modals and any other element that should
 * own keyboard focus while open. Captures the opener element on mount,
 * autofocuses the first matching control, cycles Tab / Shift-Tab inside
 * the container, and restores opener focus on destroy.
 *
 * Usage:
 *   <div use:focusTrap={{ autoFocus: 'first-input' }}> ... </div>
 *
 * `autoFocus` accepts:
 *   - 'first-input'  — first focusable form control (default)
 *   - 'close-button' — first button with aria-label="Close"
 *   - 'container'    — the trap container itself; for read-only dialogs with
 *                      no controls, this draws no focus ring
 *   - HTMLElement    — focus that exact node
 *   - false          — skip autofocus (caller handles it)
 */
const FOCUSABLE_SELECTOR = [
  'a[href]',
  'area[href]',
  'input:not([disabled]):not([type="hidden"])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  'button:not([disabled])',
  'iframe',
  'object',
  'embed',
  '[contenteditable="true"]',
  '[tabindex]:not([tabindex="-1"])',
].join(',');

type AutoFocusTarget = 'first-input' | 'close-button' | 'container' | HTMLElement | false;

export interface FocusTrapOptions {
  autoFocus?: AutoFocusTarget;
}

export function focusTrap(node: HTMLElement, options: FocusTrapOptions = {}) {
  const opener = (document.activeElement as HTMLElement | null) ?? null;
  let opts = options;

  function getFocusable(): HTMLElement[] {
    return Array.from(node.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)).filter(
      (el) => !el.hasAttribute('inert') && el.offsetParent !== null,
    );
  }

  function pickInitial(): HTMLElement | null {
    const t = opts.autoFocus ?? 'first-input';
    if (t === false) return null;
    if (t === 'container') return node;
    if (t instanceof HTMLElement) return t;
    const focusables = getFocusable();
    if (focusables.length === 0) return null;
    if (t === 'close-button') {
      const closeBtn = focusables.find((el) => el.getAttribute('aria-label') === 'Close');
      if (closeBtn) return closeBtn;
    }
    // 'first-input' — prefer the first non-button focusable, else the first focusable.
    const firstInput = focusables.find((el) => el.tagName !== 'BUTTON');
    return firstInput ?? focusables[0];
  }

  function onKeydown(e: KeyboardEvent) {
    if (e.key !== 'Tab') return;
    const focusables = getFocusable();
    if (focusables.length === 0) {
      e.preventDefault();
      return;
    }
    const first = focusables[0];
    const last = focusables[focusables.length - 1];
    const active = document.activeElement as HTMLElement | null;
    if (e.shiftKey) {
      if (active === first || !node.contains(active)) {
        e.preventDefault();
        last.focus();
      }
    } else {
      if (active === last || !node.contains(active)) {
        e.preventDefault();
        first.focus();
      }
    }
  }

  // Defer initial focus to the next microtask so transitions / mount order
  // don't lose the focus call to a still-rendering subtree.
  queueMicrotask(() => {
    const target = pickInitial();
    target?.focus();
  });

  node.addEventListener('keydown', onKeydown);

  return {
    update(next: FocusTrapOptions) {
      opts = next;
    },
    destroy() {
      node.removeEventListener('keydown', onKeydown);
      // Restore focus to the opener if it's still in the document.
      if (opener && document.contains(opener)) {
        opener.focus({ preventScroll: true });
      }
    },
  };
}
