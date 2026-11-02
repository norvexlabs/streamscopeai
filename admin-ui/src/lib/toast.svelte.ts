/**
 * Global toast notification system. Single source of feedback for save
 * confirmations, validation failures, and asynchronous errors. Mounted
 * once in the root layout via `<ToastHost>`; every page imports the
 * singleton `toast` and calls `.success()` / `.error()` / `.info()`.
 *
 * Error toasts default to sticky (no auto-dismiss) because dropped error
 * context is the worst kind of UX regression — the prior `setTimeout`
 * pattern erased messages before users could read them. Successes
 * auto-dismiss after 4s.
 */

type ToastKind = 'success' | 'error' | 'info' | 'warning';

export type Toast = {
  id: string;
  kind: ToastKind;
  title: string;
  body?: string;
  /** ApiErrorResponse.code surfaced for switchable UI behaviour. */
  code?: string;
  /** null = sticky; numeric = milliseconds to live. */
  ttlMs: number | null;
};

const DEFAULT_TTL_MS = 4000;
const MAX_VISIBLE = 5;

class ToastStore {
  toasts = $state<Toast[]>([]);
  private nextId = 0;
  private timers = new Map<string, ReturnType<typeof setTimeout>>();

  private push(t: Omit<Toast, 'id'>): string {
    // One failure, one toast: the same error still on screen is replaced, not
    // stacked — a failure repeating on every refresh (manual or automatic)
    // shows once, as the newest, with a fresh lifetime, and a retry that fails
    // the same way visibly says so again. Errors only: a repeated
    // confirmation is a new event of its own.
    if (t.kind === 'error') {
      const same = this.toasts.find(
        (x) => x.kind === 'error' && x.title === t.title && x.body === t.body && x.code === t.code,
      );
      if (same) this.dismiss(same.id);
    }
    const id = `t${++this.nextId}`;
    const next = [...this.toasts, { ...t, id }];
    // Cap the stack — drop the oldest once we exceed the visible cap.
    while (next.length > MAX_VISIBLE) {
      const dropped = next.shift();
      if (dropped) this.clearTimer(dropped.id);
    }
    this.toasts = next;
    if (t.ttlMs != null) {
      const handle = setTimeout(() => this.dismiss(id), t.ttlMs);
      this.timers.set(id, handle);
    }
    return id;
  }

  success(title: string, body?: string): string {
    return this.push({ kind: 'success', title, body, ttlMs: DEFAULT_TTL_MS });
  }

  error(
    title: string,
    opts?: { body?: string; code?: string; sticky?: boolean; ttlMs?: number },
  ): string {
    return this.push({
      kind: 'error',
      title,
      body: opts?.body,
      code: opts?.code,
      ttlMs: opts?.sticky === false ? (opts?.ttlMs ?? DEFAULT_TTL_MS * 2) : null,
    });
  }

  info(title: string, body?: string): string {
    return this.push({ kind: 'info', title, body, ttlMs: DEFAULT_TTL_MS });
  }

  warning(title: string, body?: string): string {
    return this.push({ kind: 'warning', title, body, ttlMs: DEFAULT_TTL_MS * 1.5 });
  }

  dismiss(id: string) {
    this.clearTimer(id);
    this.toasts = this.toasts.filter((t) => t.id !== id);
  }

  /** Dismiss the most recently added toast — bound to global ESC. */
  dismissLatest() {
    const latest = this.toasts[this.toasts.length - 1];
    if (latest) this.dismiss(latest.id);
  }

  clear() {
    for (const id of this.timers.keys()) this.clearTimer(id);
    this.toasts = [];
  }

  private clearTimer(id: string) {
    const handle = this.timers.get(id);
    if (handle != null) {
      clearTimeout(handle);
      this.timers.delete(id);
    }
  }
}

export const toast = new ToastStore();
