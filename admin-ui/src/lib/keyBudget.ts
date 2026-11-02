import { formatAmount, formatCost } from '#lib/formatters.js';

/** Per-key budget payload shared by the create form, mint form, and edit modal. */
export interface KeyBudget {
  daily_budget?: number | null;
  monthly_budget?: number | null;
  budget_mode: string;
}

/**
 * Human-readable per-key budget summary, e.g. "$5/day · $100/mo". Null when the
 * key is uncapped. Shared by every read-only budget chip (admin key card,
 * manager team view, self-service portal list).
 */
export function budgetSummary(
  daily: number | null | undefined,
  monthly: number | null | undefined,
): string | null {
  const parts: string[] = [];
  if (daily != null) parts.push(`${formatCost(daily)}/day`);
  if (monthly != null) parts.push(`${formatCost(monthly)}/mo`);
  return parts.length > 0 ? parts.join(' · ') : null;
}

/**
 * Spend-vs-cap line for a single window, e.g. "$2.10 / $5.00 (42%)". Returns
 * null when the window is uncapped (`cap` blank/0). Shared by every surface that
 * shows live spend next to a budget cap (per-key, per-user override, workspace
 * ceiling). `spent` defaults to 0 — an absent counter means no spend yet.
 */
export function spendVsCap(
  cap: number | null | undefined,
  spent: number | null | undefined,
): string | null {
  if (cap == null || cap <= 0) return null;
  const s = spent ?? 0;
  const pct = Math.round((s / cap) * 100);
  // Exact amounts (not abbreviated) — a spend/cap comparison must stay precise.
  return `${formatAmount(s)} / ${formatAmount(cap)} (${pct}%)`;
}

/**
 * Parse a budget input to a positive number, or null when blank/invalid.
 * Accepts `number` too: Svelte coerces `bind:value` on `type="number"` inputs
 * to a number even when the bound state is typed as string.
 */
function parseCap(v: string | number): number | null {
  const t = String(v).trim();
  if (t === '') return null;
  const n = Number(t);
  return Number.isFinite(n) && n > 0 ? n : null;
}

/**
 * Build a budget payload from the raw form fields. Returns `undefined` when no
 * cap is set (an alert-only mode with no cap is meaningless, so it's dropped) —
 * callers treat `undefined` as "no per-key budget".
 */
export function buildKeyBudget(
  daily: string | number,
  monthly: string | number,
  mode: string,
): KeyBudget | undefined {
  const d = parseCap(daily);
  const m = parseCap(monthly);
  if (d == null && m == null) return undefined;
  return { daily_budget: d, monthly_budget: m, budget_mode: mode };
}
