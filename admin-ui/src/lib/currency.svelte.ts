/**
 * The tenant's accounting currency — the denomination every budget cap, spend
 * aggregate and freshly-written audit total is expressed in.
 *
 * It is module-level rune state because the money formatters read it as their
 * default: any render that formats money re-renders when the layout's settings
 * fetch resolves, so a dashboard rendered before then does not keep the wrong
 * symbol.
 *
 * Two invariants:
 * - It is written only in the browser — by the console and portal layouts
 *   (from an effect) and by the accounting settings section once it has read
 *   or saved the setting — so the value stays at its default during SSR
 *   (module state is shared across requests on the server; a load-time write
 *   would leak one tenant's currency into another's render).
 * - A stored figure carries its OWN currency — an audit row records what the
 *   ledger said when it was written, which the setting can no longer restate.
 *   Render those with the row's `cost_currency`, never this value.
 */

/** Denomination assumed before the tenant's setting is known. */
const DEFAULT_CURRENCY = 'USD';

let accounting = $state(DEFAULT_CURRENCY);

/** The tenant's accounting currency (ISO 4217). Reactive: reading it inside a
 *  component's render subscribes that render to later changes. */
export function accountingCurrency(): string {
  return accounting;
}

/** Adopt a currency for every figure the console reports in tenant money.
 *  A blank/absent code falls back to the default rather than blanking symbols. */
export function setAccountingCurrency(code: string | null | undefined): void {
  accounting = code?.trim().toUpperCase() || DEFAULT_CURRENCY;
}
