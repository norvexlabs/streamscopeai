/**
 * The rate map — one model's price list, and the shape the price editor works in.
 *
 * A price list is one provider's quote in one currency, so it is inherited,
 * overridden and reset as a single atom: there is no per-unit inheritance.
 * The two states that look alike and are not:
 *   - no `rates` at all  → the row inherits the catalog's map whole;
 *   - `rates` with an empty `units` → the operator says NO PRICE IS KNOWN,
 *     which bills a floor of zero *and* flags the request. It does not fall
 *     through to the catalog, and it is not the same as a rate of `0` (free).
 */
import { formatPrice } from '#lib/formatters.js';
import type { components } from '#lib/generated/api-types.js';

export type Rates = components['schemas']['Rates'];
export type Rate = components['schemas']['Rate'];

/** The tiered arm of `Rate` — a base price plus step thresholds. */
export type TieredRate = Exclude<Rate, number>;

/** Rate maps quote token units per million and everything else per single unit. */
type UnitScale = 'per_million' | 'per_unit';

interface RateUnit {
  /** Pricing-unit wire name — the key inside `Rates.units`. */
  key: string;
  /** Field label in the editor. */
  label: string;
}

export interface RateUnitGroup {
  /** Scale every unit in the group is quoted at, spelled out so a bare number
   *  in an input is never ambiguous about what it buys. */
  label: string;
  scale: UnitScale;
  units: RateUnit[];
}

/**
 * Every unit the gateway prices, grouped by the scale its rate is quoted at.
 * Keep in step with the pricing unit vocabulary: a unit missing here is
 * invisible in the editor, and a rate map that carries it would still bill.
 */
export const RATE_UNIT_GROUPS: RateUnitGroup[] = [
  {
    label: 'Per 1M tokens',
    scale: 'per_million',
    units: [
      { key: 'input_token', label: 'Input' },
      { key: 'output_token', label: 'Output' },
      { key: 'cache_write_token', label: 'Cache write' },
      { key: 'cache_write_1h_token', label: 'Cache write (1 hour)' },
      { key: 'cache_read_token', label: 'Cache read' },
      { key: 'audio_input_token', label: 'Audio input' },
      { key: 'audio_output_token', label: 'Audio output' },
    ],
  },
  {
    // Its own group rather than another row above: the rate is quoted per
    // million like a token rate, but what is counted is not a token, and a
    // character price sitting under a "tokens" heading reads as a typo.
    label: 'Per 1M characters',
    scale: 'per_million',
    // "Input characters", not "Input text": this label also names the line in an
    // audit row's per-unit breakdown, beside "Input" and "Output" tokens, where
    // anything less explicit reads as a second name for the token count.
    units: [{ key: 'input_character', label: 'Input characters' }],
  },
  {
    label: 'Per unit',
    scale: 'per_unit',
    units: [
      { key: 'image_output', label: 'Per image' },
      { key: 'audio_second', label: 'Per audio second' },
      { key: 'video_second', label: 'Per video second' },
    ],
  },
];

/** Flat list of every known unit, in group order. */
const RATE_UNITS: RateUnit[] = RATE_UNIT_GROUPS.flatMap((g) => g.units);

/** Short label for a unit wire name, for compact summaries and audit lines.
 *  An unrecognised key (a rate map written by a newer build) renders its own
 *  wire name rather than vanishing. */
export function rateUnitLabel(key: string): string {
  return RATE_UNITS.find((u) => u.key === key)?.label ?? key.replace(/_/g, ' ');
}

/** The scale a unit's rate is quoted at, for the "/1M" suffix. */
function rateUnitScale(key: string): UnitScale {
  return RATE_UNIT_GROUPS.find((g) => g.units.some((u) => u.key === key))?.scale ?? 'per_unit';
}

/** Narrow a `Rate` to its tiered arm. A flat rate is a bare number. */
export function isTiered(rate: Rate | undefined): rate is TieredRate {
  return typeof rate === 'object' && rate !== null;
}

/** The price applied below the first threshold, whether or not it is tiered. */
function baseRate(rate: Rate): number {
  return isTiered(rate) ? rate.rate : rate;
}

/** One-line price summary for a dense table cell.
 *
 * Returns a plain string, deliberately: the catalog table renders one of these
 * per row and a seeded tenant carries over a thousand rows, so a component per
 * cell would cost a reactive scope and a DOM subtree each — enough to make the
 * gateway page visibly slow to render. Editing a price list is a different
 * surface with a handful of instances; that one is a component.
 *
 * Empty when no price is on file, so the caller can render the "not the same as
 * free" marker instead of a blank cell.
 */
export function formatRatesInline(rates: Rates | null | undefined): string {
  const currency = rates?.currency;
  return rateEntries(rates)
    .map(([unit, rate]) => {
      const suffix = rateUnitScale(unit) === 'per_million' ? '/1M' : '';
      const price = formatPrice(baseRate(rate), currency);
      // A tier is summarised as a range rather than enumerated — the cell has
      // no room, and the full ladder is one click away in the model editor. The
      // top is the highest threshold, not the last entry: the engine selects a
      // tier by `max(above)` and nothing requires the stored list to be sorted,
      // so reading the tail would show the wrong end of the range.
      const top = isTiered(rate)
        ? rate.tiers.reduce<TieredRate['tiers'][number] | undefined>(
            (hi, t) => (!hi || t.above > hi.above ? t : hi),
            undefined,
          )
        : undefined;
      const value = top ? `${price}\u2013${formatPrice(top.rate, currency)}` : price;
      return `${rateUnitLabel(unit)} ${value}${suffix}`;
    })
    .join('  ·  ');
}

/** True when no price is on file — billed at a floor of zero AND flagged,
 *  which is deliberately distinct from a rate map whose units are all `0`. */
export function ratesAreEmpty(rates: Rates | null | undefined): boolean {
  return !rates || Object.keys(rates.units ?? {}).length === 0;
}

/** Ordered `[unit, rate]` pairs — known units first in editor order, then any
 *  unit this build doesn't recognise, so nothing priced is hidden. */
function rateEntries(rates: Rates | null | undefined): [string, Rate][] {
  const units = rates?.units ?? {};
  const known = RATE_UNITS.map((u) => u.key).filter((k) => units[k] !== undefined);
  const rest = Object.keys(units)
    .filter((k) => !known.includes(k))
    .sort();
  return [...known, ...rest].map((k) => [k, units[k]]);
}

/** Compact threshold label for a tier boundary: 128000 → "128K". */
export function formatThreshold(above: number): string {
  if (above >= 1_000_000) return `${+(above / 1_000_000).toFixed(2)}M`;
  if (above >= 1_000) return `${+(above / 1_000).toFixed(2)}K`;
  return String(above);
}

// ---------------------------------------------------------------------------
// Editor form model
// ---------------------------------------------------------------------------

/**
 * The rate map as the editor holds it while being typed into.
 *
 * Flat prices and tiered ones live in separate maps on purpose. A number input
 * can only carry a scalar, so a tiered rate parked in the same map would be
 * flattened by the first keystroke in a box that looked ordinary — here it sits
 * in `tiers`, rendered read-only, and moves to `units` only when the operator
 * explicitly asks for a flat rate.
 */
export interface RatesForm {
  /** `false` = the row inherits the catalog's map whole. */
  overriding: boolean;
  currency: string;
  /** Editable flat prices. `undefined` means the unit has NO price — which
   *  bills zero and flags, and is not the same as a price of `0`. */
  units: Record<string, number | undefined>;
  /** Tiered rates carried through untouched unless explicitly flattened. */
  tiers: Record<string, TieredRate>;
}

/** Load an override into the editor. `null`/`undefined` = inheriting. */
export function ratesToForm(
  rates: Rates | null | undefined,
  fallbackCurrency = 'USD',
): RatesForm {
  const form: RatesForm = {
    overriding: rates != null,
    currency: rates?.currency || fallbackCurrency,
    units: {},
    tiers: {},
  };
  for (const [unit, rate] of Object.entries(rates?.units ?? {})) {
    if (isTiered(rate)) form.tiers[unit] = rate;
    else form.units[unit] = rate;
  }
  return form;
}

/** True when a slot in `RatesForm.units` actually carries a price. Emptying a
 *  number input leaves `null` there, not `undefined` — both mean "no price",
 *  and a check for one alone would ship a `null` rate to the API. */
export function isPriced(value: number | null | undefined): value is number {
  return typeof value === 'number' && !Number.isNaN(value);
}

/** The override the form describes, or `null` while it inherits. */
export function formToRates(form: RatesForm): Rates | null {
  if (!form.overriding) return null;
  const units: Record<string, Rate> = {};
  for (const [unit, value] of Object.entries(form.units)) {
    if (isPriced(value)) units[unit] = value;
  }
  for (const [unit, tiered] of Object.entries(form.tiers)) units[unit] = tiered;
  return { currency: form.currency.toUpperCase() || 'USD', units };
}

/** Stable string for change detection — a save must send the price list only
 *  when the operator actually edited it, or an untouched inherited map would be
 *  re-pinned as an override the next time anything else on the row is saved. */
export function ratesSignature(rates: Rates | null | undefined): string {
  if (rates == null) return 'inherit';
  const units = rateEntries(rates)
    .map(([unit, rate]) =>
      isTiered(rate)
        ? `${unit}=${rate.rate}[${rate.tiers.map((t) => `${t.above}:${t.rate}`).join(',')}]`
        : `${unit}=${rate}`,
    )
    .sort()
    .join('|');
  return `${(rates.currency ?? '').toUpperCase()}#${units}`;
}
