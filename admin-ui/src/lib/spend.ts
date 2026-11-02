/**
 * Rendering helpers for a spend breakdown — what a window cost, per pricing
 * unit.
 *
 * There is deliberately no "input vs output" split here. A second of audio is
 * an input unit for transcription and an output unit for speech, and which side
 * a cached token or a generated image falls on is a presentation choice rather
 * than a fact. The units the provider actually charged for are the honest
 * decomposition, so they are what gets shown.
 */
import type { SpendBreakdown } from '#lib/api-types.js';
import { formatCost, type Spend } from '#lib/formatters.js';
import * as m from '#lib/paraglide/messages.js';

/** Add spend figures that each state their own currency.
 *
 *  Returns `null` the moment two figures that actually hold money disagree, or
 *  one of them is itself absent — in either case the parts are in more than one
 *  denomination and their sum would be in none of them.
 *
 *  A **zero** part is not such a disagreement and must not be allowed to become
 *  one: a key with no traffic in the window is reported as a zero in whatever
 *  currency the tenant keeps its books in *today*, which after a currency
 *  change is not the currency the window's real spend was booked in. Counting
 *  it would make one idle key turn a perfectly statable total into "mixed".
 *
 *  An empty list, or one holding nothing but zeroes, is not that case either:
 *  nothing was spent, and the zero is reported in `fallback`. */
export function sumSpend(
  parts: readonly (Spend | null | undefined)[],
  fallback: string,
): Spend | null {
  let currency: string | null = null;
  let amount = 0;
  for (const part of parts) {
    if (!part) return null;
    if (part.amount === 0) continue;
    if (currency !== null && currency !== part.currency) return null;
    currency = part.currency;
    amount += part.amount;
  }
  return { amount, currency: currency ?? fallback };
}

/** Short label for a pricing unit. An unrecognised key — a unit a newer
 *  gateway priced and this build has never heard of — renders as itself rather
 *  than disappearing from a total it contributed to. */
function spendUnitLabel(unit: string): string {
  switch (unit) {
    case 'input_token':
      return m.spend_unit_input_token();
    case 'output_token':
      return m.spend_unit_output_token();
    case 'cache_write_token':
      return m.spend_unit_cache_write_token();
    case 'cache_write_1h_token':
      return m.spend_unit_cache_write_1h_token();
    case 'cache_read_token':
      return m.spend_unit_cache_read_token();
    case 'audio_input_token':
      return m.spend_unit_audio_input_token();
    case 'audio_output_token':
      return m.spend_unit_audio_output_token();
    case 'input_character':
      return m.spend_unit_input_character();
    case 'image_output':
      return m.spend_unit_image_output();
    case 'audio_second':
      return m.spend_unit_audio_second();
    case 'video_second':
      return m.spend_unit_video_second();
    default:
      return unit;
  }
}

/** One-line per-unit decomposition of a window's spend, largest first:
 *  `$3.40 out · $1.20 in · $0.02 cache read`.
 *
 *  Returns `undefined` when there is nothing to decompose, so a caller can drop
 *  the line rather than print an empty one. The gateway's own embedding calls
 *  (a semantic cache alias buys one per exact miss) are a line of their own:
 *  they price a different model, and leaving them out would make the parts stop
 *  adding up to the whole. */
export function spendUnitSummary(spend: SpendBreakdown | null | undefined): string | undefined {
  if (!spend) return undefined;
  const parts = [...spend.units]
    .sort((a, b) => b.cost - a.cost)
    .filter((u) => u.cost > 0)
    .map((u) => `${formatCost(u.cost, spend.currency)} ${spendUnitLabel(u.unit)}`);
  if (spend.embedding > 0) {
    parts.push(`${formatCost(spend.embedding, spend.currency)} ${m.spend_unit_embedding()}`);
  }
  return parts.length > 0 ? parts.join(' · ') : undefined;
}

/** The amount a ranked spend list may draw as a bar, measured against the
 *  list's leader.
 *
 *  A bar compares two amounts, so it is drawn only for a figure in the same
 *  currency as `leader` (the first stated figure of a list the API ranked by
 *  its spend rule); a figure in another currency, or one with no single figure at all,
 *  draws none rather than a length measured in the wrong unit. */
export function amountBeside(spend: Spend | null | undefined, leader: Spend | null | undefined): number {
  if (!spend || !leader || spend.currency !== leader.currency) return 0;
  return Math.max(0, spend.amount);
}
