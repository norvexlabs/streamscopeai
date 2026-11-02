/**
 * The PATCH body for a catalog entry edited in the form. Only what the
 * operator changed is sent, so a field nobody touched keeps whatever another
 * writer stored meanwhile.
 *
 * A number emptied in the form is sent as `null`, clearing it back to unknown.
 * A capability box is two-state where the stored value is three-state: ticking
 * one claims `true`; unticking one that was `true` claims `false` — the operator
 * said "no", which an unknown would let another provider's entry overrule. A
 * box left alone sends nothing, so an unknown stays unknown.
 */
import type { components } from './generated/api-types';

type CatalogEntry = components['schemas']['CatalogEntry'];
type UpdateCatalogEntry = components['schemas']['UpdateCatalogEntry'];

export const CATALOG_CAPABILITIES = [
  'supports_vision',
  'supports_reasoning',
  'supports_function_calling',
  'supports_caching',
  'supports_audio_input',
  'supports_audio_output',
  'supports_video_input',
  'supports_pdf_input',
  'supports_response_schema',
  'supports_system_messages',
] as const;

const CATALOG_NUMBERS = ['context_window', 'max_output_tokens', 'output_vector_size'] as const;

export type CatalogForm = {
  model_type: string;
  context_window: number | undefined;
  max_output_tokens: number | undefined;
  output_vector_size: number | undefined;
} & Record<(typeof CATALOG_CAPABILITIES)[number], boolean>;

/** A number input left empty (or cleared to 0/NaN) holds no value. */
function formNumber(v: number | undefined): number | null {
  return typeof v === 'number' && Number.isFinite(v) && v > 0 ? v : null;
}

export function catalogPatch(entry: CatalogEntry, form: CatalogForm): UpdateCatalogEntry {
  const body: UpdateCatalogEntry = {};
  if (form.model_type && form.model_type !== (entry.model_type ?? '')) {
    body.model_type = form.model_type;
  }
  for (const key of CATALOG_NUMBERS) {
    const next = formNumber(form[key]);
    if (next !== (entry[key] ?? null)) body[key] = next;
  }
  for (const key of CATALOG_CAPABILITIES) {
    const was = entry[key] === true;
    if (form[key] !== was) body[key] = form[key];
  }
  return body;
}
