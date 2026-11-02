import { describe, expect, it } from 'vitest';
import { CATALOG_CAPABILITIES, catalogPatch, type CatalogForm } from './catalog-patch';
import type { components } from './generated/api-types';

type CatalogEntry = components['schemas']['CatalogEntry'];

const caps = (v: boolean | null) =>
  Object.fromEntries(CATALOG_CAPABILITIES.map((k) => [k, v])) as Record<(typeof CATALOG_CAPABILITIES)[number], boolean | null>;

const entry = {
  id: 'e1',
  provider: 'openai',
  model: 'm',
  model_type: 'text',
  context_window: 8192,
  max_output_tokens: null,
  output_vector_size: null,
  ...caps(null),
  supports_vision: true,
  supports_reasoning: false,
} as unknown as CatalogEntry;

/** The form exactly as `openEditCatalog` fills it from `entry`. */
const untouched = (): CatalogForm => ({
  model_type: 'text',
  context_window: 8192,
  max_output_tokens: undefined,
  output_vector_size: undefined,
  ...(caps(false) as Record<(typeof CATALOG_CAPABILITIES)[number], boolean>),
  supports_vision: true,
});

describe('catalogPatch', () => {
  it('sends nothing for a form nobody changed', () => {
    expect(catalogPatch(entry, untouched())).toEqual({});
  });

  it('clears an emptied number and sets a new one', () => {
    const form = { ...untouched(), context_window: undefined, max_output_tokens: 4096 };
    expect(catalogPatch(entry, form)).toEqual({ context_window: null, max_output_tokens: 4096 });
  });

  it('treats 0 as empty, so an emptied field never stores 0', () => {
    expect(catalogPatch(entry, { ...untouched(), context_window: 0 })).toEqual({ context_window: null });
  });

  it('claims false when a ticked box is unticked, and true when an unknown one is ticked', () => {
    const form = { ...untouched(), supports_vision: false, supports_caching: true };
    expect(catalogPatch(entry, form)).toEqual({ supports_vision: false, supports_caching: true });
  });

  it('leaves a stored false or unknown alone when its box stays unticked', () => {
    const body = catalogPatch(entry, untouched());
    expect(body).not.toHaveProperty('supports_reasoning');
    expect(body).not.toHaveProperty('supports_caching');
  });

  it('never clears the model type', () => {
    expect(catalogPatch(entry, { ...untouched(), model_type: '' })).toEqual({});
    expect(catalogPatch(entry, { ...untouched(), model_type: 'embedding' })).toEqual({ model_type: 'embedding' });
  });
});
