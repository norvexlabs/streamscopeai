import type { components } from '#lib/generated/api-types.js';

/** A canonical content block — the protocol-agnostic vocabulary (`text`,
 *  `image`, `audio`, `document`, `file`, `stripped`, `unknown`, …) every wire
 *  format normalizes into, straight from the spec. Rendered by
 *  `ContentBlocks.svelte`, which falls through to raw JSON for a variant it
 *  doesn't know, so a new one is additive and never disappears from the UI. */
export type ContentBlock = components['schemas']['DomainContentBlock'];
