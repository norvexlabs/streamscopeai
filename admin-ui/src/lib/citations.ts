/**
 * How a cited source is shown (`CitationList`): the link it may open, and
 * where in the source the quote is, in the unit its kind names.
 */
import type { Citation } from '#lib/api-types.js';

/** Where a quote is: a 1-based, inclusive range in the unit of its kind. */
export interface CitationLocation {
  unit: 'chars' | 'pages' | 'blocks';
  start: number;
  end: number;
}

/**
 * The quote's place, read as the spec states each kind: characters and blocks
 * as a 0-based start, pages as a 1-based one, every end exclusive.
 * `null` when the kind names no range, or the range does not read as one.
 */
export function citationLocation(c: Citation): CitationLocation | null {
  if (c.start == null || c.end == null) return null;
  let loc: CitationLocation;
  switch (c.kind) {
    case 'char_location':
      loc = { unit: 'chars', start: c.start + 1, end: c.end };
      break;
    case 'page_location':
      loc = { unit: 'pages', start: c.start, end: c.end - 1 };
      break;
    case 'content_block_location':
    case 'search_result_location':
      loc = { unit: 'blocks', start: c.start + 1, end: c.end };
      break;
    default:
      return null;
  }
  return loc.start >= 1 && loc.end >= loc.start ? loc : null;
}

/**
 * The page a citation may open: its URL when it is an absolute `http` or
 * `https` one, never another scheme — the URL is text an upstream or a client
 * wrote. `null` otherwise (a search result's `source` that is no such URL is
 * shown as text, by its title).
 */
export function citationLink(c: Citation): string | null {
  if (!c.url) return null;
  try {
    const url = new URL(c.url);
    return url.protocol === 'http:' || url.protocol === 'https:' ? url.href : null;
  } catch {
    return null;
  }
}
