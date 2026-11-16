import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import type { Citation } from '#lib/api-types.js';
import { citationLink, citationLocation } from './citations.js';

const cite = (c: Partial<Citation>): Citation => ({ kind: 'char_location', cited_text: 'q', ...c });

describe('citationLocation', () => {
  it('reads characters and blocks as 0-based with an exclusive end', () => {
    expect(citationLocation(cite({ kind: 'char_location', start: 0, end: 12 }))).toEqual({ unit: 'chars', start: 1, end: 12 });
    expect(citationLocation(cite({ kind: 'content_block_location', start: 2, end: 3 }))).toEqual({ unit: 'blocks', start: 3, end: 3 });
    expect(citationLocation(cite({ kind: 'search_result_location', start: 0, end: 2 }))).toEqual({ unit: 'blocks', start: 1, end: 2 });
  });

  // The citations guide: "Page numbers are 1-indexed with exclusive end page
  // numbers" — its one-page example is `start_page_number: 1, end_page_number: 2`.
  it('reads pages as 1-based with an exclusive end', () => {
    expect(citationLocation(cite({ kind: 'page_location', start: 1, end: 2 }))).toEqual({ unit: 'pages', start: 1, end: 1 });
    expect(citationLocation(cite({ kind: 'page_location', start: 5, end: 8 }))).toEqual({ unit: 'pages', start: 5, end: 7 });
  });

  it('names no range for a kind without one, a missing bound, or a range that does not read', () => {
    expect(citationLocation(cite({ kind: 'web_search_result_location', start: 0, end: 1 }))).toBeNull();
    expect(citationLocation(cite({ kind: 'char_location', start: 0 }))).toBeNull();
    expect(citationLocation(cite({ kind: 'char_location', start: 5, end: 5 }))).toBeNull();
    expect(citationLocation(cite({ kind: 'page_location', start: 0, end: 1 }))).toBeNull();
    expect(citationLocation(cite({ kind: 'page_location', start: 3, end: 3 }))).toBeNull();
    expect(citationLocation(cite({ kind: 'some_new_kind', start: 0, end: 1 }))).toBeNull();
  });
});

describe('citationLink', () => {
  it('opens an http or https page', () => {
    expect(citationLink(cite({ url: 'https://example.com/a?b=1' }))).toBe('https://example.com/a?b=1');
    expect(citationLink(cite({ url: 'http://example.com/' }))).toBe('http://example.com/');
  });

  it.each(['javascript:alert(1)', 'data:text/html,x', 'JavaScript:alert(1)', 'file:///etc/passwd', 'kb/notes', ''])(
    'never opens %s',
    (url) => {
      expect(citationLink(cite({ url }))).toBeNull();
    },
  );

  it('opens nothing without a url', () => {
    expect(citationLink(cite({}))).toBeNull();
  });
});

describe('citationLink property', () => {
  // The claim: whatever an upstream wrote, a link is only ever an absolute
  // http(s) URL, and the one it returns reads back as itself. Not a claim:
  // that every http(s) string is kept (one `URL` cannot parse is not).
  it('only ever opens an absolute http(s) URL, stable under re-reading', () => {
    const spelled = fc.oneof(
      fc.string(),
      fc.webUrl(),
      fc.tuple(fc.constantFrom('javascript:', 'JaVaScRiPt:', ' javascript:', 'data:', 'file:', 'vbscript:', '\tjavascript:', 'http:', 'https:', 'HTTP://'), fc.string()).map(([a, b]) => a + b),
    );
    fc.assert(
      fc.property(spelled, (url) => {
        const link = citationLink(cite({ url }));
        if (link === null) return true;
        const parsed = new URL(link);
        return (parsed.protocol === 'http:' || parsed.protocol === 'https:') && parsed.href === link && citationLink(cite({ url: link })) === link;
      }),
    );
  });
});
