// The traffic-log search minimum, as the API enforces it (400
// `search_term_too_short`): the browse views never send a shorter term, and
// say why instead. Counted like the server counts: characters (code points)
// of the trimmed term.

/** Keep equal to the server's minimum. */
export const MIN_SEARCH_CHARS = 3;

/** A term present (not blank) but shorter than `MIN_SEARCH_CHARS`. */
export function searchTooShort(term: string | null | undefined): boolean {
  const t = (term ?? '').trim();
  return t.length > 0 && [...t].length < MIN_SEARCH_CHARS;
}
