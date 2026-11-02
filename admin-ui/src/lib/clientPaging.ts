/**
 * The window onto a list held in full and paged in the browser — one the page
 * loads whole because it filters it client-side, but must not render whole.
 *
 * The offset is clamped into the list: a list that shrank under its page (a
 * narrower filter, a deleted row) lands on its last page rather than on an empty
 * one, and an empty list sits at 0. `hasMore` says a page follows this one.
 */
export function clientPage(
	total: number,
	offset: number,
	limit: number,
): { offset: number; hasMore: boolean } {
	const lastPageOffset = total > 0 ? Math.floor((total - 1) / limit) * limit : 0;
	const clamped = Math.min(Math.max(0, offset), lastPageOffset);
	return { offset: clamped, hasMore: clamped + limit < total };
}

/** The offset of the page that holds the row at `index`. */
export function pageStartFor(index: number, limit: number): number {
	return Math.floor(Math.max(0, index) / limit) * limit;
}
