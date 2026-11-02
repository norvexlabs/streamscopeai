import { clientPage } from '#lib/clientPaging.js';

/** A list held in full and paged in the browser: its current length. */
export type ClientList = { count: () => number };

/**
 * Shared pagination state for list endpoints that return `OffsetPage<T>` or
 * `TotalPage<T>`. Hold one per list; hand it to the `<Pagination>` component
 * and call `absorbOffset(response)` / `absorbTotal(response)` after each fetch.
 *
 * Constructed with `list`, it pages a list held in full instead: `total` is the
 * list's length and `offset` / `hasMore` are clamped into it (`clientPage`), so a
 * list that shrinks never shows an empty page. The page renders
 * `items.slice(offset, offset + limit)` and calls `reset()` when its filter
 * changes. In that mode the total and `hasMore` are the list's, never set: a
 * write to either, or an `absorb*` call, is refused and logged as the misuse it
 * is.
 */
export class Pagination {
	limit = $state(50);
	#offset = $state(0);
	#hasMore = $state(false);
	#total = $state<number | null>(null);
	/** The last page's search stopped at its scan budget (`OffsetPage.scan_cut`):
	 * more matches may exist past what it scanned. */
	scanCut = $state(false);
	readonly #list: ClientList | null;
	#window = $derived.by(() => (this.#list ? clientPage(this.#list.count(), this.#offset, this.limit) : null));

	constructor(opts?: { limit?: number; list?: ClientList }) {
		if (opts?.limit && opts.limit > 0) this.limit = opts.limit;
		this.#list = opts?.list ?? null;
	}

	/** In list mode, a write the list decides is refused, loudly. */
	#refusedInListMode(what: string): boolean {
		if (!this.#list) return false;
		console.error(`Pagination: ${what} is the list's own on a client-side pager — not set`);
		return true;
	}

	get offset(): number {
		return this.#window ? this.#window.offset : this.#offset;
	}
	set offset(value: number) {
		this.#offset = this.#list ? clientPage(this.#list.count(), value, this.limit).offset : value;
	}

	get hasMore(): boolean {
		return this.#window ? this.#window.hasMore : this.#hasMore;
	}
	set hasMore(value: boolean) {
		if (this.#refusedInListMode('hasMore')) return;
		this.#hasMore = value;
	}

	/** `null` for OffsetPage (unknown total); populated after `absorbTotal`. */
	get total(): number | null {
		return this.#list ? this.#list.count() : this.#total;
	}
	set total(value: number | null) {
		if (this.#refusedInListMode('total')) return;
		this.#total = value;
	}

	get page(): number {
		return Math.floor(this.offset / this.limit) + 1;
	}

	get pageCount(): number | null {
		if (this.total == null) return null;
		return Math.max(1, Math.ceil(this.total / this.limit));
	}

	goToPage(p: number) {
		const max = this.pageCount ?? Number.POSITIVE_INFINITY;
		const clamped = Math.min(Math.max(1, p), max);
		this.offset = (clamped - 1) * this.limit;
	}

	next() {
		if (this.hasMore) this.offset += this.limit;
	}

	prev() {
		this.offset = Math.max(0, this.offset - this.limit);
	}

	/** Reset to page 1. Call when filters change so stale offsets don't land on empty pages. */
	reset() {
		this.offset = 0;
		if (this.#list) return;
		this.hasMore = false;
		this.total = null;
		this.scanCut = false;
	}

	/** Absorb an `OffsetPage<T>` response; returns the items array for convenience. */
	absorbOffset<T>(
		response: { items?: T[] | null; has_more: boolean; scan_cut?: boolean } | null | undefined,
	): T[] {
		if (this.#refusedInListMode('absorbOffset')) return response?.items ?? [];
		if (!response) {
			this.hasMore = false;
			this.scanCut = false;
			return [];
		}
		this.hasMore = response.has_more;
		this.scanCut = response.scan_cut ?? false;
		this.total = null;
		return response.items ?? [];
	}

	/** Absorb a `TotalPage<T>` response; returns the items array for convenience. */
	absorbTotal<T>(response: { items?: T[] | null; has_more: boolean; total: number } | null | undefined): T[] {
		if (this.#refusedInListMode('absorbTotal')) return response?.items ?? [];
		if (!response) {
			this.hasMore = false;
			this.total = 0;
			return [];
		}
		this.hasMore = response.has_more;
		this.total = response.total;
		return response.items ?? [];
	}
}
