/**
 * What a view shows for ONE key (a profile id): the key it is showing, and the
 * content read for it. Each `show` is a new visit, numbered; an answer that
 * lands for an earlier visit — a read or a save issued before the view moved
 * on, to another key or back to this one — is dropped, so a change is never
 * computed from one visit's content and written under another.
 */
export class KeyedContent<T> {
	#key = $state<string | null>(null);
	#value = $state<T | null>(null);
	// Not reactive: only compared by the answers it numbers.
	#visit = 0;

	/** The key shown; `null` before the first `show`. */
	get key(): string | null {
		return this.#key;
	}

	/** The content of the key shown; `null` until it lands (and after a move). */
	get value(): T | null {
		return this.#value;
	}

	/** The current visit's number — what a request captures before it awaits. */
	get visit(): number {
		return this.#visit;
	}

	/** Move to `key`: whatever was shown is gone until this visit's content
	 *  lands. Returns the new visit's number. */
	show(key: string): number {
		this.#key = key;
		this.#value = null;
		return ++this.#visit;
	}

	/** Whether `visit` is still the current one — what a caller checks before
	 *  it acts on an answer that carries no content. */
	isCurrent(visit: number): boolean {
		return visit === this.#visit && this.#key !== null;
	}

	/** Land `value`, read or saved under `visit`. Dropped (`false`) when the
	 *  view has moved on since. */
	land(visit: number, value: T | null): boolean {
		if (!this.isCurrent(visit)) return false;
		this.#value = value;
		return true;
	}
}
