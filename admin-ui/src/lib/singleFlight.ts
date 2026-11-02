/**
 * Run an async task exclusively, coalescing everything triggered while it runs.
 *
 * The shape a page needs: a first load, plus reload signals that can arrive at
 * any time — including *during* the first load. Running those concurrently is
 * not merely wasteful, it is wrong, because a slower earlier load can settle
 * after a faster later one and clobber it with stale data. That is exactly how
 * a workspace filter reverts to "all workspaces" after correcting itself: the
 * heavier unfiltered query lands last.
 *
 * So a trigger arriving mid-flight is not queued and it is not dropped — every
 * such trigger collapses into a SINGLE trailing run that starts once the
 * current one settles. The latest inputs always win, and the number of trailing
 * runs never grows with the number of signals.
 *
 * The runner is deliberately free of any Svelte or SvelteKit import: it is a
 * state machine, and keeping it that way is what lets it be asserted directly
 * instead of through a mounted component.
 */
export type SingleFlight = (first: () => Promise<void> | void) => Promise<void>;

/**
 * Build a runner over `trailing` — the task a coalesced trigger runs. Callers
 * pass the *initial* task per call, so a mount load and a reload can differ
 * while sharing one exclusion.
 */
export function singleFlight(trailing: () => Promise<void> | void): SingleFlight {
	let running = false;
	let pending = false;

	return async function run(first: () => Promise<void> | void): Promise<void> {
		if (running) {
			pending = true;
			return;
		}
		running = true;
		// A task that throws does not end the drain: a trigger that arrived
		// while it ran (a scope change during a failing refresh) still gets its
		// trailing run, or the page keeps showing the previous scope. The first
		// failure is rethrown to this caller once the drain is done.
		let failed = false;
		let failure: unknown;
		try {
			try {
				await first();
			} catch (e) {
				failed = true;
				failure = e;
			}
			while (pending) {
				pending = false;
				try {
					await trailing();
				} catch (e) {
					if (!failed) {
						failed = true;
						failure = e;
					}
				}
			}
		} finally {
			// Released even when a task throws: a load that fails must not wedge
			// the page into never loading again.
			running = false;
		}
		if (failed) throw failure;
	};
}
