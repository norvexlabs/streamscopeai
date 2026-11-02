import { describe, expect, it } from 'vitest';
import { singleFlight, type SingleFlight } from '#lib/singleFlight.js';

/**
 * The transition table for the exclusion runner. Its failure mode is the one
 * that already shipped as "the workspace filter is stuck on all": two loads
 * overlap, the slower earlier one settles last, and its stale result overwrites
 * the corrected one. Nothing throws and nothing logs — the page simply shows
 * the wrong scope.
 *
 * States are (running, pending). The transitions:
 *   idle          + call  → runs `first` immediately
 *   running       + call  → sets pending, returns WITHOUT running
 *   running       + N calls → still exactly ONE trailing run, not N
 *   first settles + pending → runs `trailing` (not `first` again)
 *   any throw            → releases, so the next call still runs
 */

/** A promise plus its resolver, so a test can hold a task open deliberately. */
function deferred() {
	let resolve!: () => void;
	let reject!: (e: Error) => void;
	const promise = new Promise<void>((res, rej) => {
		resolve = res;
		reject = rej;
	});
	return { promise, resolve, reject };
}

describe('singleFlight', () => {
	it('runs the first task immediately when idle', async () => {
		const log: string[] = [];
		const run = singleFlight(() => void log.push('trailing'));
		await run(() => void log.push('first'));
		expect(log).toEqual(['first']);
	});

	it('never runs two tasks concurrently', async () => {
		const gate = deferred();
		let concurrent = 0;
		let maxConcurrent = 0;
		const task = async () => {
			concurrent += 1;
			maxConcurrent = Math.max(maxConcurrent, concurrent);
			await gate.promise;
			concurrent -= 1;
		};
		const run = singleFlight(task);
		const first = run(task);
		void run(task); // arrives mid-flight
		gate.resolve();
		await first;
		expect(maxConcurrent).toBe(1);
	});

	it('coalesces many mid-flight triggers into exactly one trailing run', async () => {
		const gate = deferred();
		let trailingRuns = 0;
		const run = singleFlight(() => {
			trailingRuns += 1;
		});
		const first = run(() => gate.promise);
		void run(() => {});
		void run(() => {});
		void run(() => {});
		gate.resolve();
		await first;
		expect(trailingRuns).toBe(1);
	});

	it('runs the trailing task, not the first one again', async () => {
		const gate = deferred();
		const log: string[] = [];
		const run = singleFlight(() => void log.push('trailing'));
		const first = run(async () => {
			log.push('first');
			await gate.promise;
		});
		void run(() => void log.push('should-not-run'));
		gate.resolve();
		await first;
		expect(log).toEqual(['first', 'trailing']);
	});

	it('starts the trailing run only after the first settles', async () => {
		const gate = deferred();
		const log: string[] = [];
		const run = singleFlight(() => void log.push('trailing-start'));
		const first = run(async () => {
			await gate.promise;
			log.push('first-end');
		});
		void run(() => {});
		gate.resolve();
		await first;
		expect(log).toEqual(['first-end', 'trailing-start']);
	});

	it('releases the lock when the first task throws', async () => {
		// A failed load must not wedge the page into never loading again.
		const run = singleFlight(() => {});
		await expect(
			run(() => Promise.reject(new Error('boom'))),
		).rejects.toThrow('boom');
		const log: string[] = [];
		await run(() => void log.push('ran'));
		expect(log).toEqual(['ran']);
	});

	it('releases the lock when the trailing task throws', async () => {
		const gate = deferred();
		const run = singleFlight(() => Promise.reject(new Error('trailing boom')));
		const first = run(() => gate.promise);
		void run(() => {});
		gate.resolve();
		await expect(first).rejects.toThrow('trailing boom');
		const log: string[] = [];
		await run(() => void log.push('ran'));
		expect(log).toEqual(['ran']);
	});

	it('schedules a further trailing run when a trigger arrives DURING one', async () => {
		// The drain is a loop, not a single follow-up: a signal landing while the
		// trailing run is itself in flight has to be honoured too, or the last
		// change before things settle is the one silently dropped. Every other
		// case here exercises only the loop's first iteration.
		const gate = deferred();
		let trailingRuns = 0;
		let run!: SingleFlight;
		const trailing = () => {
			trailingRuns += 1;
			if (trailingRuns === 1) void run(() => {}); // arrives mid-trailing
		};
		run = singleFlight(trailing);
		const first = run(() => gate.promise);
		void run(() => {}); // schedules the first trailing run
		gate.resolve();
		await first;
		expect(trailingRuns).toBe(2);
	});

	it('runs every non-overlapping call — the positive control', async () => {
		// Without this, a runner that dropped everything after the first call
		// would satisfy each coalescing assertion above.
		const log: string[] = [];
		const run = singleFlight(() => void log.push('trailing'));
		await run(() => void log.push('a'));
		await run(() => void log.push('b'));
		await run(() => void log.push('c'));
		expect(log).toEqual(['a', 'b', 'c']);
	});

	it('still runs a trigger that arrived during a first task that throws', async () => {
		// A scope change landing while a refresh load fails must still load
		// the new scope; the failure is reported to the caller afterwards.
		const gate = deferred();
		let trailingRuns = 0;
		const run = singleFlight(() => {
			trailingRuns += 1;
		});
		const first = run(() => gate.promise);
		void run(() => {});
		gate.reject(new Error('boom'));
		await expect(first).rejects.toThrow('boom');
		expect(trailingRuns).toBe(1);
		// Nothing is left pending: the next call runs exactly once.
		const log: string[] = [];
		await run(() => void log.push('next'));
		expect(log).toEqual(['next']);
		expect(trailingRuns).toBe(1);
	});
});
