import { describe, expect, it } from 'vitest';
import { ApplianceReader, LOG_EVERY_MS, type ReaderIO } from '#lib/appliance-reader.js';
import { THROTTLED_WAIT_MS, type FollowInput } from '#lib/appliance-follow.js';

const flush = async () => {
	for (let i = 0; i < 50; i++) await Promise.resolve();
};

const answered = (events: number | null = 7): FollowInput => ({
	kind: 'status',
	read: { kind: 'answered', events, eventsError: events === null ? 'busy' : null, rebootPending: false },
});

/** A daemon that answers what each test scripts; a long poll or a wait ends
 *  only when the reader interrupts it (or the test answers it). */
function fake(over: Partial<ReaderIO> = {}) {
	const calls: string[] = [];
	let clock = 0;
	const pendingPolls: Array<(v: FollowInput | null) => void> = [];
	const io: ReaderIO = {
		events: (cursor, wait, signal) => {
			calls.push(`events:${cursor}:${wait}`);
			return new Promise((resolve) => {
				pendingPolls.push(resolve);
				signal.addEventListener('abort', () => resolve(null));
			});
		},
		status: async () => {
			calls.push('status');
			return answered();
		},
		job: async () => {
			calls.push('job');
			return { ok: true, ended: false, kind: null };
		},
		rest: () => calls.push('rest'),
		backupStatus: () => calls.push('backup-status'),
		jobRunning: () => false,
		notice: () => {},
		state: () => {},
		now: () => clock,
		sleep: (_ms, signal) => new Promise((resolve) => signal.addEventListener('abort', () => resolve())),
		...over,
	};
	return {
		io,
		calls,
		advance: (ms: number) => {
			clock += ms;
		},
		answerPoll: (v: FollowInput) => pendingPolls.shift()?.(v),
	};
}

describe('the one reader', () => {
	it('a first page read takes the cursor before the job, then the status, then the rest, and then follows', async () => {
		const f = fake();
		const r = new ApplianceReader(f.io);
		await r.ask('page');
		expect(f.calls.slice(0, 4)).toEqual(['status', 'job', 'status', 'rest']);
		await flush();
		expect(f.calls.at(-1)).toBe('events:7:25');
		r.destroy();
	});

	it('a request interrupts the long poll and is answered once read', async () => {
		const f = fake();
		const r = new ApplianceReader(f.io);
		await r.ask('page');
		await flush();
		f.calls.length = 0;
		await r.ask('snapshot');
		expect(f.calls.slice(0, 2)).toEqual(['job', 'status']);
		await flush();
		expect(f.calls.at(-1)).toBe('events:7:25');
		r.destroy();
	});

	it('whoever asked is answered when the snapshot fails, and the reader stops', async () => {
		let failJob = false;
		const f = fake({
			job: async () => {
				if (failJob) throw new Error('unreadable answer');
				return { ok: true, ended: false, kind: null };
			},
		});
		const r = new ApplianceReader(f.io);
		await r.ask('page');
		failJob = true;
		await r.ask('snapshot');
		await flush();
		expect(r.state.watch).toEqual({ kind: 'stopped', reason: 'unreadable answer' });
		// A request while stopped is still answered, and resume follows again.
		failJob = false;
		r.resume();
		await r.ask('snapshot');
		expect(r.state.watch.kind).toBe('following');
		r.destroy();
	});

	it('destroying answers whoever waits and reads nothing more', async () => {
		const f = fake({ status: () => new Promise(() => {}) });
		const r = new ApplianceReader(f.io);
		const asked = r.ask('page');
		await flush();
		r.destroy();
		await asked;
		expect(await Promise.race([r.ask('page').then(() => 'answered'), flush().then(() => 'pending')])).toBe('answered');
	});

	it('a running job is read between short polls, its log not held back by the follower\'s wait', async () => {
		let running = true;
		const sleeps: number[] = [];
		const f = fake({
			jobRunning: () => running,
			sleep: (ms, signal) => {
				sleeps.push(ms);
				return new Promise((resolve) => signal.addEventListener('abort', () => resolve()));
			},
		});
		const r = new ApplianceReader(f.io);
		await r.ask('page');
		await flush();
		// Short polls while a job runs.
		expect(f.calls.at(-1)).toBe('events:7:2');
		// An answer that came back at once and moved nothing asks the follower to
		// wait 4 s: the reader waits only until the log is due.
		f.answerPoll({ kind: 'events', events: [], next: 7, truncated: false, elapsedMs: 10 });
		await flush();
		expect(sleeps.at(-1)).toBeLessThanOrEqual(LOG_EVERY_MS);
		running = false;
		r.destroy();
	});

	it('a request made as a stopped reader ends is still read', async () => {
		const f = fake({ events: async () => ({ kind: 'events-failed', httpStatus: 404, code: 'appliance_unavailable', reason: 'off' }) });
		const r = new ApplianceReader(f.io);
		await r.ask('page');
		await flush();
		expect(r.state.watch.kind).toBe('stopped');
		f.calls.length = 0;
		await r.ask('snapshot');
		expect(f.calls.slice(0, 2)).toEqual(['job', 'status']);
		r.destroy();
	});

	it('resume follows again on its own', async () => {
		let refuse = true;
		const f = fake({
			events: (cursor, wait, signal) => {
				f.calls.push(`events:${cursor}:${wait}`);
				if (refuse) return Promise.resolve({ kind: 'events-failed', httpStatus: 404, code: 'x', reason: 'off' });
				return new Promise((resolve) => signal.addEventListener('abort', () => resolve(null)));
			},
		});
		const r = new ApplianceReader(f.io);
		await r.ask('page');
		await flush();
		expect(r.state.watch.kind).toBe('stopped');
		refuse = false;
		f.calls.length = 0;
		r.resume();
		await flush();
		expect(f.calls).toContain('events:7:25');
		r.destroy();
	});

	it('a page read after time away is not read twice: what the snapshot asked for itself it reads', async () => {
		let down = true;
		const f = fake({
			status: async () => {
				f.calls.push('status');
				return down
					? { kind: 'status', read: { kind: 'failed', httpStatus: 503, code: 'network_unreachable', reason: 'x' } }
					: answered();
			},
		});
		const r = new ApplianceReader(f.io);
		await r.ask('page');
		await flush();
		expect(r.state.watch.kind).toBe('down');
		down = false;
		f.calls.length = 0;
		await r.ask('snapshot');
		await flush();
		// One job read, one status read, the rest once: no second snapshot.
		expect(f.calls.filter((c) => c === 'job')).toHaveLength(1);
		expect(f.calls.filter((c) => c === 'rest')).toHaveLength(1);
		r.destroy();
	});

	it("the wait a snapshot's last status asks for is waited before the next read, and only that one", async () => {
		const throttled: FollowInput = { kind: 'status', read: { kind: 'failed', httpStatus: 429, code: 'rate_limit_exceeded', reason: 'x' } };
		// Each scenario scripts the snapshot's two status reads: the cursor, then the status after the job.
		const run = async (reads: FollowInput[]) => {
			const sleeps: number[] = [];
			const f = fake({
				status: async () => {
					f.calls.push('status');
					return reads.shift() ?? answered();
				},
				sleep: (ms, signal) => {
					sleeps.push(ms);
					f.calls.push(`sleep:${ms}`);
					return new Promise((resolve) => signal.addEventListener('abort', () => resolve()));
				},
			});
			const r = new ApplianceReader(f.io);
			await r.ask('page');
			await flush();
			r.destroy();
			return { sleeps, calls: f.calls };
		};
		// Throttled on the last read: the loop waits it out before reading again.
		const last = await run([answered(), throttled]);
		expect(last.calls.slice(0, 5)).toEqual(['status', 'job', 'status', 'rest', `sleep:${THROTTLED_WAIT_MS}`]);
		// Throttled only on the first: the last read answered, so nothing is waited.
		const first = await run([throttled, answered()]);
		expect(first.sleeps).not.toContain(THROTTLED_WAIT_MS);
	});
});
