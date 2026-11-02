import { describe, expect, it } from 'vitest';
import {
	MAX_LOG_LINES,
	OFFLINE_BACKOFF_AFTER_MS,
	jobSince,
	mergeLog,
	wholeLog,
	noticesFor,
	sameJob,
	EVENTS_FAILURES_TOLD,
	follow,
	START,
	THROTTLED_WAIT_MS,
	type FollowInput,
	type FollowState,
	type ApplianceEvent,
	type ApplianceJob,
} from '#lib/appliance-follow.js';

const v = (version: string, revision = 1) => ({ version, revision });
const JOB = '2026-10-14T09:00:00.000000001Z';

let seq = 0;
function ev(kind: string, over: Partial<ApplianceEvent> = {}): ApplianceEvent {
	return { seq: ++seq, at: '2026-10-14T09:00:00Z', kind, ...over };
}

function job(over: Partial<ApplianceJob> = {}): ApplianceJob {
	return { started: JOB, kind: 'upgrade', state: 'running', target: 'v1.1', error: null, log: [], log_total: 0, ...over };
}

describe('what the operator is told, from the journal', () => {
	it('a job whose end carries its reboot says the appliance restarts; one without says to restart', () => {
		const rebooting = ev('job.ended', { job: JOB, job_kind: 'upgrade', state: 'done', reboot: { action: 'reboot', drain_secs: 30 } });
		expect(noticesFor([rebooting])).toEqual([
			{ tone: 'success', text: 'Update written — the appliance is restarting to run it.' },
		]);
		const written = ev('job.ended', { job: JOB, job_kind: 'upgrade', state: 'done' });
		expect(noticesFor([written])).toEqual([{ tone: 'success', text: 'Update written — restart the appliance to run it.' }]);
		const rollback = ev('job.ended', { job: JOB, job_kind: 'rollback', state: 'done', reboot: { action: 'reboot', drain_secs: 0 } });
		expect(noticesFor([rollback])[0].text).toBe('Rollback written — the appliance is restarting into it.');
		// A reboot that then fails is told by its own entry, with the job that scheduled it.
		expect(noticesFor([ev('reboot.cancelled', { action: 'reboot', by: JOB, reason: 'systemctl reboot failed: x' })])[0].tone).toBe('error');
	});

	it('a failed job says why, whatever its kind', () => {
		const failed = ev('job.ended', { job: JOB, job_kind: 'backup-verify', state: 'failed', error: 'writing b:x/probe: 403' });
		expect(noticesFor([failed])).toEqual([{ tone: 'error', text: 'The backup test failed: writing b:x/probe: 403' }]);
	});

	it('the backup test that passed names its destination', () => {
		const done = ev('job.ended', { job: JOB, job_kind: 'backup-verify', target: 'b:bucket/x', state: 'done' });
		expect(noticesFor([done])).toEqual([{ tone: 'success', text: 'b:bucket/x is reachable and writable.' }]);
		// The daemon's own verdict, when it gives one.
		const said = ev('job.ended', { job: JOB, job_kind: 'backup-verify', state: 'done', result: 'b:bucket/x is reachable: probe written' });
		expect(noticesFor([said])[0].text).toBe('b:bucket/x is reachable: probe written');
	});

	it('a lost job, a cancelled reboot and a failed install each say why', () => {
		expect(noticesFor([ev('job.lost', { job_kind: 'backup', reason: 'the system rebooted' })])[0]).toEqual({
			tone: 'error',
			text: 'The backup did not finish: the system rebooted.',
		});
		expect(noticesFor([ev('reboot.cancelled', { action: 'poweroff', reason: 'systemctl poweroff failed' })])[0].text).toBe(
			'The scheduled power-off did not happen: systemctl poweroff failed.',
		);
		expect(noticesFor([ev('install.failed', { release: v('1.1'), reason: 'the provision hook failed' })])[0].text).toBe(
			'The install of 1.1 failed: the provision hook failed.',
		);
	});

	it('a boot says what runs; the gate says whether an upgrade on trial was kept', () => {
		expect(noticesFor([ev('boot.started', { release: v('1.1', 2), fallback: false })])[0].text).toBe(
			'The appliance is back — running 1.1 (revision 2).',
		);
		expect(noticesFor([ev('boot.started', { release: v('1.0'), fallback: true })])[0].text).toContain('fallback');
		const judged = (verdict: string) =>
			ev('boot.judged', { release: v('1.1'), on_trial: true, verdict, reason: 'not ready', kept: 'the database moved on' });
		expect(noticesFor([judged('healthy')])[0]).toEqual({ tone: 'success', text: '1.1 passed its health check and is kept.' });
		expect(noticesFor([judged('went_back')])[0].tone).toBe('error');
		expect(noticesFor([judged('kept_unhealthy')])[0]).toEqual({
			tone: 'warning',
			text: '1.1 did not come up healthy (not ready) and keeps running: the database moved on.',
		});
		// Off trial nobody upgraded: nothing to tell.
		expect(noticesFor([ev('boot.judged', { on_trial: false, verdict: 'healthy' })])).toEqual([]);
	});

	it('a job end kept by its head only (no state) is no success', () => {
		expect(noticesFor([ev('job.ended', { job: JOB })])).toEqual([]);
	});

	it('an entry missing its details says only what it carries', () => {
		expect(noticesFor([ev('boot.started')])[0].text).toBe('The appliance is back.');
		expect(noticesFor([ev('reboot.cancelled')])[0].text).toBe('The scheduled restart or power-off did not happen.');
		expect(noticesFor([ev('install.failed')])[0].text).toBe('The install failed.');
		expect(noticesFor([ev('job.lost')])[0].text).toBe('A job did not finish.');
		expect(noticesFor([ev('boot.judged', { on_trial: true })])).toEqual([]);
		expect(noticesFor([ev('boot.judged', { on_trial: true, verdict: 'deferred' })])).toEqual([]);
		expect(noticesFor([ev('boot.judged', { on_trial: true, verdict: 'healthy' })])[0].text).toBe(
			'The new version passed its health check and is kept.',
		);
	});

	it('entries that only start something, and kinds this side does not know, say nothing', () => {
		expect(
			noticesFor([
				ev('job.started', { job: JOB, job_kind: 'upgrade' }),
				ev('reboot.scheduled', { action: 'reboot' }),
				ev('install.finished', { release: v('1.1') }),
				ev('something.new'),
			]),
		).toEqual([]);
	});
});

describe('the job log', () => {
	const running = job({ log: ['a', 'b'], log_total: 2 });

	it('the held job appends its new lines', () => {
		expect(jobSince(running)).toBe(2);
		expect(mergeLog(running, ['a', 'b'], job({ log: ['c'], log_total: 3 }), 2)).toEqual(['a', 'b', 'c']);
	});

	it('another job, or lines the daemon no longer holds, make the log read again', () => {
		expect(mergeLog(running, ['a', 'b'], job({ started: '2026-10-14T10:00:00Z', log: ['x'], log_total: 1 }), 2)).toBeNull();
		// Asked from line 2, it answers from line 2100 (it dropped the ones between).
		expect(mergeLog(running, ['a', 'b'], job({ log: ['z'], log_total: 2101 }), 2)).toBeNull();
	});

	it('a job read from its start keeps its last lines, the same as a merge from line 0', () => {
		const long = job({ log: Array.from({ length: MAX_LOG_LINES + 5 }, (_, i) => `l${i}`), log_total: MAX_LOG_LINES + 5 });
		expect(wholeLog(long)).toEqual(long.log?.slice(5));
		expect(mergeLog(running, ['a', 'b'], long, 0)).toEqual(wholeLog(long));
		expect(wholeLog(job({ log: undefined, log_total: 0 }))).toEqual([]);
	});

	it('a job never started has no identity', () => {
		const idle = job({ started: null, kind: null, state: 'idle' });
		expect(sameJob(idle, idle)).toBe(false);
		expect(jobSince(idle)).toBe(0);
	});

	it('is capped at the daemon bound, keeping the latest lines', () => {
		const lines = Array.from({ length: MAX_LOG_LINES + 10 }, (_, i) => `l${i}`);
		const whole = mergeLog(null, [], job({ log: lines, log_total: lines.length }), 0);
		expect(whole).toHaveLength(MAX_LOG_LINES);
		expect(whole?.at(-1)).toBe(`l${MAX_LOG_LINES + 9}`);
	});
});

describe('the follower', () => {
	const at = (cursor: number | null, watch: FollowState['watch'] = { kind: 'following' }, extra: Partial<FollowState> = {}): FollowState => ({
		...START,
		cursor,
		watch,
		since: watch.kind === 'following' ? null : 0,
		// As a real transition into a state that may change the appliance sets it.
		wasAway: watch.kind === 'down' || watch.kind === 'faulty' || watch.kind === 'journal',
		...extra,
	});
	const answered = (events: number | null, eventsError: string | null = null, rebootPending = false): FollowInput => ({
		kind: 'status',
		read: { kind: 'answered', events, eventsError, rebootPending },
	});
	const failed = (httpStatus: number, code: string | null, reason = 'x'): FollowInput => ({
		kind: 'status',
		read: { kind: 'failed', httpStatus, code, reason },
	});

	it('takes its cursor from the status, even 0, and reads the page', () => {
		const r = follow(START, answered(0), 0);
		expect(r).toMatchObject({ state: { cursor: 0, watch: { kind: 'following' } }, reload: 'page', next: 'poll', waitMs: 0 });
	});

	it('an answer moves the cursor to `next`, tells its entries and reads again what they changed', () => {
		const ended = ev('job.ended', { job: JOB, job_kind: 'upgrade', state: 'done' });
		const r = follow(at(5), { kind: 'events', events: [ended], next: 9, truncated: false, elapsedMs: 30 }, 0);
		expect(r.state.cursor).toBe(9);
		expect(r.notices).toHaveLength(1);
		expect(r.reload).toBe('snapshot');
		expect(follow(at(5), { kind: 'events', events: [ev('boot.started')], next: 9, truncated: false, elapsedMs: 30 }, 0).reload).toBe('page');
		expect(follow(at(5), { kind: 'events', events: [], next: 9, truncated: true, elapsedMs: 30 }, 0).reload).toBe('page');
		// Coming back to following reads the page again.
		expect(follow(at(5, { kind: 'down', reason: 'x' }), { kind: 'events', events: [], next: 5, truncated: false, elapsedMs: 9000 }, 0).reload).toBe('page');
	});

	it('an answer that came back at once and moved nothing waits; one that moved does not', () => {
		const still = follow(at(5), { kind: 'events', events: [], next: 5, truncated: false, elapsedMs: 999 }, 0);
		expect(still.waitMs).toBe(4000);
		expect(follow(at(5), { kind: 'events', events: [], next: 5, truncated: false, elapsedMs: 1000 }, 0).waitMs).toBe(0);
		// Entries this side does not know were passed: the cursor moved, no wait.
		expect(follow(at(5), { kind: 'events', events: [], next: 7, truncated: false, elapsedMs: 10 }, 0).waitMs).toBe(0);
		expect(follow(at(5), { kind: 'events', events: [], next: 5, truncated: true, elapsedMs: 10 }, 0).waitMs).toBe(4000);
	});

	it('a failed journal read asks the status; a refusal stops', () => {
		expect(follow(at(5), { kind: 'events-failed', httpStatus: 502, code: 'host_daemon_unreachable', reason: 'r' }, 0)).toMatchObject({
			next: 'probe',
			waitMs: 0,
		});
		for (const [st, code] of [
			[404, 'appliance_unavailable'],
			[502, 'host_daemon_bad_response'],
			[502, 'host_daemon_refused'],
		] as const) {
			expect(follow(at(5), { kind: 'events-failed', httpStatus: st, code, reason: 'no' }, 0)).toMatchObject({
				state: { watch: { kind: 'stopped', reason: 'no' } },
				next: 'stop',
			});
		}
	});

	it('one journal failure while the status reads is a blip; two in a row are said', () => {
		const failedOnce = follow(at(5), { kind: 'events-failed', httpStatus: 502, code: 'host_daemon_unreachable', reason: 'timeout' }, 0);
		const once = follow(failedOnce.state, answered(5), 0);
		expect(once).toMatchObject({ state: { watch: { kind: 'following' }, eventsFailures: 1 }, next: 'poll', waitMs: 4000 });
		expect(once.state.eventsFailures).toBe(EVENTS_FAILURES_TOLD - 1);
		const failedTwice = follow(once.state, { kind: 'events-failed', httpStatus: 502, code: 'host_daemon_unreachable', reason: 'timeout' }, 0);
		const twice = follow(failedTwice.state, answered(5), 0);
		expect(twice.state.watch).toEqual({ kind: 'journal', reason: 'timeout' });
		// The journal answering again clears it.
		const back = follow(twice.state, { kind: 'events', events: [], next: 5, truncated: false, elapsedMs: 25_000 }, 0);
		expect(back.state).toMatchObject({ watch: { kind: 'following' }, eventsFailures: 0 });
	});

	it('an appliance that answers without a cursor cannot read its journal: not an outage', () => {
		expect(follow(at(5), answered(null, 'lock: busy'), 0).state.watch).toEqual({ kind: 'journal', reason: 'lock: busy' });
	});

	it('no answer is down; an answer with an error is faulty; a throttle is neither', () => {
		for (const [st, code] of [
			[503, 'network_unreachable'],
			[502, 'host_daemon_unreachable'],
			[503, 'maintenance_in_progress'],
			[504, null],
			[500, null],
			[408, null],
		] as const) {
			expect(follow(at(5), failed(st, code), 0).state.watch.kind, `${st} ${code}`).toBe('down');
		}
		expect(follow(at(5), failed(502, 'host_daemon_error'), 0).state.watch.kind).toBe('faulty');
		const t = follow(at(5), failed(429, 'rate_limit_exceeded'), 0);
		expect(t).toMatchObject({ state: { watch: { kind: 'throttled' } }, next: 'probe', waitMs: THROTTLED_WAIT_MS });
		// Just below the server-error class, a refusal.
		expect(follow(at(5), failed(499, null), 0)).toMatchObject({ state: { watch: { kind: 'stopped' } }, next: 'stop' });
	});

	it('a status that answers without an events failure before it counts nothing', () => {
		// Back from an outage: the next events blip is the first, not the second.
		const back = follow(at(5, { kind: 'down', reason: 'x' }), answered(5), 0);
		expect(back).toMatchObject({ state: { watch: { kind: 'following' }, eventsFailures: 0 }, reload: 'page', waitMs: 0 });
	});

	it('a throttled journal read is a throttle, not a journal failure; leaving it reads nothing more', () => {
		const t = follow(at(5), { kind: 'events-failed', httpStatus: 429, code: 'rate_limit_exceeded', reason: 'slow' }, 0);
		expect(t).toMatchObject({ state: { watch: { kind: 'throttled' }, eventsFailures: 0 }, next: 'poll', waitMs: THROTTLED_WAIT_MS });
		expect(follow(t.state, answered(5), 0).reload).toBe('none');
		// The usual way out is the journal answering: no burst either.
		expect(follow(t.state, { kind: 'events', events: [], next: 5, truncated: false, elapsedMs: 25_000 }, 0).reload).toBe('none');
		// A throttled probe keeps the journal's failure count.
		const failed1 = follow(at(5), { kind: 'events-failed', httpStatus: 502, code: 'host_daemon_unreachable', reason: 'r' }, 0).state;
		const throttledProbe = follow(failed1, failed(429, 'rate_limit_exceeded'), 0).state;
		expect(throttledProbe.afterEventsFailure).toBe(true);
	});

	it('a stop is not lifted by a failed status read either', () => {
		const stopped = follow(at(5), { kind: 'events-failed', httpStatus: 404, code: 'appliance_unavailable', reason: 'off' }, 0).state;
		expect(follow(stopped, failed(502, 'host_daemon_unreachable'), 1)).toMatchObject({ state: { watch: { kind: 'stopped' } }, next: 'stop' });
	});

	it('entries at or below the cursor are never told twice; after a truncation all are new', () => {
		const old = ev('job.ended', { seq: 5, job: JOB, job_kind: 'backup', state: 'failed', error: 'x' });
		expect(follow(at(5), { kind: 'events', events: [old], next: 5, truncated: false, elapsedMs: 10 }, 0).notices).toEqual([]);
		expect(follow(at(5), { kind: 'events', events: [old], next: 5, truncated: true, elapsedMs: 10 }, 0).notices).toHaveLength(1);
	});

	it('an entry the console could not read is said, never silently passed', () => {
		expect(noticesFor([ev('unreadable')])[0].tone).toBe('warning');
	});

	it('a stop lasts until a resume: a status read meanwhile does not lift it', () => {
		const stopped = follow(at(5), { kind: 'events-failed', httpStatus: 404, code: 'appliance_unavailable', reason: 'off' }, 0).state;
		expect(follow(stopped, answered(5), 1)).toMatchObject({ state: { watch: { kind: 'stopped' } }, next: 'stop' });
	});

	it('the page failing while following stops it, keeping the cursor', () => {
		expect(follow(at(4, { kind: 'down', reason: 'x' }, { eventsFailures: 1 }), { kind: 'crashed', reason: 'boom' }, 9)).toMatchObject({
			state: { watch: { kind: 'stopped', reason: 'boom' }, cursor: 4, eventsFailures: 0, since: 9 },
			next: 'stop',
		});
	});

	it('a cursor another read found, and a resume, go through the follower', () => {
		expect(follow(START, { kind: 'cursor', cursor: 7 }, 0)).toMatchObject({ state: { cursor: 7 }, next: 'poll' });
		expect(follow(at(3), { kind: 'cursor', cursor: 7 }, 0).state.cursor).toBe(3);
		const stopped = at(3, { kind: 'stopped', reason: 'no' });
		expect(follow(stopped, { kind: 'resume' }, 0)).toMatchObject({ state: { watch: { kind: 'following' }, cursor: 3 }, next: 'poll' });
		expect(follow(START, { kind: 'resume' }, 0).next).toBe('probe');
	});

	it('coming back from an outage through a throttle still reads the whole page', () => {
		const down = follow(at(5), failed(503, 'network_unreachable'), 0).state;
		const throttled = follow(down, failed(429, 'rate_limit_exceeded'), 1).state;
		expect(throttled.wasAway).toBe(true);
		expect(follow(throttled, answered(5), 2).reload).toBe('page');
		expect(follow(throttled, { kind: 'events', events: [], next: 5, truncated: false, elapsedMs: 9000 }, 2).reload).toBe('page');
		// A throttle alone changed nothing.
		const onlyThrottled = follow(at(5), failed(429, 'rate_limit_exceeded'), 0).state;
		expect(follow(onlyThrottled, answered(5), 1).reload).toBe('none');
	});

	it('the whole time away from following is one backoff clock; following again restarts it', () => {
		const down = follow(at(5), failed(503, 'network_unreachable'), 1000).state;
		const throttled = follow(down, failed(429, 'rate_limit_exceeded'), 2000).state;
		const journal = follow(throttled, answered(null, 'e'), 1001 + OFFLINE_BACKOFF_AFTER_MS);
		expect(journal.state.since).toBe(1000);
		expect(journal.waitMs).toBe(60_000);
		const back = follow(journal.state, answered(5), 1002 + OFFLINE_BACKOFF_AFTER_MS).state;
		expect(back.since).toBeNull();
		expect(follow(back, failed(503, 'network_unreachable'), 9e9).waitMs).toBe(4000);
	});

	it('a reboot the journal told of lasts while the daemon says one is scheduled, and no longer', () => {
		const told = follow(
			at(5),
			{ kind: 'events', events: [ev('job.ended', { job: JOB, job_kind: 'upgrade', state: 'done', reboot: { action: 'reboot', drain_secs: 30 } })], next: 6, truncated: false, elapsedMs: 30 },
			0,
		).state;
		expect(told.rebootComing).toBe(true);
		// The drain: the status says a reboot is scheduled.
		expect(follow(told, answered(6, null, true), 1).state.rebootComing).toBe(true);
		// Through the outage of the reboot itself.
		const down = follow(told, failed(503, 'network_unreachable'), 2).state;
		expect(down.rebootComing).toBe(true);
		// Any status that says none is scheduled settles it: rebooted, cancelled,
		// or lost with a daemon that restarted — never stuck.
		expect(follow(down, answered(6), 3).state.rebootComing).toBe(false);
		expect(follow(told, answered(6), 3).state.rebootComing).toBe(false);
		// A stop and a resume keep it while nothing settled it.
		const stopped = follow(told, { kind: 'crashed', reason: 'x' }, 0).state;
		expect(follow(stopped, { kind: 'resume' }, 1).state.rebootComing).toBe(true);
	});

	it('a snapshot status does not clear a journal state its own reads established', () => {
		let st = at(5);
		for (let i = 0; i < EVENTS_FAILURES_TOLD; i++) {
			st = follow(st, { kind: 'events-failed', httpStatus: 502, code: 'host_daemon_unreachable', reason: 'r' }, 0).state;
			st = follow(st, answered(5), 0).state;
		}
		expect(st.watch.kind).toBe('journal');
		expect(follow(st, answered(5), 1)).toMatchObject({ state: { watch: { kind: 'journal' } }, reload: 'none' });
	});

	it('a reboot the journal told of is coming until a boot or a cancellation says otherwise', () => {
		const poll = (st: FollowState, events: ReturnType<typeof ev>[]) =>
			follow(st, { kind: 'events', events, next: (st.cursor ?? 0) + events.length, truncated: false, elapsedMs: 30 }, 0).state;
		const told = poll(at(5), [ev('job.ended', { job: JOB, job_kind: 'upgrade', state: 'done', reboot: { action: 'reboot', drain_secs: 30 } })]);
		expect(told.rebootComing).toBe(true);
		// Kept through the outage of the reboot itself.
		const down = follow(told, failed(503, 'network_unreachable'), 1).state;
		expect(down.rebootComing).toBe(true);
		expect(poll(down, [ev('boot.started')]).rebootComing).toBe(false);
		expect(poll(told, [ev('reboot.cancelled')]).rebootComing).toBe(false);
		expect(poll(at(5), [ev('job.ended', { job: JOB, job_kind: 'backup', state: 'done' })]).rebootComing).toBe(false);
	});

	it('a throttle in the middle of an outage keeps its backoff clock', () => {
		const down = follow(at(5), failed(503, 'network_unreachable'), 1000).state;
		const throttled = follow(down, failed(429, 'rate_limit_exceeded'), 2000).state;
		const downAgain = follow(throttled, failed(503, 'network_unreachable'), 1001 + OFFLINE_BACKOFF_AFTER_MS);
		expect(downAgain.state.since).toBe(1000);
		expect(downAgain.waitMs).toBe(60_000);
	});

	it('an outage alternating between no answer and an error keeps one backoff clock', () => {
		const down = follow(at(5), failed(502, 'host_daemon_unreachable'), 1000).state;
		const faulty = follow(down, failed(502, 'host_daemon_error'), 2000).state;
		expect(faulty.since).toBe(1000);
		expect(follow(faulty, failed(502, 'host_daemon_unreachable'), 1001 + OFFLINE_BACKOFF_AFTER_MS).waitMs).toBe(60_000);
	});

	it('a state that lasts backs off, and keeps its start while it lasts', () => {
		const down = follow(at(5), failed(503, 'network_unreachable'), 1000).state;
		expect(down.since).toBe(1000);
		const later = follow(down, failed(503, 'network_unreachable'), 1000 + OFFLINE_BACKOFF_AFTER_MS + 1);
		expect(later.state.since).toBe(1000);
		expect(later.waitMs).toBe(60_000);
		expect(follow(down, failed(503, 'network_unreachable'), 1000 + OFFLINE_BACKOFF_AFTER_MS).waitMs).toBe(4000);
		// Another state away from following keeps the same clock.
		expect(follow(down, answered(null, 'e'), 5000).state.since).toBe(1000);
	});
});
