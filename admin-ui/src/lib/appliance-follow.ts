/**
 * What the Appliance page tells the operator about what happened on the
 * appliance, and how it holds a job's log.
 *
 * The host daemon keeps a journal of what happens — a job started, ended or
 * lost, a reboot scheduled or cancelled, a boot started or judged by the health
 * gate, the install finished or failed — written by the daemon and the gate
 * themselves, kept across daemon restarts and reboots. The page takes the
 * journal's cursor from the status, then reads its snapshot (the job, then the
 * status) and follows the journal from the cursor: every fact it states is an
 * entry, never something inferred from two snapshots.
 *
 * Pure and free of Svelte, so every notice is asserted directly.
 */
import type { components } from '#lib/generated/api-types.js';

export type ApplianceEvent = components['schemas']['ApplianceEvent'];
export type ApplianceJob = components['schemas']['ApplianceJob'];
export type HostVersion = components['schemas']['HostVersion'];

/** A release as the operator reads it; the revision only when it is not the first. */
export function release(v: HostVersion | null | undefined): string {
	if (!v) return '—';
	return v.revision > 1 ? `${v.version} (revision ${v.revision})` : v.version;
}

/** Two releases are one when version and revision match; an absent one never matches. */
export function sameVersion(a: HostVersion | null | undefined, b: HostVersion | null | undefined): boolean {
	return !!a && !!b && a.version === b.version && a.revision === b.revision;
}

const JOB_NAMES: Record<string, string> = {
	upgrade: 'The upgrade',
	rollback: 'The rollback',
	backup: 'The backup',
	'backup-verify': 'The backup test',
};

/** A job's name in a sentence. */
export function jobName(kind: string | null | undefined): string {
	return JOB_NAMES[kind ?? ''] ?? `The ${kind || 'job'}`;
}

export interface Notice {
	tone: 'success' | 'error' | 'warning';
	text: string;
}

/**
 * What the operator is told about journal entries the page had not seen, in
 * order. Entries that only start something (a job, a reboot) say nothing: the
 * snapshot read after them shows it.
 */
export function noticesFor(events: ApplianceEvent[]): Notice[] {
	const out: Notice[] = [];
	for (const e of events) {
		const n = noticeFor(e);
		if (n) out.push(n);
	}
	return out;
}

function noticeFor(e: ApplianceEvent): Notice | null {
	switch (e.kind) {
		case 'job.ended': {
			const name = jobName(e.job_kind);
			if (e.state === 'failed') return { tone: 'error', text: `${name} failed: ${e.error || 'no reason given'}` };
			// An entry kept by its head only says nothing it cannot back.
			if (e.state !== 'done') return null;
			// The entry carries the reboot the job scheduled; a reboot that then
			// fails is its own entry (`reboot.cancelled`).
			const reboots = !!e.reboot;
			switch (e.job_kind) {
				case 'upgrade':
					return {
						tone: 'success',
						text: reboots
							? 'Update written — the appliance is restarting to run it.'
							: 'Update written — restart the appliance to run it.',
					};
				case 'rollback':
					return {
						tone: 'success',
						text: reboots
							? 'Rollback written — the appliance is restarting into it.'
							: 'Rollback written — restart the appliance to run it.',
					};
				case 'backup-verify':
					return { tone: 'success', text: e.result || `${e.target || 'The destination'} is reachable and writable.` };
				default:
					return { tone: 'success', text: `${name} finished.` };
			}
		}
		case 'job.lost':
			return {
				tone: 'error',
				text: `${e.job_kind ? jobName(e.job_kind) : 'A job'} did not finish${e.reason ? `: ${e.reason}` : ''}.`,
			};
		case 'reboot.cancelled': {
			const what = e.action === 'poweroff' ? 'power-off' : e.action === 'reboot' ? 'restart' : 'restart or power-off';
			return { tone: 'error', text: `The scheduled ${what} did not happen${e.reason ? `: ${e.reason}` : ''}.` };
		}
		case 'boot.started':
			return {
				tone: 'success',
				text: e.release
					? `The appliance is back — running ${release(e.release)}${e.fallback ? ' (its fallback system)' : ''}.`
					: 'The appliance is back.',
			};
		case 'boot.judged': {
			// Off trial the gate judges a boot nobody upgraded: nothing to tell; a
			// verdict it does not know, nothing it can back.
			if (!e.on_trial) return null;
			const which = e.release ? release(e.release) : 'The new version';
			const why = e.reason ? ` (${e.reason})` : '';
			if (e.verdict === 'healthy') return { tone: 'success', text: `${which} passed its health check and is kept.` };
			if (e.verdict === 'went_back')
				return { tone: 'error', text: `${which} did not come up healthy${why}: the appliance goes back to the previous version.` };
			if (e.verdict === 'kept_unhealthy')
				return {
					tone: 'warning',
					text: `${which} did not come up healthy${why} and keeps running${e.kept ? `: ${e.kept}` : ''}.`,
				};
			return null;
		}
		case 'unreadable':
			return { tone: 'warning', text: 'An entry of the appliance journal could not be read: see the appliance events.' };
		case 'install.failed':
			return {
				tone: 'error',
				text: `${e.release ? `The install of ${release(e.release)}` : 'The install'} failed${e.reason ? `: ${e.reason}` : ''}.`,
			};
		default:
			return null;
	}
}

/** The most log lines held: the daemon itself keeps at most twice its 2000. */
export const MAX_LOG_LINES = 4000;

/** Two reads are of one job when the daemon started it at the same time. */
export function sameJob(a: ApplianceJob | null | undefined, b: ApplianceJob | null | undefined): boolean {
	return !!a?.started && !!b?.started && a.started === b.started;
}

/** The log line to ask the held job from: after the lines held. */
export function jobSince(held: ApplianceJob | null): number {
	return held?.started ? held.log_total : 0;
}

/** The lines of a job read from its start that the page keeps: its last ones. */
export function wholeLog(job: ApplianceJob): string[] {
	return (job.log ?? []).slice(-MAX_LOG_LINES);
}

/** The whole log of a job read from `since`, onto the `held` job's `log`; null
 *  when it must be read again from its start: the read is of another job, or
 *  the daemon no longer held the lines from `since` (its answer starts later). */
export function mergeLog(held: ApplianceJob | null, log: string[], job: ApplianceJob, since: number): string[] | null {
	if (since === 0) return wholeLog(job);
	const lines = job.log ?? [];
	const contiguous = job.log_total - lines.length === since;
	return sameJob(held, job) && contiguous ? [...log, ...lines].slice(-MAX_LOG_LINES) : null;
}

export const OFFLINE_BACKOFF_AFTER_MS = 15 * 60 * 1000;

/** How long to wait before asking again in a state that is not following:
 *  often at first, every minute once it has lasted. */
function retryAfter(since: number, now: number): number {
	return now - since > OFFLINE_BACKOFF_AFTER_MS ? 60_000 : 4000;
}

/** How long a throttled page waits before asking again. */
export const THROTTLED_WAIT_MS = 15_000;

/** A status read the follower makes when the journal did not answer, or when it
 *  holds no cursor yet. */
type StatusRead =
	| { kind: 'answered'; events: number | null; eventsError: string | null; rebootPending: boolean }
	| { kind: 'failed'; httpStatus: number; code: string | null; reason: string };

/** What the page knows of the appliance through its journal — one value,
 *  written only by `follow`, from which every notice above the tabs is derived. */
type Watch =
	/** The journal is read from the cursor. */
	| { kind: 'following' }
	/** The appliance answers, its journal does not: said; the actions stay. */
	| { kind: 'journal'; reason: string }
	/** Nothing answers: waited out; the actions held. */
	| { kind: 'down'; reason: string }
	/** The appliance's host service answers, with an error: waited out; the
	 *  actions held; never called lost contact. */
	| { kind: 'faulty'; reason: string }
	/** The console throttles the page's reads: waited out, the rest untouched. */
	| { kind: 'throttled'; reason: string }
	/** The console refused, or cannot read the answer: waiting does not mend
	 *  it; following stops until the viewer asks again. */
	| { kind: 'stopped'; reason: string };

export interface FollowState {
	watch: Watch;
	/** The journal entry the page has told; null before the status gave one. */
	cursor: number | null;
	/** When the page stopped following (the backoff clock of the whole time
	 *  away, whatever states it went through); null while following. */
	since: number | null;
	/** Events reads that failed in a row while the status answered. */
	eventsFailures: number;
	/** The status read under way was asked because an events read failed. */
	afterEventsFailure: boolean;
	/** The page waited out a state that may have changed the appliance (down,
	 *  faulty, journal) since it last followed — kept through a throttle, so
	 *  coming back through one still reads the whole page again. */
	wasAway: boolean;
	/** The journal told of a reboot or power-off on its way (a job's end that
	 *  carries one, or its own entry), not yet told to have happened or been
	 *  cancelled: an outage now is the restart, never "lost contact". */
	rebootComing: boolean;
	/** The last of those failures' reason. */
	eventsReason: string;
}

export const START: FollowState = {
	watch: { kind: 'following' },
	cursor: null,
	since: null,
	eventsFailures: 0,
	afterEventsFailure: false,
	wasAway: false,
	rebootComing: false,
	eventsReason: '',
};

/** One thing the follower learned. */
export type FollowInput =
	/** The journal answered (admin-api's `next` already applied the client rule). */
	| { kind: 'events'; events: ApplianceEvent[]; next: number; truncated: boolean; elapsedMs: number }
	/** The journal did not answer. */
	| { kind: 'events-failed'; httpStatus: number; code: string | null; reason: string }
	/** The status read the follower made instead. */
	| { kind: 'status'; read: StatusRead }
	/** A status another reader made gave the journal's cursor first. */
	| { kind: 'cursor'; cursor: number }
	/** The viewer asked to follow again (the header's refresh). */
	| { kind: 'resume' }
	/** The page itself failed while following: following stops. */
	| { kind: 'crashed'; reason: string };

export interface FollowStep {
	state: FollowState;
	notices: Notice[];
	/** What the page reads again: nothing, the job and the status, or all of it. */
	reload: 'none' | 'snapshot' | 'page';
	/** The backup status too (a backup job started, ended or was lost); part of
	 *  a page read already. */
	backup?: boolean;
	/** What the follower does next, after `waitMs`. */
	next: 'poll' | 'probe' | 'stop';
	waitMs: number;
}

/** A failed read the follower waits out — no answer, a 5xx, a timeout, a
 *  throttle — as against one that waiting does not mend: a refusal, an answer
 *  the console cannot decode, the host refusing the console's credential. */
function waitsOut(httpStatus: number, code: string | null | undefined): boolean {
	if (code === 'host_daemon_bad_response' || code === 'host_daemon_refused') return false;
	return httpStatus >= 500 || httpStatus === 408 || httpStatus === 429 || code === 'network_unreachable';
}

/** The appliance's state from a failed read: what waiting out means for it. */
function failedWatch(httpStatus: number, code: string | null, reason: string): Watch {
	if (httpStatus === 429) return { kind: 'throttled', reason };
	if (!waitsOut(httpStatus, code)) return { kind: 'stopped', reason };
	// The host service answered, with an error it does not forward: not lost.
	if (code === 'host_daemon_error') return { kind: 'faulty', reason };
	return { kind: 'down', reason };
}

/** A reboot on its way, carried through every transition: only evidence
 *  changes it. An entry tells it (a job's end that carries a reboot, a reboot
 *  scheduled) or settles it (a boot started, a reboot cancelled); a status
 *  answering settles it too — its `reboot_pending` is the daemon's own "a
 *  reboot is scheduled", which the daemon claims before it journals the job's
 *  end, so a status without one means the reboot happened, was cancelled, or
 *  was lost with a restarted daemon. */
type Boot = Pick<FollowState, 'rebootComing'>;

function bootOf(s: FollowState): Boot {
	return { rebootComing: s.rebootComing };
}

function bootAfterEvents(b: Boot, events: ApplianceEvent[]): Boot {
	let coming = b.rebootComing;
	for (const e of events) {
		if (e.kind === 'reboot.scheduled' || (e.kind === 'job.ended' && e.reboot)) coming = true;
		else if (e.kind === 'boot.started' || e.kind === 'reboot.cancelled') coming = false;
	}
	return { rebootComing: coming };
}

function bootAfterStatus(b: Boot, rebootPending: boolean): Boot {
	return { rebootComing: b.rebootComing && rebootPending };
}

/** Consecutive events failures, the status answering meanwhile, before the
 *  page says the journal is not read: one is a blip, two are a state. */
export const EVENTS_FAILURES_TOLD = 2;

/** Move the follower on by one input. Pure: the page performs the step. */
export function follow(s: FollowState, input: FollowInput, now: number): FollowStep {
	// One backoff clock for the whole time away from following: an outage that
	// moves between kinds (down, faulty, journal, a throttle between them) still
	// backs off. It starts again only once the page follows again.
	const away = (w: Watch, next: FollowStep['next'], extra: Partial<FollowState> = {}): FollowStep => {
		const since = s.since ?? now;
		const waitMs = w.kind === 'stopped' ? 0 : w.kind === 'throttled' ? THROTTLED_WAIT_MS : retryAfter(since, now);
		const wasAway = s.wasAway || w.kind === 'down' || w.kind === 'faulty' || w.kind === 'journal';
		return { state: { ...s, ...extra, since, watch: w, wasAway }, notices: [], reload: 'none', next, waitMs };
	};
	switch (input.kind) {
		case 'events': {
			const moved = input.next !== s.cursor;
			// Only entries past the cursor are new — all of them after a truncation,
			// whose journal may have started again below it.
			const fresh =
				input.truncated || s.cursor === null ? input.events : input.events.filter((e) => e.seq > (s.cursor ?? 0));
			const kinds = fresh.map((e) => e.kind);
			// Back from a state that may have changed the appliance — a throttle
			// alone changed nothing and must not trigger a burst.
			const back = s.wasAway;
			const reload: FollowStep['reload'] =
				input.truncated || back || kinds.some((k) => k.startsWith('boot.') || k.startsWith('install.'))
					? 'page'
					: fresh.length
						? 'snapshot'
						: 'none';
			return {
				// A truncated answer may have dropped the entry that settled a reboot:
				// the status read after it says what is now.
				state: { ...START, ...bootAfterEvents(bootOf(s), fresh), cursor: input.next },
				notices: noticesFor(fresh),
				reload,
				backup: reload !== 'page' && fresh.some((e) => e.kind.startsWith('job.') && e.job_kind === 'backup'),
				next: 'poll',
				// An answer that came back at once and moved nothing (a daemon that
				// ignores `wait`) is not asked again at once.
				waitMs: !moved && input.elapsedMs < 1000 ? 4000 : 0,
			};
		}
		case 'events-failed': {
			const w = failedWatch(input.httpStatus, input.code, input.reason);
			if (w.kind === 'stopped') return away(w, 'stop');
			// The console throttling the journal's read throttles a probe too.
			if (w.kind === 'throttled') return away(w, 'poll');
			// Whether the appliance answers is the status's to say.
			return {
				state: { ...s, eventsReason: input.reason, afterEventsFailure: true },
				notices: [],
				reload: 'none',
				next: 'probe',
				waitMs: 0,
			};
		}
		case 'cursor':
			if (s.cursor !== null) return { state: s, notices: [], reload: 'none', next: 'poll', waitMs: 0 };
			return { state: { ...s, cursor: input.cursor }, notices: [], reload: 'none', next: 'poll', waitMs: 0 };
		case 'crashed':
			return {
				state: {
					...START,
					cursor: s.cursor,
					...bootOf(s),
					wasAway: s.wasAway,
					watch: { kind: 'stopped', reason: input.reason },
					since: now,
				},
				notices: [],
				reload: 'none',
				next: 'stop',
				waitMs: 0,
			};
		case 'resume':
			if (s.watch.kind !== 'stopped') return { state: s, notices: [], reload: 'none', next: s.cursor === null ? 'probe' : 'poll', waitMs: 0 };
			return {
				state: { ...START, ...bootOf(s), cursor: s.cursor, wasAway: s.wasAway },
				notices: [],
				reload: 'none',
				next: s.cursor === null ? 'probe' : 'poll',
				waitMs: 0,
			};
		case 'status': {
			const r = input.read;
			// A stop lasts until the viewer asks to follow again (`resume`): no
			// status read the page made meanwhile lifts it, answered or failed.
			if (s.watch.kind === 'stopped') {
				const kept = r.kind === 'answered' ? bootAfterStatus(bootOf(s), r.rebootPending) : bootOf(s);
				return { state: { ...s, ...kept }, notices: [], reload: 'none', next: 'stop', waitMs: 0 };
			}
			if (r.kind === 'failed') {
				const w = failedWatch(r.httpStatus, r.code, r.reason);
				// A throttle says nothing about the journal: its count stays.
				if (w.kind === 'throttled') return away(w, 'probe');
				return away(w, w.kind === 'stopped' ? 'stop' : 'probe', { eventsFailures: 0, afterEventsFailure: false });
			}
			// What the status says of the boot, whatever else it says.
			const boot = bootAfterStatus(bootOf(s), r.rebootPending);

			if (r.events === null) {
				return away({ kind: 'journal', reason: r.eventsError || 'the event journal cannot be read' }, 'probe', {
					...boot,
					eventsFailures: 0,
					afterEventsFailure: false,
				});
			}
			const back = s.wasAway;
			if (s.cursor === null) {
				return {
					state: { ...START, ...boot, cursor: r.events },
					notices: [],
					reload: 'page',
					next: 'poll',
					waitMs: 0,
				};
			}
			if (!s.afterEventsFailure) {
				// A status read the page asked for (a snapshot) says nothing of a
				// journal whose own reads failed: that state stands.
				if (s.watch.kind === 'journal' && s.eventsFailures >= EVENTS_FAILURES_TOLD) {
					return { state: { ...s, ...boot }, notices: [], reload: 'none', next: 'poll', waitMs: 0 };
				}
				return {
					state: { ...START, ...boot, cursor: s.cursor },
					notices: [],
					reload: back ? 'page' : 'none',
					next: 'poll',
					waitMs: 0,
				};
			}
			// The status reads its journal; the journal's own read failed.
			const failures = s.eventsFailures + 1;
			if (failures >= EVENTS_FAILURES_TOLD) {
				return away({ kind: 'journal', reason: s.eventsReason || 'the event journal does not answer' }, 'poll', {
					...boot,
					eventsFailures: failures,
					afterEventsFailure: false,
				});
			}
			return {
				state: {
					...s,
					...boot,
					watch: { kind: 'following' },
					since: null,
					eventsFailures: failures,
					afterEventsFailure: false,
					wasAway: false,
				},
				notices: [],
				reload: back ? 'page' : 'none',
				next: 'poll',
				waitMs: 4000,
			};
		}
	}
}
