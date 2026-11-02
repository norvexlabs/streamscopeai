/**
 * The Appliance page's one reader of the job and the status.
 *
 * Every such read is the reader's, one at a time — the journal's long poll, the
 * status probes, the running job's log, and the snapshots a refresh or an action
 * asks for — so no read can land over a newer one, and every status read goes
 * through `follow`, which decides what it means. A request interrupts the long
 * poll or wait in flight and is served before anything else; whoever asked is
 * answered once it is read, and never left waiting: not by a reader that
 * crashed, ended or was destroyed.
 *
 * The reads themselves, the waits and the notices are injected (`ReaderIO`), so
 * every interleaving is asserted directly.
 */
import { follow, START, type FollowInput, type FollowState, type FollowStep, type Notice } from '#lib/appliance-follow.js';

export interface ReaderIO {
	/** The journal after `cursor`, waiting up to `wait` s; null when `signal` ended it. */
	events(cursor: number, wait: number, signal: AbortSignal): Promise<FollowInput | null>;
	/** A status read, applied to the page, as the follower's input. */
	status(): Promise<FollowInput>;
	/** The job (its log from the lines held), applied: whether it answered, and
	 *  whether the job was seen leaving `running`. */
	job(): Promise<{ ok: boolean; ended: boolean; kind: string | null }>;
	/** The rest of the page and the backup status: read beside, never by the reader. */
	rest(): void;
	backupStatus(): void;
	/** Whether a job runs, as last read. */
	jobRunning(): boolean;
	notice(n: Notice): void;
	/** The follower's state changed. */
	state(s: FollowState): void;
	now(): number;
	/** A wait of `ms`, ended early by `signal`. */
	sleep(ms: number, signal: AbortSignal): Promise<void>;
}

/** How often a running job's log is read, and after a failed read. */
export const LOG_EVERY_MS = 2000;
const LOG_RETRY_MS = 10_000;

type Want = 'none' | 'snapshot' | 'page';

export class ApplianceReader {
	#io: ReaderIO;
	#s: FollowState = START;
	#want: Want = 'none';
	#waiters: Array<() => void> = [];
	// Those whose request the snapshot under way serves.
	#serving: Array<() => void> = [];
	#running = false;
	#destroyed = false;
	#wake = new AbortController();
	#action: 'poll' | 'probe' = 'probe';
	#logDue = 0;
	// While a snapshot runs: what its own reads asked for is read by it.
	#inSnapshot = false;
	#alsoRest = false;

	constructor(io: ReaderIO) {
		this.#io = io;
	}

	get state(): FollowState {
		return this.#s;
	}

	/** Ask for a snapshot (the job, then the status) or the whole page, and
	 *  wait until it has been read. */
	ask(kind: 'snapshot' | 'page'): Promise<void> {
		if (this.#destroyed) return Promise.resolve();
		this.#want = kind === 'page' || this.#want === 'page' ? 'page' : 'snapshot';
		const done = new Promise<void>((resolve) => this.#waiters.push(resolve));
		this.#interrupt();
		this.#start();
		return done;
	}

	/** Follow again after a stop (the header's refresh), from a page read; the
	 *  same as asking for one when nothing stopped. */
	resume(): Promise<void> {
		if (this.#s.watch.kind === 'stopped') this.#take({ kind: 'resume' });
		// Following again starts from a fresh read of the page.
		return this.ask('page');
	}

	/** The page is gone: nothing more is read, and whoever waits is answered. */
	destroy() {
		this.#destroyed = true;
		this.#interrupt();
		this.#release();
	}

	#interrupt() {
		this.#wake.abort();
		this.#wake = new AbortController();
	}

	#release() {
		const w = [...this.#serving, ...this.#waiters];
		this.#serving = [];
		this.#waiters = [];
		for (const r of w) r();
	}

	#start() {
		if (this.#running || this.#destroyed) return;
		this.#running = true;
		void this.#loop()
			.catch((e: unknown) => {
				if (!this.#destroyed) this.#take({ kind: 'crashed', reason: e instanceof Error ? e.message : 'the page lost track of it' });
			})
			.finally(() => {
				this.#running = false;
				// A request made as the reader ended — stopped or not — is served by
				// a new one; only then is nobody left waiting.
				if (this.#want !== 'none' && !this.#destroyed) this.#start();
				else this.#release();
			});
	}

	#take(input: FollowInput): FollowStep {
		const step = follow(this.#s, input, this.#io.now());
		this.#s = step.state;
		this.#io.state(this.#s);
		for (const n of step.notices) this.#io.notice(n);
		if (this.#inSnapshot) {
			// The snapshot under way reads the job and the status itself.
			if (step.reload === 'page') this.#alsoRest = true;
		} else if (step.reload === 'page') {
			this.#want = 'page';
		} else if (step.reload === 'snapshot' && this.#want === 'none') {
			this.#want = 'snapshot';
		}
		if (step.backup) this.#io.backupStatus();
		this.#action = step.next === 'probe' ? 'probe' : 'poll';
		return step;
	}

	async #loop() {
		while (!this.#destroyed) {
			if (this.#want !== 'none') {
				const kind = this.#want;
				this.#want = 'none';
				this.#serving = this.#waiters;
				this.#waiters = [];
				let wait = 0;
				try {
					wait = await this.#snapshot(kind);
				} finally {
					const served = this.#serving;
					this.#serving = [];
					for (const r of served) r();
				}
				// The wait the snapshot's own last step asked for (a throttle, a
				// backoff) holds after it too.
				if (wait > 0 && this.#want === 'none' && !this.#destroyed) await this.#io.sleep(wait, this.#wake.signal);
				continue;
			}
			if (this.#s.watch.kind === 'stopped') return;
			const read = this.#s.watch.kind === 'following' || this.#s.watch.kind === 'journal';
			const running = read && this.#io.jobRunning();
			if (running && this.#io.now() >= this.#logDue) {
				const r = await this.#io.job();
				this.#logDue = this.#io.now() + (r.ok ? LOG_EVERY_MS : LOG_RETRY_MS);
				// The journal tells a job's end; when it does not answer, the
				// status is read after the end the log read saw.
				if (r.ended && this.#s.watch.kind === 'journal') {
					if (this.#want === 'none') this.#want = 'snapshot';
					if (r.kind === 'backup') this.#io.backupStatus();
				}
				continue;
			}
			const signal = this.#wake.signal;
			if (this.#want !== 'none') continue;
			const cursor = this.#s.cursor;
			const input =
				this.#action === 'poll' && cursor !== null ? await this.#io.events(cursor, running ? 2 : 25, signal) : await this.#io.status();
			if (this.#destroyed) return;
			if (!input) continue;
			const step = this.#take(input);
			if (step.next === 'stop') continue;
			// A running job's log is not held back by the follower's waits.
			let wait = step.waitMs;
			if (running) wait = Math.min(wait, Math.max(0, this.#logDue - this.#io.now()));
			if (wait > 0 && this.#want === 'none') await this.#io.sleep(wait, this.#wake.signal);
		}
	}

	/** The job, then the status: the daemon schedules a job's reboot before it
	 *  marks the job done, so a done job is never paired with a status from
	 *  before its reboot was scheduled. Without a cursor, the status is read
	 *  first for it, so an entry written between the reads is still told; the
	 *  job is read whatever that status says, and again when that first status
	 *  brought the cursor. Answers the wait the last status read asked for (0
	 *  when the reader was destroyed first). */
	async #snapshot(kind: 'snapshot' | 'page'): Promise<number> {
		this.#inSnapshot = true;
		this.#alsoRest = false;
		let wait = 0;
		try {
			if (this.#s.cursor === null) {
				// The status read first for the cursor is a status read like any:
				// it sets the cursor, settles a reboot, says what is not answering.
				// The job and a status after it are read all the same, in that order.
				const first = await this.#io.status();
				if (this.#destroyed) return 0;
				wait = this.#take(first).waitMs;
			}
			const hadCursor = this.#s.cursor !== null;
			await this.#io.job();
			if (this.#destroyed) return 0;
			wait = this.#take(await this.#io.status()).waitMs;
			// The cursor came only now, after the job was read: the job again, so
			// nothing written between the two reads goes untold on screen.
			if (!hadCursor && this.#s.cursor !== null && !this.#destroyed) await this.#io.job();
		} finally {
			this.#inSnapshot = false;
			if (!this.#destroyed && (kind === 'page' || this.#alsoRest)) this.#io.rest();
		}
		return wait;
	}
}
