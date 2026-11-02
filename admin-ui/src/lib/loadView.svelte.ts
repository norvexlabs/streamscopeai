import { untrack } from 'svelte';
import { refreshCycle } from '#lib/refreshCycle.svelte.js';
import { refreshSkipped, refreshViewSkeleton, showSkeleton } from '#lib/loadView.js';
import type { ReloadCause } from '#lib/refreshCycle.svelte.js';

/**
 * Bind the dashboard loading rule (`#lib/loadView.js`) to a component. Call at the
 * top level of its <script>. `skeleton` is when to show the loading
 * placeholder; `reloading` is a load that keeps what is shown — a view must
 * then keep its last settled empty state too, not re-derive it from data that
 * is still in flight.
 */
export function useLoadView(loading: () => boolean): { readonly skeleton: boolean; readonly reloading: boolean } {
	const scope = () => refreshCycle.scopeGeneration;

	let loadedScope = $state<number | null>(null);
	// A finished load marks the view loaded for the scope it is in.
	$effect(() => {
		const busy = loading();
		untrack(() => {
			if (!busy) loadedScope = scope();
		});
	});
	// A scope change with no load running (a tab, an anchor, a URL a page does
	// not load from) reloads nothing, so there is nothing to cover.
	$effect(() => {
		const current = scope();
		untrack(() => {
			if (!loading()) loadedScope = current;
		});
	});

	return {
		get skeleton() {
			return showSkeleton(loading(), loadedScope, scope());
		},
		get reloading() {
			return loading() && !showSkeleton(loading(), loadedScope, scope());
		},
	};
}

/**
 * `useLoadView` for a list a viewer drives: only a REFRESH keeps what is
 * shown. A load the page starts itself — a filter applied, another page of
 * results — shows the skeleton, since the rows on screen no longer answer
 * what was asked. Route `usePeriodicLoad`'s reload through `refresh` with the
 * cause it is given: a scope change is a load like the page's own (skeleton,
 * nothing kept on failure); only a refresh keeps the rows, and a refresh is
 * skipped while the page's own load runs.
 */
export function useRefreshView(loading: () => boolean): {
	readonly skeleton: boolean;
	readonly refreshing: boolean;
	begin(): void;
	refresh(load: () => Promise<void>, cause: ReloadCause): Promise<void>;
} {
	const view = useLoadView(loading);
	// Set only while `refresh` calls the loader, so `begin` (the loader's first
	// line) tells the two kinds of load apart.
	let inRefresh = false;
	// What started the load now running: a page load begun during a refresh
	// takes the view back from it, skeleton included.
	let current = $state<'refresh' | 'own'>('own');
	return {
		get skeleton() {
			return refreshViewSkeleton(view.skeleton, loading(), current === 'refresh');
		},
		/** The load now running is a refresh: a failure keeps what is shown. */
		get refreshing() {
			return current === 'refresh';
		},
		/** First line of the loader, before any `await`. */
		begin() {
			current = inRefresh ? 'refresh' : 'own';
		},
		async refresh(load: () => Promise<void>, cause: ReloadCause): Promise<void> {
			// A scope change answers a new question: the page's own kind of load.
			if (cause === 'scope') return load();
			// A refresh is dropped while the page's own load is under way: that
			// load answers it, and superseding it would hide its skeleton.
			if (refreshSkipped(loading())) return;
			inRefresh = true;
			let running: Promise<void>;
			try {
				running = load();
			} finally {
				inRefresh = false;
			}
			await running;
		},
	};
}
