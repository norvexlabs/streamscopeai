<script lang="ts">
	/**
	 * Pagination controls bound to a `Pagination` state object from
	 * `#lib/hooks.svelte.js`. Renders:
	 *   - numbered page buttons + total when `state.total` is known (TotalPage<T>)
	 *   - prev/next buttons otherwise (OffsetPage<T>)
	 *
	 * The parent fetches; this component only drives the offset. Pass `onchange`
	 * as the refetch callback — it fires after the offset has already been
	 * updated, so the parent just re-reads the paginated endpoint.
	 */
	import type { Pagination } from '#lib/hooks.svelte.js';
	import ScanCutNotice from './ScanCutNotice.svelte';
	import { m } from '#lib/paraglide/messages.js';

	interface Props {
		state: Pagination;
		onchange: () => void | Promise<void>;
		/** Number of items rendered on the current page; used in the info line. */
		itemsShown?: number;
		/** Hide the whole bar on empty first page. Default: true. */
		hideOnEmpty?: boolean;
	}

	let { state, onchange, itemsShown, hideOnEmpty = true }: Props = $props();

	async function navTo(p: number) {
		state.goToPage(p);
		await onchange();
	}
	async function navPrev() {
		if (state.offset === 0) return;
		state.prev();
		await onchange();
	}
	async function navNext() {
		if (!state.hasMore) return;
		state.next();
		await onchange();
	}

	const btnCls =
		'px-3 py-1.5 border border-(--border) rounded-md text-sm font-medium transition-colors disabled:opacity-30 disabled:cursor-not-allowed hover:bg-(--bg-card) text-(--text-secondary) hover:text-(--text-primary)';
	const activeCls =
		'px-3 py-1.5 border border-(--accent) bg-(--accent)/10 rounded-md text-sm font-medium text-(--text-primary)';

	// Numbered pager: always show first, last, current ±2, and ellipses in between.
	function pagesToRender(current: number, total: number): (number | 'ellipsis')[] {
		if (total <= 7) return Array.from({ length: total }, (_, i) => i + 1);
		const pages: (number | 'ellipsis')[] = [1];
		const start = Math.max(2, current - 2);
		const end = Math.min(total - 1, current + 2);
		if (start > 2) pages.push('ellipsis');
		for (let i = start; i <= end; i++) pages.push(i);
		if (end < total - 1) pages.push('ellipsis');
		pages.push(total);
		return pages;
	}

	const hidden = $derived(
		hideOnEmpty && state.offset === 0 && !state.hasMore && !state.scanCut && (itemsShown ?? 0) === 0,
	);
</script>

<ScanCutNotice cut={state.scanCut} />
{#if !hidden}
	<div class="flex items-center justify-between mt-4 flex-wrap gap-2">
		<p class="text-sm text-(--text-secondary)">
			{#if state.total != null}
				{m.pagination_page_of({ page: state.page, count: state.pageCount ?? 1 })}
				&middot; {m.pagination_total({ total: state.total.toLocaleString() })}
				{#if itemsShown != null}&middot; {m.pagination_showing({ count: itemsShown })}{/if}
			{:else}
				{m.pagination_page({ page: state.page })}
				{#if itemsShown != null}&middot; {m.pagination_showing({ count: itemsShown })}{/if}
			{/if}
		</p>

		<div class="flex gap-1 items-center">
			<button type="button" class={btnCls} onclick={navPrev} disabled={state.offset === 0}>{m.pagination_previous()}</button>

			{#if state.total != null && state.pageCount != null && state.pageCount > 1}
				{#each pagesToRender(state.page, state.pageCount) as p}
					{#if p === 'ellipsis'}
						<span class="px-2 text-sm text-(--text-secondary)">…</span>
					{:else}
						<button
							type="button"
							class={p === state.page ? activeCls : btnCls}
							onclick={() => navTo(p)}
							disabled={p === state.page}
						>
							{p}
						</button>
					{/if}
				{/each}
			{/if}

			<button type="button" class={btnCls} onclick={navNext} disabled={!state.hasMore}>{m.pagination_next()}</button>
		</div>
	</div>
{/if}
