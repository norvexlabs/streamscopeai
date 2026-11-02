<script lang="ts">
	import type { Snippet } from 'svelte';
	import { page } from '$app/state';
	import { scopeHref } from '#lib/tenant.js';
	import { useLoadView } from '#lib/loadView.svelte.js';

	let {
		title,
		subtitle,
		action,
		actionHref,
		headerExtra,
		flush = false,
		loading = false,
		error = '',
		empty = false,
		emptyMessage = 'No data for the selected period.',
		skeleton,
		emptySlot,
		children,
	}: {
		title: string;
		subtitle?: string;
		/** Optional drill-down link label, e.g. "View all". */
		action?: string;
		actionHref?: string;
		/** Optional controls rendered in the header, left of the action link
		 *  (e.g. a period chip, a sort toggle, a count pill). */
		headerExtra?: Snippet;
		/** Render the body flush to the card edges (no p-5). For table / list
		 *  bodies that own their own row padding. */
		flush?: boolean;
		loading?: boolean;
		error?: string;
		empty?: boolean;
		emptyMessage?: string;
		/** Optional loading placeholder. When provided, replaces the spinner. */
		skeleton?: Snippet;
		/** Optional rich empty state. When provided, replaces the default text. */
		emptySlot?: Snippet;
		children: Snippet;
	} = $props();

	// Skeleton on the first load and after a scope change only
	// (`#lib/loadView.js`); a refresh keeps the body — or its empty state, since a
	// caller's `empty` is usually `!loading && …` and reads false mid-load.
	const view = useLoadView(() => loading);
	let settledEmpty = $state(false);
	$effect(() => {
		if (!loading) settledEmpty = empty;
	});
	const shownEmpty = $derived(view.reloading ? settledEmpty : empty);

	const scopedActionHref = $derived(scopeHref(page.params.slug ?? '', page.url.pathname, actionHref));
</script>

<div class="rounded-lg border border-(--border) bg-(--bg-card) overflow-hidden">
	<header class="flex items-center justify-between gap-2 px-5 py-3 border-b border-(--border)">
		<div class="min-w-0">
			<h2 class="text-sm font-semibold text-(--text-primary) truncate">{title}</h2>
			{#if subtitle}
				<p class="text-xs text-(--text-secondary) mt-0.5">{subtitle}</p>
			{/if}
		</div>
		{#if headerExtra || (action && actionHref)}
			<div class="flex items-center gap-2 shrink-0">
				{#if headerExtra}
					{@render headerExtra()}
				{/if}
				{#if action && actionHref}
					<a
						href={scopedActionHref}
						class="text-xs font-medium text-(--accent) hover:text-(--accent-hover) transition-colors"
					>
						{action} →
					</a>
				{/if}
			</div>
		{/if}
	</header>
	<div class={flush ? '' : 'p-5'}>
		{#if view.skeleton}
			{#if skeleton}
				{@render skeleton()}
			{:else}
				<div class="flex items-center justify-center py-8">
					<div
						class="w-5 h-5 border-2 border-(--text-secondary) border-t-(--accent) rounded-full animate-spin"
					></div>
				</div>
			{/if}
		{:else if error}
			<p class="text-sm text-(--error-text) py-4">{error}</p>
		{:else if shownEmpty}
			{#if emptySlot}
				{@render emptySlot()}
			{:else}
				<p class="text-sm text-(--text-secondary) py-4 text-center">{emptyMessage}</p>
			{/if}
		{:else}
			{@render children()}
		{/if}
	</div>
</div>
