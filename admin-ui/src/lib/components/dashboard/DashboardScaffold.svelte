<script lang="ts">
	import type { Snippet } from 'svelte';

	// PeriodSelector is global (header bar) — driven by `consoleScope.period`. Pages
	// only need to read it; the scaffold doesn't render its own.
	let {
		title,
		subtitle,
		filters,
		children,
	}: {
		title: string;
		subtitle?: string;
		/** Optional in-page filter chips (e.g. KindChip on Sessions / Audit / Tool Calls). */
		filters?: Snippet;
		/** Page body — chart grid, tables, etc. */
		children: Snippet;
	} = $props();
</script>

<div class="flex items-center justify-between gap-4 mb-6 pb-4 border-b border-(--border)">
	<div class="min-w-0">
		<h1 class="text-2xl font-semibold text-(--text-primary) truncate">{title}</h1>
		{#if subtitle}
			<p class="text-sm text-(--text-secondary) mt-1">{subtitle}</p>
		{/if}
	</div>
	{#if filters}
		<div class="flex items-center gap-2 shrink-0">{@render filters()}</div>
	{/if}
</div>

{@render children()}
