<script lang="ts">
	/**
	 * Says that a list's text search stopped at its scan budget
	 * (`OffsetPage.scan_cut`): more matches may exist past what it read, so the
	 * list is not everything. Renders nothing when `cut` is false.
	 */
	import { m } from '#lib/paraglide/messages.js';

	let { cut }: { cut: boolean } = $props();
</script>

{#if cut}
	<p class="mt-4 text-sm text-(--warning)">{m.pagination_scan_cut()}</p>
{/if}
