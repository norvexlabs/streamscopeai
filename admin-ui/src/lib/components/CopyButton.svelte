<script lang="ts">
	import Icon from '#lib/components/Icon.svelte';

	let { text, label = 'Copy' }: { text: string; label?: string } = $props();
	let copied = $state(false);

	async function copy() {
		await navigator.clipboard.writeText(text);
		copied = true;
		setTimeout(() => (copied = false), 1500);
	}
</script>

<button
	onclick={copy}
	class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded-sm text-[9px] font-medium transition-colors {copied ? 'bg-(--tag-teal-bg) text-(--success)' : 'bg-(--bg-secondary) text-(--text-secondary) hover:text-(--text-primary)'}"
	title={copied ? 'Copied!' : label}
>
	{#if copied}
		<Icon name="check" size="sm" tone="success" />
		Copied
	{:else}
		<Icon name="copy" size="sm" tone="neutral" />
		{label}
	{/if}
</button>
