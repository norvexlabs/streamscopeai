<script lang="ts">
	import { page } from '$app/state';
	import { tick } from 'svelte';
	import { goto } from '$app/navigation';
	import type { NavCluster, NavSubtree } from '#lib/nav.js';
	import { activeSubtreeHref } from '#lib/nav.js';
	import SidebarCluster from './SidebarCluster.svelte';
	import SidebarLeaf from './SidebarLeaf.svelte';
	import SidebarSubtree from './SidebarSubtree.svelte';
	import SidebarFlyout from './SidebarFlyout.svelte';

	let { nav, collapsed = false }: { nav: NavCluster[]; collapsed?: boolean } = $props();

	// Auto-expand the subtree containing the active route — once at mount,
	// then only on real page navigation. The effect deliberately doesn't read
	// expandedHref, so a same-page user collapse won't trigger a re-open.
	let expandedHref = $state<string | null>(null);
	let initialized = $state(false);
	let lastPath = $state(page.url.pathname);
	$effect(() => {
		const path = page.url.pathname;
		if (initialized && path === lastPath) return;
		lastPath = path;
		initialized = true;
		const hint = activeSubtreeHref(nav, path);
		if (hint) expandedHref = hint;
	});

	// Folded-mode flyout state.
	let flyoutHref = $state<string | null>(null);
	let flyoutPinned = $state(false);
	let flyoutAnchor = $state<DOMRect | null>(null);
	let hoverTimer: ReturnType<typeof setTimeout> | null = null;
	// Grace period after mouse leaves the parent icon — gives the user time to
	// reach the flyout panel before it closes. ~200ms is comfortable.
	let closeTimer: ReturnType<typeof setTimeout> | null = null;
	const FLYOUT_CLOSE_GRACE_MS = 200;

	function isLeafActive(href: string): boolean {
		return page.url.pathname === href;
	}
	function isSubtreeActive(item: NavSubtree): boolean {
		if (page.url.pathname === item.href) return true;
		if (page.url.pathname.startsWith(item.href + '/')) return true;
		return item.children.some((c) => c.href === page.url.pathname);
	}

	function cancelClose() {
		if (closeTimer) {
			clearTimeout(closeTimer);
			closeTimer = null;
		}
	}
	function scheduleClose() {
		cancelClose();
		closeTimer = setTimeout(() => {
			if (!flyoutPinned) flyoutHref = null;
		}, FLYOUT_CLOSE_GRACE_MS);
	}

	function openFlyoutHover(item: NavSubtree, ev: MouseEvent) {
		if (!collapsed) return;
		cancelClose();
		if (hoverTimer) clearTimeout(hoverTimer);
		const target = ev.currentTarget as HTMLElement;
		hoverTimer = setTimeout(() => {
			flyoutAnchor = target.getBoundingClientRect();
			flyoutHref = item.href;
			flyoutPinned = false;
		}, 220);
	}
	function closeFlyoutHover() {
		if (hoverTimer) {
			clearTimeout(hoverTimer);
			hoverTimer = null;
		}
		// Don't close immediately — the user may be moving toward the flyout.
		if (!flyoutPinned) scheduleClose();
	}
	async function pinOrNavigateSubtree(item: NavSubtree, ev: MouseEvent) {
		if (collapsed) {
			ev.preventDefault();
			cancelClose();
			if (hoverTimer) {
				clearTimeout(hoverTimer);
				hoverTimer = null;
			}
			const target = ev.currentTarget as HTMLElement;
			flyoutAnchor = target.getBoundingClientRect();

			// Click on a folded subtree-parent always opens (or re-pins) the
			// flyout. To reach the parent index route the user clicks the first
			// item inside the flyout (which IS the parent index — e.g. "Overview"
			// leads to /dashboard, the same place a direct navigate would go).
			if (flyoutHref === item.href && flyoutPinned) {
				// Second click on a pinned flyout dismisses it.
				flyoutHref = null;
				flyoutPinned = false;
			} else {
				flyoutHref = item.href;
				flyoutPinned = true;
				await tick();
				const firstItem = document.querySelector<HTMLAnchorElement>(
					`[data-flyout-item][data-flyout-href="${item.href}"]`,
				);
				firstItem?.focus();
			}
			return;
		}
		// Expanded mode. Opening a subtree also navigates to its index;
		// closing just collapses (no navigation away from the current page).
		const wasOpen = expandedHref === item.href;
		expandedHref = wasOpen ? null : item.href;
		if (!wasOpen) void goto(item.href);
	}
	function dismissFlyout() {
		cancelClose();
		flyoutHref = null;
		flyoutPinned = false;
	}

	function onKeydown(ev: KeyboardEvent) {
		if (ev.key === 'Escape' && flyoutHref) {
			ev.preventDefault();
			dismissFlyout();
		}
	}
	$effect(() => {
		if (flyoutPinned) {
			document.addEventListener('keydown', onKeydown);
			const onClick = (e: MouseEvent) => {
				if (!(e.target as HTMLElement).closest('[data-flyout]')) dismissFlyout();
			};
			document.addEventListener('mousedown', onClick);
			return () => {
				document.removeEventListener('keydown', onKeydown);
				document.removeEventListener('mousedown', onClick);
			};
		}
	});

	const flyoutSubtree = $derived(
		flyoutHref
			? (nav
					.flatMap((c) => c.items)
					.find((i) => i.kind === 'subtree' && i.href === flyoutHref) as NavSubtree | undefined)
			: null,
	);
</script>

<nav class="shrink-0">
	<ul class="py-4 px-3 space-y-0.5">
		{#each nav as cluster, ci (cluster.label)}
			<SidebarCluster label={cluster.label} showDivider={ci > 0} {collapsed}>
				{#each cluster.items as item (item.href)}
					{#if item.kind === 'leaf'}
						<SidebarLeaf {item} active={isLeafActive(item.href)} {collapsed} />
					{:else}
						<SidebarSubtree
							{item}
							active={isSubtreeActive(item)}
							open={!collapsed && expandedHref === item.href}
							{collapsed}
							flyoutOpen={flyoutHref === item.href}
							{isLeafActive}
							onclick={(e) => pinOrNavigateSubtree(item, e)}
							onmouseenter={(e) => openFlyoutHover(item, e)}
							onmouseleave={closeFlyoutHover}
						/>
					{/if}
				{/each}
			</SidebarCluster>
		{/each}
	</ul>
</nav>

{#if collapsed && flyoutSubtree && flyoutAnchor}
	<SidebarFlyout
		subtree={flyoutSubtree}
		anchor={flyoutAnchor}
		{isLeafActive}
		onmouseenter={cancelClose}
		onmouseleave={() => {
			if (!flyoutPinned) scheduleClose();
		}}
		ondismiss={dismissFlyout}
	/>
{/if}
