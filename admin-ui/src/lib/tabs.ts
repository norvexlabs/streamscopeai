/** Read ?tab= from URL, return it if in allowed set, else fallback. */
export function getTabFromUrl<T extends string>(allowed: T[], fallback: T): T {
	if (typeof window === 'undefined') return fallback;
	const t = new URLSearchParams(window.location.search).get('tab');
	return allowed.includes(t as T) ? (t as T) : fallback;
}

/** Update ?tab= in URL without triggering navigation. Preserves other params. */
export function setTabParam(tab: string): void {
	const url = new URL(window.location.href);
	url.searchParams.set('tab', tab);
	history.replaceState(history.state, '', url.toString());
}
