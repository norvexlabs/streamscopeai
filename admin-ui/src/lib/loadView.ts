// When a view shows its loading skeleton, and when it keeps what it shows
// while a load runs. One rule for every dashboard surface (<StatCard>,
// <Panel>, <ChartCard>, sections with their own spinner) — `useLoadView` in
// `loadView.svelte.ts` binds it to a component.
//
//  - The first load shows the skeleton: there is nothing to keep.
//  - A load after a scope change (period, workspace, URL) shows the skeleton:
//    what is on screen describes another view and must not pass for current.
//  - Any other load (a refresh, an auto-refresh tick) keeps what is shown —
//    content or empty state — until the new data lands, so a live dashboard
//    never blinks.
//
// `loadedScope` is the scope generation of the last finished load, or null
// before any.
export function showSkeleton(loading: boolean, loadedScope: number | null, scope: number): boolean {
	return loading && loadedScope !== scope;
}

// A list the viewer drives (`useRefreshView`): only a refresh keeps what is
// shown. `scopeSkeleton` is `showSkeleton`'s answer; `byRefresh` says the load
// now running was started by a refresh.

/** The skeleton: a scope change, or a load the page started itself. */
export function refreshViewSkeleton(scopeSkeleton: boolean, loading: boolean, byRefresh: boolean): boolean {
	return scopeSkeleton || (loading && !byRefresh);
}

/** A refresh arriving during the page's own load is dropped: that load is
 *  newer than anything the refresh would read, and superseding it would hide
 *  its skeleton. */
export function refreshSkipped(loading: boolean): boolean {
	return loading;
}
