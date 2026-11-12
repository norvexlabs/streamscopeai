/**
 * What an administrator can hide in the portal for a member's workspaces
 * (Portal & clients profiles): `sessions` — the Sessions page and every
 * conversation's content — and `requests`, the Requests page.
 *
 * The gateway decides, per request: it refuses a hidden route with 403
 * `portal_page_hidden`, and `GET /portal/auth/me` names what is hidden. The
 * portal's layout loads that identity once and keeps it — a CACHE of the
 * gateway's answer, wrong from the moment an administrator changes a profile.
 * One rule keeps it honest: whatever finds it wrong re-reads it. A refusal
 * does (the page that asked shows that it is not available at once, from the
 * refusal itself), the Refresh button does, and a page shown as hidden does
 * when it opens — so a page hidden since the load gives way, and one shown
 * again comes back, without a reload.
 */
import type { Middleware } from 'openapi-fetch';
import type { components } from '#lib/generated/api-types.js';
import { extractErrorCode } from '#lib/api-helpers.js';

export type PortalPage = components['schemas']['PortalPage'];
type ApiErrorCode = components['schemas']['ApiErrorCode'];

/** The code of the gateway's refusal for a hidden route. */
const PORTAL_PAGE_HIDDEN: ApiErrorCode = 'portal_page_hidden';

/** Whether an API answer is the refusal of a hidden route. */
export function isPageHiddenAnswer(status: number, body: unknown): boolean {
	return status === 403 && extractErrorCode(body) === PORTAL_PAGE_HIDDEN;
}

/**
 * What a refused portal route was hidden by, from its path: the Sessions
 * page's own routes and every route serving conversation content (a request's
 * detail, its web calls, its media, its tool definitions) by `sessions`; the
 * request list by `requests`; the filter options, refused only when both are
 * hidden, by both. A refusal names its own pages, so one that lands after the
 * viewer moved on says nothing about the page they are on now.
 */
export function pagesOfRoute(pathname: string): PortalPage[] {
	const route = /\/api\/v1\/portal\/(sessions|audit)(\/.*)?$/.exec(pathname);
	if (!route) return [];
	if (route[1] === 'sessions') return ['sessions'];
	const rest = (route[2] ?? '').replace(/\/$/, '');
	if (rest === '') return ['requests'];
	if (rest === '/filter-options') return ['sessions', 'requests'];
	return ['sessions'];
}

/**
 * The refusals seen since the identity was last re-read, and the re-read
 * itself. Browser-only state: the portal client that feeds it never runs on
 * the server.
 */
class HiddenPagesWatch {
	#refused = $state.raw<readonly PortalPage[]>([]);
	#reread: (() => Promise<void>) | null = null;
	#flight: Promise<void> | null = null;
	#again = false;

	/** Whether a route of `page` was refused and the identity not re-read since. */
	has(page: PortalPage): boolean {
		return this.#refused.includes(page);
	}

	/** How the identity is re-read (the portal layout: its load, invalidated).
	 *  Returns the function that withdraws it. */
	rereadWith(reread: () => Promise<void>): () => void {
		this.#reread = reread;
		return () => {
			if (this.#reread === reread) this.#reread = null;
		};
	}

	/** Routes of `pages` were refused: they are hidden from now, and the
	 *  identity is re-read so everything else follows. */
	refused(pages: readonly PortalPage[]): Promise<void> {
		const added = pages.filter((p) => !this.#refused.includes(p));
		if (added.length > 0) this.#refused = [...this.#refused, ...added];
		return this.recheck();
	}

	/**
	 * Re-read the identity. Once it has landed it says what is hidden, so the
	 * refusals seen before the read started are dropped; one seen while it ran
	 * is kept, and the identity is read once more. A failed read keeps them.
	 */
	recheck(): Promise<void> {
		if (this.#flight) {
			this.#again = true;
			return this.#flight;
		}
		this.#flight = this.#run().finally(() => {
			this.#flight = null;
		});
		return this.#flight;
	}

	async #run(): Promise<void> {
		do {
			this.#again = false;
			const reread = this.#reread;
			if (!reread) return;
			const settled = this.#refused;
			try {
				await reread();
			} catch {
				return;
			}
			this.#refused = this.#refused.filter((p) => !settled.includes(p));
		} while (this.#again);
	}
}

export const hiddenPages = new HiddenPagesWatch();

/** The layout data that names what is hidden: the portal's has it, the
 *  console's does not (nothing is hidden there). */
interface IdentityData {
	portalHiddenPages?: readonly PortalPage[];
}

/** Whether `page` is hidden for the viewer: the identity says so, or one of
 *  its routes has been refused since. */
export function pageHidden(page: PortalPage, data: IdentityData): boolean {
	return (data.portalHiddenPages ?? []).includes(page) || hiddenPages.has(page);
}

/** Tells [`hiddenPages`] when the gateway refuses a hidden route. */
export const pageHiddenMiddleware: Middleware = {
	async onResponse({ request, response }) {
		if (response.status === 403) {
			const body: unknown = await response
				.clone()
				.json()
				.catch(() => null);
			if (isPageHiddenAnswer(response.status, body)) {
				void hiddenPages.refused(pagesOfRoute(new URL(request.url).pathname));
			}
		}
		return undefined;
	},
};
