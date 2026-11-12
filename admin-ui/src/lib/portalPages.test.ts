import { afterEach, describe, expect, it } from 'vitest';
import { hiddenPages, isPageHiddenAnswer, pageHidden, pagesOfRoute } from './portalPages.svelte.js';

const refusal = { error: { code: 'portal_page_hidden', message: 'this page is not available for your workspaces' } };

describe('isPageHiddenAnswer', () => {
	it('is_the_403_carrying_the_page_hidden_code', () => {
		expect(isPageHiddenAnswer(403, refusal)).toBe(true);
	});

	it('is_not_another_403_nor_the_code_under_another_status', () => {
		expect(isPageHiddenAnswer(403, { error: { code: 'workspace_membership_required' } })).toBe(false);
		expect(isPageHiddenAnswer(404, refusal)).toBe(false);
		expect(isPageHiddenAnswer(200, refusal)).toBe(false);
	});

	it('is_not_a_body_without_the_envelope', () => {
		for (const body of [null, undefined, 'portal_page_hidden', { code: 'portal_page_hidden' }, { error: null }, {}]) {
			expect(isPageHiddenAnswer(403, body)).toBe(false);
		}
	});
});

describe('pagesOfRoute', () => {
	const under = (path: string) => `/portal/t/acme/api/v1/portal${path}`;

	it('names_sessions_for_the_sessions_pages_routes_and_for_every_content_route', () => {
		for (const path of [
			'/sessions',
			'/sessions/0b0e/conversation',
			'/sessions/0b0e/linked',
			'/audit/0b0e',
			'/audit/0b0e/web',
			'/audit/media/abc',
			'/audit/tool-definitions/abc',
		]) {
			expect(pagesOfRoute(under(path)), path).toEqual(['sessions']);
		}
	});

	it('names_requests_for_the_list_alone_and_both_for_the_filter_options', () => {
		expect(pagesOfRoute(under('/audit'))).toEqual(['requests']);
		expect(pagesOfRoute(under('/audit/'))).toEqual(['requests']);
		expect(pagesOfRoute('/api/v1/portal/audit')).toEqual(['requests']);
		expect(pagesOfRoute(under('/audit/filter-options'))).toEqual(['sessions', 'requests']);
	});

	it('names_nothing_for_a_route_no_switch_hides', () => {
		for (const path of ['/home', '/keys', '/stats', '/auth/me', '/auditors', '/sessionsx']) {
			expect(pagesOfRoute(under(path)), path).toEqual([]);
		}
		expect(pagesOfRoute('/api/v1/admin/audit')).toEqual([]);
	});
});

describe('hiddenPages', () => {
	let withdraw: (() => void) | undefined;

	/** A re-read that lands when `land` is called. */
	function heldReread() {
		const calls: (() => void)[] = [];
		withdraw = hiddenPages.rereadWith(() => new Promise<void>((resolve) => calls.push(resolve)));
		return {
			get count() {
				return calls.length;
			},
			land: (i: number) => calls[i](),
		};
	}

	afterEach(async () => {
		// Drop whatever a case left: one landed re-read forgets every refusal.
		withdraw?.();
		withdraw = hiddenPages.rereadWith(() => Promise.resolve());
		await hiddenPages.recheck();
		await hiddenPages.recheck();
		withdraw();
		withdraw = undefined;
	});

	it('a_refusal_hides_its_own_pages_at_once_and_no_other', async () => {
		const reread = heldReread();
		const done = hiddenPages.refused(['sessions']);
		expect(hiddenPages.has('sessions')).toBe(true);
		expect(hiddenPages.has('requests')).toBe(false);
		expect(pageHidden('sessions', {})).toBe(true);
		// A page the viewer moved to is not the one that was refused.
		expect(pageHidden('requests', { portalHiddenPages: [] })).toBe(false);
		expect(reread.count).toBe(1);
		reread.land(0);
		await done;
	});

	it('the_identity_once_re_read_replaces_the_refusal', async () => {
		const reread = heldReread();
		const done = hiddenPages.refused(['requests']);
		reread.land(0);
		await done;
		expect(hiddenPages.has('requests')).toBe(false);
		// What is hidden is then what the identity says, either way.
		expect(pageHidden('requests', { portalHiddenPages: ['requests'] })).toBe(true);
		expect(pageHidden('requests', { portalHiddenPages: [] })).toBe(false);
	});

	it('a_refusal_seen_while_the_identity_is_being_re_read_is_kept_and_read_again', async () => {
		const reread = heldReread();
		const first = hiddenPages.refused(['sessions']);
		const second = hiddenPages.refused(['requests']);
		expect(reread.count).toBe(1);
		reread.land(0);
		// The first read started before the second refusal: it settles only
		// the first, and a second read is under way.
		await Promise.resolve();
		await Promise.resolve();
		expect(hiddenPages.has('sessions')).toBe(false);
		expect(hiddenPages.has('requests')).toBe(true);
		expect(reread.count).toBe(2);
		reread.land(1);
		await Promise.all([first, second]);
		expect(hiddenPages.has('requests')).toBe(false);
	});

	it('a_failed_re_read_keeps_the_refusal', async () => {
		withdraw = hiddenPages.rereadWith(() => Promise.reject(new Error('unreachable')));
		await hiddenPages.refused(['sessions']);
		expect(hiddenPages.has('sessions')).toBe(true);
	});

	it('with_nothing_to_re_read_the_refusal_stands', async () => {
		await hiddenPages.refused(['sessions']);
		expect(hiddenPages.has('sessions')).toBe(true);
	});

	it('the_identity_alone_hides_a_page_and_the_console_hides_none', () => {
		expect(pageHidden('sessions', { portalHiddenPages: ['sessions'] })).toBe(true);
		expect(pageHidden('requests', { portalHiddenPages: ['sessions'] })).toBe(false);
		expect(pageHidden('sessions', {})).toBe(false);
	});
});
