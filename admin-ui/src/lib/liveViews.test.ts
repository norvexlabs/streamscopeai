import { describe, expect, it } from 'vitest';
import { isLiveView } from '#lib/liveViews.js';

describe('isLiveView', () => {
	it('runs on the viewing pages, a subtree with its children', () => {
		expect(isLiveView('/t/[slug]/dashboard')).toBe(true);
		expect(isLiveView('/t/[slug]/dashboard/servers/[id]')).toBe(true);
		expect(isLiveView('/t/[slug]/sessions/[id]')).toBe(true);
		expect(isLiveView('/t/[slug]/audit')).toBe(true);
	});

	it('never on an editing page', () => {
		for (const id of [
			'/t/[slug]/users',
			'/t/[slug]/gateways/llm',
			'/t/[slug]/admin/edge',
			'/t/[slug]/transforms',
			'/t/[slug]/experts',
			'/portal/t/[slug]/keys',
			'/portal/t/[slug]/team',
		]) {
			expect(isLiveView(id), id).toBe(false);
		}
	});

	it('an exact route never reaches its children or a longer sibling', () => {
		expect(isLiveView('/portal/t/[slug]/sessions/[id]')).toBe(false);
		expect(isLiveView('/t/[slug]/audit/[id]')).toBe(false);
		expect(isLiveView('/t/[slug]/audit-export')).toBe(false);
		expect(isLiveView('/t/[slug]/dashboardx')).toBe(false);
	});

	it('never on the portal: members refresh by hand', () => {
		for (const id of [
			'/portal/t/[slug]/home',
			'/portal/t/[slug]/sessions',
			'/portal/t/[slug]/audit',
			'/portal/t/[slug]/usage',
		]) {
			expect(isLiveView(id), id).toBe(false);
		}
	});

	it('nothing without a route', () => {
		expect(isLiveView(null)).toBe(false);
		expect(isLiveView(undefined)).toBe(false);
	});
});
