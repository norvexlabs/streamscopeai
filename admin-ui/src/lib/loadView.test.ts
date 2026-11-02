import { describe, expect, it } from 'vitest';
import { refreshSkipped, refreshViewSkeleton, showSkeleton } from '#lib/loadView.js';

describe('showSkeleton', () => {
	it('shows it on the first load', () => {
		expect(showSkeleton(true, null, 0)).toBe(true);
	});

	it('keeps what is shown on a reload in the same scope — a refresh never blinks', () => {
		expect(showSkeleton(true, 3, 3)).toBe(false);
	});

	it('shows it on a load after a scope change — old data never passes for current', () => {
		expect(showSkeleton(true, 3, 4)).toBe(true);
	});

	it('never shows it while nothing is loading — the positive control', () => {
		expect(showSkeleton(false, null, 0)).toBe(false);
		expect(showSkeleton(false, 3, 4)).toBe(false);
	});
});

describe('a list the viewer drives', () => {
	it('a refresh keeps the rows; a load the page starts shows the skeleton', () => {
		expect(refreshViewSkeleton(false, true, true)).toBe(false);
		expect(refreshViewSkeleton(false, true, false)).toBe(true);
	});

	it('a scope change shows it whatever is in flight; nothing loading shows nothing', () => {
		expect(refreshViewSkeleton(true, true, true)).toBe(true);
		expect(refreshViewSkeleton(false, false, false)).toBe(false);
	});

	it('a refresh waits out the page own load, and only it', () => {
		expect(refreshSkipped(true)).toBe(true);
		expect(refreshSkipped(false)).toBe(false);
	});
});
