import { afterEach, describe, expect, it } from 'vitest';
import { toast } from '#lib/toast.svelte.js';

afterEach(() => {
	for (const t of [...toast.toasts]) toast.dismiss(t.id);
});

describe('toast — one condition, one toast', () => {
	it('replaces an error identical to one still shown, as the newest', () => {
		const first = toast.error('Refresh failed', { body: 'timeout' });
		toast.info('Unrelated');
		const again = toast.error('Refresh failed', { body: 'timeout' });
		expect(again).not.toBe(first);
		expect(toast.toasts.map((t) => t.title)).toEqual(['Unrelated', 'Refresh failed']);
	});

	it('shows it again once the first is dismissed', () => {
		const first = toast.error('Refresh failed', { body: 'timeout' });
		toast.dismiss(first);
		toast.error('Refresh failed', { body: 'timeout' });
		expect(toast.toasts).toHaveLength(1);
		expect(toast.toasts[0].id).not.toBe(first);
	});

	it('stacks a different message, body, code or kind', () => {
		toast.error('Refresh failed', { body: 'timeout' });
		toast.error('Refresh failed', { body: 'refused' });
		toast.error('Other', { body: 'timeout' });
		toast.error('Refresh failed', { body: 'timeout', code: 'network_unreachable' });
		toast.warning('Refresh failed', 'timeout');
		expect(toast.toasts).toHaveLength(5);
	});

	it('never folds a repeated confirmation into the first', () => {
		toast.success('Saved');
		toast.success('Saved');
		expect(toast.toasts).toHaveLength(2);
	});
});
