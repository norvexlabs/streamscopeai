import { describe, expect, it } from 'vitest';
import { KeyedContent } from './keyedContent.svelte.js';

describe('KeyedContent', () => {
	it('an_answer_for_the_current_visit_lands', () => {
		const shown = new KeyedContent<string[]>();
		const visit = shown.show('a');
		expect(shown.key).toBe('a');
		expect(shown.value).toBeNull();
		expect(shown.land(visit, ['x'])).toBe(true);
		expect(shown.value).toEqual(['x']);
		// A later answer of the same visit replaces it (a save's answer).
		expect(shown.land(shown.visit, [])).toBe(true);
		expect(shown.value).toEqual([]);
	});

	it('an_answer_for_a_key_the_view_has_left_is_dropped', () => {
		const shown = new KeyedContent<string[]>();
		const onA = shown.show('a');
		shown.land(onA, ['of-a']);
		const onB = shown.show('b');
		// Moving on clears what was shown: nothing of `a` is saved under `b`.
		expect(shown.value).toBeNull();
		shown.land(onB, ['of-b']);
		// The save issued under `a` answers now.
		expect(shown.land(onA, [])).toBe(false);
		expect(shown.value).toEqual(['of-b']);
		expect(shown.isCurrent(onA)).toBe(false);
		expect(shown.isCurrent(onB)).toBe(true);
	});

	it('coming_back_to_a_key_does_not_land_an_answer_issued_before_leaving_it', () => {
		const shown = new KeyedContent<string>();
		const first = shown.show('a');
		shown.show('b');
		const again = shown.show('a');
		// Same key, another visit: its content is read again.
		expect(shown.value).toBeNull();
		expect(shown.land(first, 'stale')).toBe(false);
		expect(shown.value).toBeNull();
		expect(shown.land(again, 'fresh')).toBe(true);
		expect(shown.value).toBe('fresh');
	});

	it('a_resolution_that_lands_after_the_route_moved_on_is_dropped', () => {
		// The profile page resolves its route to a profile id; the `shared`
		// alias takes a read. The route moves to a plain id before it answers.
		const resolved = new KeyedContent<string>();
		const alias = resolved.show('shared');
		const plain = resolved.show('profile-2');
		expect(resolved.land(plain, 'profile-2')).toBe(true);
		expect(resolved.land(alias, 'default-profile')).toBe(false);
		expect(resolved.value).toBe('profile-2');
		// And back to the alias: its own resolution lands.
		const again = resolved.show('shared');
		expect(resolved.value).toBeNull();
		expect(resolved.land(again, 'default-profile')).toBe(true);
		expect(resolved.value).toBe('default-profile');
	});

	it('nothing_lands_before_a_key_is_shown', () => {
		const shown = new KeyedContent<string>();
		expect(shown.key).toBeNull();
		expect(shown.land(shown.visit, 'x')).toBe(false);
		expect(shown.value).toBeNull();
	});
});
