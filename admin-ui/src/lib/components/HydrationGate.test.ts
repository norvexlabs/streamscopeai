import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { render } from 'svelte/server';
import HydrationGate from './HydrationGate.svelte';

const here = dirname(fileURLToPath(import.meta.url));

describe('HydrationGate as the server renders it', () => {
	// A server-rendered control has no handler until the app hydrates; the
	// marker is what keeps a click off it until then (`app.css`). Dropping it
	// after mount is held by the e2e tier, where a click on a control made
	// before hydration waits for it and then acts.
	it('marks the server render as not ready', () => {
		const html = render(HydrationGate, { props: { class: 'min-h-screen', children: (() => {}) as never } }).body;
		const root = html.match(/<div[^>]*>/)?.[0];
		expect(root).toBeDefined();
		expect(root).toMatch(/\sdata-hydrating(=""|\s|>)/);
		expect(root).toContain('class="min-h-screen"');
	});

	it('wraps every page: the root layout renders through it', () => {
		const layout = readFileSync(resolve(here, '../../routes/+layout.svelte'), 'utf8');
		expect(layout).toMatch(/<HydrationGate[\s>][\s\S]*\{@render children\(\)\}[\s\S]*<\/HydrationGate>/);
	});
});
