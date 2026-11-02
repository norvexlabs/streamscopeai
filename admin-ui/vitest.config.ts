import { svelte } from '@sveltejs/vite-plugin-svelte';
import { defineConfig } from 'vitest/config';

/**
 * Component-level test tier for admin-ui.
 *
 * Scope is the `lib/` LOGIC surface — the path scoper, the badge collapsers,
 * the money formatters and the spend arithmetic. Those decide what an operator
 * is shown and whether an authenticated request carries its session cookie, and
 * until this tier existed the only thing executing them was the Playwright tier
 * of the e2e suite, which asserts pages rather than functions and takes minutes
 * to say so.
 *
 * Deliberately NOT a rendering tier: asserting markup for 169 presentational
 * components buys churn, not defects. A component earns a case here only when it
 * encodes a rule of its own. The one case outside `lib/` is the stylesheet's
 * (`app.css.test.ts`): it compiles `app.css` with the build's Tailwind and holds
 * the rules a silent CSS change would break (a theme tint renders, no token
 * shadows a Tailwind theme variable).
 *
 * `svelte()` is present so `.svelte.ts` rune modules (`currency.svelte.ts`, which
 * the money formatters read for the tenant's accounting currency) compile; the
 * SvelteKit plugin is deliberately absent — it wants a synced project and
 * a dev server, and nothing here renders a route.
 */
export default defineConfig({
	plugins: [svelte()],
	resolve: {
		// Load the browser condition so `.svelte.ts` rune modules get the
		// client-side Svelte runtime rather than the SSR one, which treats
		// module-level `$state` as request-shared and does not track it.
		// NOTE: from Vite 6 this REPLACES the default condition list rather than
		// extending it — `module` and `development`/`production` are dropped. No
		// dependency these tests reach keys on those today, so if a newly imported
		// package ever resolves to something unexpected here, this line is why.
		conditions: ['browser'],
	},
	test: {
		environment: 'node',
		include: ['src/**/*.test.ts'],
		coverage: {
			provider: 'v8',
			include: ['src/lib/**/*.ts', 'src/lib/**/*.svelte.ts'],
			exclude: ['src/lib/generated/**', 'src/lib/paraglide/**', 'src/**/*.test.ts'],
			reporter: ['text', 'html'],
		},
	},
});
