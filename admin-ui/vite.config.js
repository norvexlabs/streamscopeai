import adapter from '@sveltejs/adapter-node';
import { sveltekit } from '@sveltejs/kit/vite';
import tailwindcss from '@tailwindcss/vite';
import { paraglideVitePlugin } from '@inlang/paraglide-js';
import { defineConfig } from 'vite';
import { readFileSync, writeFileSync, existsSync } from 'fs';

// i18n locale-resolution order. Cookie-first (explicit user choice via the
// language selector), then the browser's Accept-Language, then English. No `url`
// strategy: the locale must NOT live in the path, or it would collide with the
// /t/<slug> + /portal/t/<slug> tenant prefix and the path-scoped session
// cookies. Keep this list in sync with the `paraglide-js compile` invocation in
// package.json's `check` script.
/** @type {('cookie' | 'preferredLanguage' | 'baseLocale')[]} */
const I18N_STRATEGY = ['cookie', 'preferredLanguage', 'baseLocale'];

// Version from CHANGELOG.md (single source of truth).
// Docker builds pass VITE_APP_VERSION; local dev reads the file directly.
function resolveVersion() {
	if (process.env.VITE_APP_VERSION) return process.env.VITE_APP_VERSION;
	const path = '../CHANGELOG.md';
	if (existsSync(path)) {
		const m = readFileSync(path, 'utf-8').match(/^## \[(.+?)\]/m);
		if (m) return m[1];
	}
	return '0.0.0';
}
const appVersion = resolveVersion();

// Records the packages a build takes code from, for the image's third-party
// licence list (scripts/third-party-licenses.mjs): the installed directory of
// every node_modules module it bundles (a nested copy by its nested path), and
// the name of every bare import it leaves external, which the adapter bundles
// later. Each build (client, server) adds to the same file, so a run starts
// without one (the image build has none; it is gitignored).
const BUNDLED_PACKAGES = '.bundled-packages.json';
/** @returns {import('vite').Plugin} */
function bundledPackages() {
	return {
		name: 'bundled-packages',
		apply: 'build',
		generateBundle(_, bundle) {
			const seen = new Set(existsSync(BUNDLED_PACKAGES) ? JSON.parse(readFileSync(BUNDLED_PACKAGES, 'utf-8')) : []);
			for (const chunk of Object.values(bundle)) {
				if (chunk.type !== 'chunk') continue;
				for (const id of Object.keys(chunk.modules)) {
					const at = id.indexOf('node_modules/');
					const m = at < 0 ? null : id.slice(at).match(/^(?:node_modules\/(?:@[^/]+\/)?[^/]+\/?)+/);
					if (m) seen.add(m[0].replace(/\/$/, ''));
				}
				for (const spec of chunk.imports) {
					const m = spec.match(/^((?:@[^/.][^/]*\/)?[^/.][^/]*)/);
					if (m && !spec.startsWith('node:') && !(spec in bundle)) seen.add(`node_modules/${m[1]}`);
				}
			}
			writeFileSync(BUNDLED_PACKAGES, JSON.stringify([...seen].sort()));
		}
	};
}

export default defineConfig({
	plugins: [
		tailwindcss(),
		paraglideVitePlugin({
			project: './project.inlang',
			outdir: './src/lib/paraglide',
			strategy: I18N_STRATEGY,
		}),
		sveltekit({
			// Every component of the console compiles in runes mode, so legacy
			// syntax (`export let`, `$:`) is a build error; a library keeps the
			// mode it was written in.
			compilerOptions: {
				runes: ({ filename }) => (filename.split(/[/\\]/).includes('node_modules') ? undefined : true),
			},
			adapter: adapter(),
			csp: {
				directives: {
					'default-src': ['self'],
					'script-src': ['self'],
					'style-src': ['self', 'unsafe-inline'],
					'img-src': ['self', 'data:', 'https:', 'blob:'],
					'media-src': ['self', 'data:', 'blob:'],
					'frame-src': ['data:'],
					'connect-src': ['self'],
					'font-src': ['self']
				}
			}
		}),
		bundledPackages()
	],
	define: {
		'__APP_VERSION__': JSON.stringify(appVersion),
	}
});
