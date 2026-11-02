import { Scanner } from '@tailwindcss/oxide';
import { __unstable__loadDesignSystem, compile } from 'tailwindcss';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

// The console stylesheet compiled by the same Tailwind the build uses, so these
// assertions read the rules a page actually gets.
const here = dirname(fileURLToPath(import.meta.url));
const appCss = readFileSync(resolve(here, 'app.css'), 'utf8');
const tailwindDir = dirname(createRequire(import.meta.url).resolve('tailwindcss/package.json'));

const loadStylesheet = async (id: string, base: string) => {
	const path = id === 'tailwindcss' ? resolve(tailwindDir, 'index.css') : resolve(base, id);
	return { path, base: dirname(path), content: readFileSync(path, 'utf8') };
};

async function build(candidates: string[]): Promise<string> {
	const compiler = await compile(appCss, { base: here, loadStylesheet });
	return compiler.build(candidates);
}

// Every candidate class in src/ (the files app.css's `@source` names), as
// Tailwind's own scanner finds it, with the file it is written in. The
// generated API types, the message catalogs and the tests are not markup.
function candidatesInSource(): { file: string; candidate: string }[] {
	const scanner = new Scanner({ sources: [{ base: here, pattern: '**/*.{html,js,svelte,ts}', negated: false }] });
	scanner.scan();
	return scanner.files
		.filter((file) => !/\/(paraglide|generated)\/|\.test\.ts$/.test(file))
		.flatMap((file) =>
			scanner
				.getCandidatesWithPositions({ content: readFileSync(file, 'utf8'), extension: file.split('.').pop() ?? '' })
				.map(({ candidate }) => ({ file: file.slice(here.length + 1), candidate })),
		);
}

// The stylesheet split into its `@theme` blocks (any form: `@theme`, `@theme
// inline`, …, nested braces included) and everything else, comments removed.
// Braces inside a quoted string do not count.
function splitTheme(css: string): { theme: string; rest: string } {
	const src = css.replace(/\/\*[\s\S]*?\*\//g, '');
	let theme = '';
	let rest = '';
	let at = 0;
	for (const m of src.matchAll(/@theme\b[^{;]*\{/g)) {
		if (m.index < at) continue;
		rest += src.slice(at, m.index);
		let depth = 1;
		let quote = '';
		let i = m.index + m[0].length;
		for (; i < src.length && depth > 0; i++) {
			const c = src[i];
			if (quote) {
				if (c === '\\') i++;
				else if (c === quote) quote = '';
			} else if (c === '"' || c === "'") quote = c;
			else if (c === '{') depth++;
			else if (c === '}') depth--;
		}
		theme += src.slice(m.index, i);
		at = i;
	}
	return { theme, rest: rest + src.slice(at) };
}

const declared = (css: string) => new Set([...css.matchAll(/(--[\w.-]+)\s*:/g)].map((m) => m[1]));

// The custom properties a stylesheet declares outside `@theme` under the name of
// a theme variable utilities read — Tailwind's defaults or the sheet's own `@theme`.
function shadowedTokens(css: string, defaults: string): string[] {
	const { theme, rest } = splitTheme(css);
	const themeVars = new Set([...declared(defaults), ...declared(theme)]);
	return [...declared(rest)].filter((t) => themeVars.has(t));
}

// A `:root` token's literal value (`#rrggbb` or `rgba(r, g, b, a)`), as sRGB 0–255 and alpha.
function tokenColour(name: string): { rgb: number[]; a: number } {
	const v = new RegExp(`${name}:\\s*([^;]+);`).exec(appCss)?.[1].trim() ?? '';
	const hex = /^#([0-9a-f]{6})$/i.exec(v);
	if (hex) return { rgb: [0, 2, 4].map((i) => parseInt(hex[1].slice(i, i + 2), 16)), a: 1 };
	const rgba = /^rgba\(([^)]+)\)$/.exec(v);
	if (!rgba) throw new Error(`${name} is not a literal colour: ${v}`);
	const [r, g, b, a] = rgba[1].split(',').map(Number);
	return { rgb: [r, g, b], a };
}
const linear = (c: number) => ((c /= 255) <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
const luminance = (rgb: number[]) => 0.2126 * linear(rgb[0]) + 0.7152 * linear(rgb[1]) + 0.0722 * linear(rgb[2]);
function contrast(x: number[], y: number[]): number {
	const [lo, hi] = [luminance(x), luminance(y)].sort((p, q) => p - q);
	return (hi + 0.05) / (lo + 0.05);
}
// OKLab ×100, the distance the palette comment states.
function oklab(rgb: number[]): number[] {
	const [r, g, b] = rgb.map(linear);
	const l = Math.cbrt(0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b);
	const m = Math.cbrt(0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b);
	const s = Math.cbrt(0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b);
	return [
		0.2104542553 * l + 0.793617785 * m - 0.0040720468 * s,
		1.9779984951 * l - 2.428592205 * m + 0.4505937099 * s,
		0.0259040371 * l + 0.7827717662 * m - 0.808675766 * s,
	].map((v) => v * 100);
}
const deltaE = (x: number[], y: number[]) => Math.hypot(...oklab(x).map((v, i) => v - oklab(y)[i]));
const over = (top: { rgb: number[]; a: number }, under: number[]) => top.rgb.map((c, i) => Math.round(c * top.a + under[i] * (1 - top.a)));

// A colour a mark is drawn in (a bar, a rule, a stroke or fill) that names a
// tag's `-text` shade — the shade is for text on the tag's tint only.
// Covers a style declaration, a chart option and a utility class, and a tag
// named through a template (`--tag-${…}-text`) as well as literally. A value
// ends at a comma, so the next field of an object on the same line is not read.
const TAG_TEXT = String.raw`--tag-(?:[a-z]+|\$\{[^}]*\})-text`;
const MARK_IN_TEXT_SHADE = new RegExp(
	String.raw`(?:(?:barColor|accent|border(?:-left)?(?:-color)?|stroke|fill|background(?:-color)?)\s*[=:][^;,"\n]*${TAG_TEXT}` +
		String.raw`|(?:border|bg|ring|outline|stroke|fill|from|to|divide|decoration)(?:-[a-z]+)?-\(${TAG_TEXT}\))`,
);

describe('console stylesheet', () => {
	it('a_tint_drawn_from_a_theme_colour_renders', async () => {
		const css = await build(['bg-(--error)/10', 'text-(--warning)/80', 'border-(--error)/30']);
		expect(css).toMatch(/\.bg-\\\(--error\\\)\\\/10\s*\{[^}]*color-mix\(in (?:oklab|srgb), var\(--error\) 10%, transparent\)/);
		expect(css).toMatch(/\.text-\\\(--warning\\\)\\\/80\s*\{[^}]*color-mix\([^)]*var\(--warning\) 80%/);
		expect(css).toMatch(/\.border-\\\(--error\\\)\\\/30\s*\{[^}]*color-mix\([^)]*var\(--error\) 30%/);
	});

	it('a_script_driven_control_takes_no_click_before_hydration_and_a_link_does', async () => {
		const css = (await build([])).replace(/\/\*[\s\S]*?\*\//g, '');
		// Every rule under the marker, as (selector, declarations).
		const rules = [...css.matchAll(/(\[data-hydrating\][^{}]*)\{([^}]*)\}/g)].map((m) => ({
			selector: m[1].trim(),
			body: m[2],
		}));
		// The blocked list is the argument of the first `:is(` after the marker,
		// read up to its own closing parenthesis — never into the `:not(...)`
		// exemption that follows it.
		const blocking = rules.find((r) => /pointer-events:\s*none/.test(r.body));
		expect(blocking).toBeDefined();
		const open = blocking!.selector.indexOf(':is(') + ':is('.length;
		let depth = 1;
		let end = open;
		while (depth > 0 && end < blocking!.selector.length) {
			const ch = blocking!.selector[end++];
			if (ch === '(') depth++;
			else if (ch === ')') depth--;
		}
		const blocked = blocking!.selector
			.slice(open, end - 1)
			.split(',')
			.map((s) => s.trim().replace(/'/g, '"'));
		expect(blocked).toContain('button');
		expect(blocked).toContain('[role="button"]');
		expect(blocked).toContain('select');
		// What works without script is not blocked: a link, a disclosure.
		expect(blocked).not.toContain('a');
		expect(blocked).not.toContain('summary');
		// And a link inside a blocked control is live again.
		const link = rules.find((r) => /^\[data-hydrating\]\s+a$/.test(r.selector));
		expect(link?.body).toMatch(/pointer-events:\s*auto/);
	});

	it('a_chip_outlined_in_its_own_text_colour_renders', async () => {
		const css = await build(['border-current/30']);
		expect(css).toMatch(/\.border-current\\\/30\s*\{[^}]*color-mix\(in (?:oklab|srgb), currentcolor 30%, transparent\)/i);
	});

	it('a_border_with_no_colour_draws_in_the_border_token', async () => {
		const css = (await build(['border'])).replace(/\/\*[\s\S]*?\*\//g, '');
		// Tailwind's base styles reset every element's border to `0 solid`, which
		// leaves its colour at the text colour; the last universal-rule border
		// colour, in the same layer, is the one an uncoloured border draws in.
		const universal = /\*, ::after, ::before, ::backdrop, ::file-selector-button\s*\{([^}]*)\}/g;
		const colours = [...css.matchAll(universal)].flatMap((m) => [...m[1].matchAll(/border-color:\s*([^;]+)/g)].map((d) => d[1].trim()));
		expect(colours.at(-1)).toBe('var(--border)');
		// The same for a placeholder: the last `::placeholder` rule's colour wins
		// over Tailwind's own, at the same specificity and in the same layer.
		const placeholders = [...css.matchAll(/(?:^|[{}])\s*::placeholder\s*\{([^}]*)\}/g)].flatMap((m) => [...m[1].matchAll(/(?:^|;)\s*color:\s*([^;]+)/g)].map((d) => d[1].trim()));
		expect(placeholders.length).toBeGreaterThan(1);
		expect(placeholders.at(-1)).toBe('var(--text-secondary)');
	});

	// Canonicalising costs about 3 ms per distinct utility — ~3 s for the
	// console's ~700 alone, ~9 s while the rest of the suite runs beside it —
	// past vitest's 5 s default; the bound is that cost, with room.
	it('every_class_is_written_in_its_canonical_form', { timeout: 30_000 }, async () => {
		// The design system and its canonicaliser are what Tailwind's editor tooling
		// runs; the API is marked unstable, so a Tailwind upgrade that renames it
		// fails here and the test follows it. A new rewrite it learns is a new
		// canonical form: the classes move to it.
		const ds = await __unstable__loadDesignSystem(appCss, { base: here, loadStylesheet });
		// The same option the editor's Tailwind tooling suggests with: a 16px root.
		const canonical = (c: string) => ds.canonicalizeCandidates([c], { rem: 16 })[0];
		// Positive control: the forms this rule exists to keep out are rewritten.
		expect(['bg-[var(--error)]/10', 'flex-shrink-0', 'min-w-[160px]'].map(canonical)).toEqual(['bg-(--error)/10', 'shrink-0', 'min-w-40']);
		// Each distinct candidate is compiled once (in one call: its answer is
		// positional) and canonicalised once — alone, since a batch answers with
		// its distinct results, not one per candidate.
		const found = candidatesInSource();
		const distinct = [...new Set(found.map(({ candidate }) => candidate))];
		const css = ds.candidatesToCss(distinct);
		const canonicalOf = new Map(distinct.filter((_, i) => css[i] !== null).map((c) => [c, canonical(c)]));
		const used = found.filter(({ candidate }) => canonicalOf.has(candidate));
		expect(used.length).toBeGreaterThan(1000);
		const off = used.filter(({ candidate }) => canonicalOf.get(candidate) !== candidate).map(({ file, candidate }) => `${file}: ${candidate} → ${canonicalOf.get(candidate)}`);
		expect(off).toEqual([]);
	});

	it('no_token_shadows_a_tailwind_theme_variable', () => {
		const defaults = readFileSync(resolve(tailwindDir, 'theme.css'), 'utf8');
		// Positive controls: a token named after a default, and one named after a
		// variable only the sheet's own `@theme` declares, past a quoted brace.
		const fixture = `@theme { --font-x: "a{b"; --color-brand: red; }
			:root { --radius-md: 1px; --color-brand: blue; --ui-own: 0; }`;
		expect(shadowedTokens(fixture, defaults).sort()).toEqual(['--color-brand', '--radius-md']);
		expect(declared(splitTheme(appCss).rest)).toContain('--ui-radius-md');
		expect(shadowedTokens(appCss, defaults)).toEqual([]);
	});

	it('every_tag_reads_on_its_tint_and_stays_apart_from_the_others', () => {
		const tags = [...appCss.matchAll(/--tag-([a-z]+)-text:/g)].map((m) => m[1]);
		expect(tags.length).toBe(10);
		// A tag sits on a card, or on a hovered row or tile.
		const surfaces = ['--bg-card', '--bg-elevated'];
		const low = surfaces.flatMap((surface) =>
			tags
				.map((t) => ({ t, ratio: contrast(tokenColour(`--tag-${t}-text`).rgb, over(tokenColour(`--tag-${t}-bg`), tokenColour(surface).rgb)) }))
				.filter(({ ratio }) => ratio < 4.5)
				.map(({ t, ratio }) => `${t} on ${surface} ${ratio.toFixed(2)}:1`),
		);
		expect(low).toEqual([]);
		// Positive control: the measure sees text that is too dim on its tint.
		expect(contrast([0xc0, 0x50, 0x7f], over(tokenColour('--tag-pink-bg'), tokenColour('--bg-card').rgb))).toBeLessThan(4.5);
		// Each tint is its own mark colour at 18%, so a retuned series moves both.
		const markOf = (t: string) => {
			const v = new RegExp(`--tag-${t}-mark:\\s*([^;]+);`).exec(appCss)?.[1].trim() ?? '';
			return tokenColour(/^var\((--[\w-]+)\)$/.exec(v)?.[1] ?? `--tag-${t}-mark`);
		};
		const drifted = tags.filter((t) => {
			const bg = tokenColour(`--tag-${t}-bg`);
			return bg.a !== 0.18 || bg.rgb.join() !== markOf(t).rgb.join();
		});
		expect(drifted).toEqual([]);
		const close: string[] = [];
		tags.forEach((a, i) =>
			tags.slice(i + 1).forEach((b) => {
				const d = deltaE(tokenColour(`--tag-${a}-text`).rgb, tokenColour(`--tag-${b}-text`).rgb);
				if (d < 8) close.push(`${a}/${b} ${d.toFixed(1)}`);
			}),
		);
		expect(close).toEqual([]);
		// Positive control: the measure sees a pair that is too close.
		expect(deltaE([0xff, 0xb4, 0x9a], [0xfd, 0xbe, 0xc1])).toBeLessThan(8);
	});

	it('no_mark_is_drawn_in_a_tag_text_shade', () => {
		// Positive and negative controls: a bar and a rule in the shade are caught,
		// the same shade as text is not.
		expect(MARK_IN_TEXT_SHADE.test("barColor: 'var(--tag-teal-text)',")).toBe(true);
		expect(MARK_IN_TEXT_SHADE.test('style="border-color: var(--tag-blue-text)"')).toBe(true);
		expect(MARK_IN_TEXT_SHADE.test("barColor: `var(--tag-${operationColor('fetch')}-text)`,")).toBe(true);
		expect(MARK_IN_TEXT_SHADE.test('class="border border-(--tag-violet-text)/30"')).toBe(true);
		expect(MARK_IN_TEXT_SHADE.test("accent: 'var(--tag-indigo-text)',")).toBe(true);
		expect(MARK_IN_TEXT_SHADE.test('style="color: var(--tag-blue-text)"')).toBe(false);
		expect(MARK_IN_TEXT_SHADE.test("accent: tagMarkColor('violet'), text: 'var(--tag-violet-text)'")).toBe(false);
		const scanner = new Scanner({ sources: [{ base: here, pattern: '**/*.{svelte,ts}', negated: false }] });
		scanner.scan();
		const hits = scanner.files
			.filter((file) => !/\/(paraglide|generated)\/|\.test\.ts$/.test(file))
			.flatMap((file) =>
				readFileSync(file, 'utf8')
					.split('\n')
					.map((line, i) => ({ line, at: `${file.slice(here.length + 1)}:${i + 1}` }))
					.filter(({ line }) => MARK_IN_TEXT_SHADE.test(line))
					.map(({ at }) => at),
			);
		expect(hits).toEqual([]);
	});
});
