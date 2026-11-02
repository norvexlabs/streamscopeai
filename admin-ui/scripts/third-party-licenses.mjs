// Writes the image's third-party licence list to stdout: every package the build
// bundled (`.bundled-packages.json`, written by vite.config.js) with the
// packages they depend on, tailwindcss, and every package in the production
// node_modules.
// Fails on a package that declares no licence, or one outside ACCEPTED: adding
// a licence there is a licensing decision, read in review.
// With `--sbom FILE`, it also writes a CycloneDX document of the bundled
// packages that are not also in the production node_modules: compiled into the
// build, no scanner of the image sees them, while a package the image installs
// is found there (listing it twice would report each of its advisories twice).
//
//   APP_VERSION=<v> node scripts/third-party-licenses.mjs [--sbom FILE] > THIRD_PARTY_LICENSES
import { readFileSync, readdirSync, existsSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { execFileSync } from 'node:child_process';

function fail(message) {
	console.error(`third-party-licenses: ${message}`);
	process.exit(1);
}

const ACCEPTED = new Set(['MIT', 'ISC', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', '0BSD', 'MPL-2.0', 'CC0-1.0', 'OFL-1.1']);

const pkgDir = (name) => join('node_modules', name);
const manifest = (dir) => JSON.parse(readFileSync(join(dir, 'package.json'), 'utf-8'));

// Where `dep`, required from the package at `from`, is installed: Node's lookup,
// the nearest node_modules walking up from the requiring package.
function resolveFrom(from, dep) {
	for (let dir = from; ; dir = dirname(dir)) {
		const candidate = join(dir, 'node_modules', dep);
		if (existsSync(join(candidate, 'package.json'))) return candidate;
		if (dir === '.' || dir === dirname(dir)) return null;
	}
}

// The bundled packages and everything they depend on. A bundled package or a
// required dependency that is not installed fails: the list would miss it.
const dirs = new Set();
const pending = JSON.parse(readFileSync('.bundled-packages.json', 'utf-8'));
while (pending.length) {
	const dir = pending.pop();
	if (dirs.has(dir)) continue;
	if (!existsSync(join(dir, 'package.json'))) fail(`${dir} is bundled but not installed`);
	dirs.add(dir);
	const m = manifest(dir);
	for (const dep of Object.keys(m.dependencies ?? {})) {
		const found = resolveFrom(dir, dep);
		if (found) pending.push(found);
		else if (!(dep in (m.optionalDependencies ?? {}))) fail(`${m.name} depends on ${dep}, which is not installed`);
	}
}
// The stylesheet carries CSS tailwindcss generates (its base styles), though
// no module of it is bundled.
if (!existsSync(join(pkgDir('tailwindcss'), 'package.json'))) fail('tailwindcss is not installed');
dirs.add(pkgDir('tailwindcss'));
const bundled = [...dirs];
// The production tree the image installs.
const prodIds = new Set();
const prod = execFileSync('npm', ['ls', '--omit=dev', '--all', '--parseable'], { encoding: 'utf-8' });
for (const line of prod.split('\n').slice(1)) {
	// The path from the first node_modules keeps a nested install's own copy.
	if (!line) continue;
	const at = line.indexOf('node_modules');
	if (at < 0) fail(`${line} is a production dependency outside node_modules`);
	// SvelteKit's sync writes its generated types there; npm lists the
	// directory as an extraneous package, but it is none and the image has none.
	if (line.slice(at) === 'node_modules/$app') continue;
	dirs.add(line.slice(at));
	const pm = manifest(line.slice(at));
	prodIds.add(`${pm.name}@${pm.version}`);
}

// An SPDX licence expression is accepted when it can be met with accepted
// licences only: an OR needs one accepted side, an AND both, AND binding tighter
// than OR, parentheses grouping. A `WITH` exception is read with its licence.
function accepted(expr) {
	const tokens = expr.match(/\(|\)|[^\s()]+/g) ?? [];
	let i = 0;
	const primary = () => {
		if (tokens[i] === '(') {
			i++;
			const v = or();
			if (tokens[i++] !== ')') fail(`unbalanced licence expression: ${expr}`);
			return v;
		}
		let id = tokens[i++];
		if (tokens[i] === 'WITH') { id += ` WITH ${tokens[i + 1]}`; i += 2; }
		return ACCEPTED.has(id);
	};
	const and = () => { let v = primary(); while (tokens[i] === 'AND') { i++; v = primary() && v; } return v; };
	const or = () => { let v = and(); while (tokens[i] === 'OR') { i++; v = and() || v; } return v; };
	const v = or();
	if (i !== tokens.length) fail(`unparsed licence expression: ${expr}`);
	return v;
}

const entries = [];
const refused = [];
for (const dir of dirs) {
	const m = manifest(dir);
	const license = typeof m.license === 'string' ? m.license : m.license?.type;
	if (!license || !accepted(license)) refused.push(`${m.name}@${m.version}: ${license ?? 'no licence declared'}`);
	// Every licence file it ships: LICENSE, LICENCE, COPYING, with any suffix
	// (LICENSE-MIT, LICENSE.md, …) or as a prefix (MIT-LICENSE).
	const files = readdirSync(dir)
		.filter((f) => /^(licen[cs]e|copying)([.\-_]|$)|[.\-_]licen[cs]e(\.|$)/i.test(f))
		.sort();
	entries.push({
		id: `${m.name}@${m.version}`,
		license,
		text: files.length
			? files.map((f) => readFileSync(join(dir, f), 'utf-8').trim()).join('\n\n')
			: `(The package carries no licence file; its package.json declares ${license}.)`
	});
}
if (refused.length) fail(`licence not accepted:\n  ${refused.join('\n  ')}`);

const sbomAt = process.argv.indexOf('--sbom');
if (sbomAt >= 0) {
	const file = process.argv[sbomAt + 1];
	if (!file) fail('--sbom needs a file');
	// One component per name and version: a package installed twice at one
	// version is one package. No serial number or timestamp, so the same
	// bundle writes the same document.
	const components = new Map();
	for (const dir of bundled) {
		const m = manifest(dir);
		// Installed in the image's node_modules as well: the image's own scan lists it.
		if (prodIds.has(`${m.name}@${m.version}`)) continue;
		const license = typeof m.license === 'string' ? m.license : m.license?.type;
		const purl = `pkg:npm/${m.name.replace(/^@/, '%40')}@${m.version}`;
		components.set(purl, {
			type: 'library',
			'bom-ref': purl,
			name: m.name,
			version: m.version,
			purl,
			licenses: [{ expression: license }]
		});
	}
	const sbom = {
		bomFormat: 'CycloneDX',
		specVersion: '1.5',
		version: 1,
		metadata: { component: { type: 'application', name: 'streamscopeai-console', version: process.env.APP_VERSION || 'unknown' } },
		components: [...components.values()].sort((a, b) => a.purl.localeCompare(b.purl))
	};
	writeFileSync(file, JSON.stringify(sbom, null, 2) + '\n');
}
entries.sort((a, b) => a.id.localeCompare(b.id));
process.stdout.write(
	'Third-party software in this image and the licences it is used under: the\n' +
		'packages the console bundles and the ones it runs on. Streamscope AI itself is\n' +
		'under the GNU Affero General Public License v3.0: see LICENSE and NOTICE beside\n' +
		'this file.\n' +
		entries.map((e) => `\n${'='.repeat(80)}\n${e.id} (${e.license})\n${'-'.repeat(80)}\n${e.text}\n`).join('')
);
