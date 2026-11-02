#!/usr/bin/env node
// Generates admin-ui/src/lib/generated/providers.ts from the canonical provider
// seed (seeds/providers/providers.json) — the single source of provider identity
// (label, brand icon, default URL, native protocol). Keeping the frontend copy
// GENERATED (not hand-maintained) means ProviderIcon can render synchronously in
// both the admin and portal planes without depending on an admin-only endpoint.
//
//   node scripts/regen-provider-catalog.mjs           # write the module
//   node scripts/regen-provider-catalog.mjs --check    # fail on drift (build gate)
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
// Paths default to the repo layout; SEED_PATH / OUT_PATH override them so the
// admin-ui image build (which copies only admin-ui/ + the seed) can run --check.
const seedPath = process.env.SEED_PATH ? resolve(process.env.SEED_PATH) : join(root, 'seeds/providers/providers.json');
const outPath = process.env.OUT_PATH ? resolve(process.env.OUT_PATH) : join(root, 'admin-ui/src/lib/generated/providers.ts');

const rows = JSON.parse(readFileSync(seedPath, 'utf8'));
// Fold to the icon-registry key shape (getProvider folds its input the same way),
// so a provider value like `google_gemini` resolves to the `googlegemini` glyph.
const fold = (k) => k.toLowerCase().replace(/[_\s-]/g, '');

const providersEntries = rows
  .map((r) => `  ${JSON.stringify(fold(r.provider))}: { name: ${JSON.stringify(r.label)}, icon: ${JSON.stringify(r.icon)} },`)
  .join('\n');

const defaults = rows
  .filter((r) => !r.icon_only)
  .map((r) => `  { value: ${JSON.stringify(r.provider)}, label: ${JSON.stringify(r.label)}, defaultUrl: ${JSON.stringify(r.default_url ?? '')}, defaultApiFormat: ${JSON.stringify(r.default_api_format)}, defaultChatEndpointPath: ${JSON.stringify(r.chat_endpoint_path ?? '')}, defaultTransport: ${JSON.stringify(r.default_transport ?? 'default')} },`)
  .join('\n');

const out = `// GENERATED FILE — do not edit by hand.
// Source: seeds/providers/providers.json (the single source of provider identity).
// Regenerate: node scripts/regen-provider-catalog.mjs   (--check fails on drift).

export interface ProviderInfo {
  name: string;
  icon: string;
}

// Brand glyph + display name, keyed by the folded provider key (case/underscore
// insensitive). Includes icon-only registry entries (e.g. google, meta) surfaced
// in the downstream icon picker but not selectable as upstream providers.
export const PROVIDERS: Record<string, ProviderInfo> = {
${providersEntries}
};

export function getProvider(key: string): ProviderInfo {
  const lower = key.toLowerCase().replace(/[_\\s-]/g, '');
  if (PROVIDERS[lower]) return PROVIDERS[lower];
  const keys = Object.keys(PROVIDERS);
  for (let i = 0; i < keys.length; i++) {
    if (lower.indexOf(keys[i]) !== -1) return PROVIDERS[keys[i]];
  }
  return PROVIDERS.custom;
}

export interface ProviderDefault {
  value: string;
  label: string;
  defaultUrl: string;
  defaultApiFormat: string;
  defaultChatEndpointPath: string;
  /// How a new upstream for this provider is carried (URL shape + credential
  /// header). "default" is a plain bearer-auth endpoint.
  defaultTransport: string;
}

// Selectable upstream providers (icon-only entries excluded) with their default
// URL + native protocol, for the provider dropdown and URL auto-fill.
export const PROVIDER_DEFAULTS: ProviderDefault[] = [
${defaults}
];

export function providerDefaultUrl(value: string): string {
  return PROVIDER_DEFAULTS.find((p) => p.value === value)?.defaultUrl ?? '';
}

export function providerDefaultTransport(value: string): string {
  return PROVIDER_DEFAULTS.find((p) => p.value === value)?.defaultTransport ?? 'default';
}
`;

if (process.argv.includes('--check')) {
  let existing = '';
  try {
    existing = readFileSync(outPath, 'utf8');
  } catch {
    existing = '';
  }
  if (existing !== out) {
    console.error(
      'provider catalog drift: admin-ui/src/lib/generated/providers.ts is stale.\n' +
        'Run from the repository root: node scripts/regen-provider-catalog.mjs\n' +
        '(without Node: docker run --rm -v "$PWD:/w" -w /w node:24-alpine node scripts/regen-provider-catalog.mjs)',
    );
    process.exit(1);
  }
  console.log('provider catalog up to date');
} else {
  writeFileSync(outPath, out);
  console.log('wrote', outPath);
}
