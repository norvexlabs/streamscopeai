import { describe, expect, it } from 'vitest';
import {
  authKind,
  changedUrlValues,
  catalogMeta,
  displayName,
  emptyServerJson,
  metaOf,
  parseServerJson,
  previewUrl,
  urlVariables,
  withCatalogMeta,
  type ServerJson,
} from './serverJson';

function doc(over: Record<string, unknown> = {}): ServerJson {
  const parsed = parseServerJson(JSON.stringify({ name: 'io.example/x', description: 'd', version: '1.0.0', ...over }));
  if ('error' in parsed) throw new Error(parsed.error);
  return parsed.doc;
}

describe('catalogMeta', () => {
  it('reads the gateway namespace and drops malformed fields', () => {
    const d = doc({
      _meta: {
        'ai.streamscope/catalog': {
          category: 'Dev',
          featured: true,
          liveness: 7,
          toolCount: 3,
          tools: [{ name: 'a', description: 'A' }, { nope: 1 }, { name: 'b' }],
          oauth: { issuerUrl: 'https://i', defaultScopes: ['r', 2] },
        },
      },
    });
    expect(catalogMeta(d)).toEqual({
      category: 'Dev',
      featured: true,
      toolCount: 3,
      tools: [{ name: 'a', description: 'A' }, { name: 'b' }],
      oauth: { issuerUrl: 'https://i', defaultScopes: ['r'] },
    });
  });

  it('reads an absent or non-object namespace as empty', () => {
    expect(catalogMeta(doc())).toEqual({});
    expect(catalogMeta(doc({ _meta: { 'ai.streamscope/catalog': 'x' } }))).toEqual({});
  });

  it('keeps an empty oauth object: the server runs discovery for it', () => {
    expect(catalogMeta(doc({ _meta: { 'ai.streamscope/catalog': { oauth: {} } } })).oauth).toEqual({});
  });
});

describe('withCatalogMeta', () => {
  it('replaces the gateway namespace and keeps every other one', () => {
    const d = doc({ _meta: { 'io.other/x': { a: 1 }, 'ai.streamscope/catalog': { category: 'Old' } } });
    const out = withCatalogMeta(d, { category: 'New', featured: false, tools: [] });
    expect(metaOf(out)).toEqual({ 'io.other/x': { a: 1 }, 'ai.streamscope/catalog': { category: 'New' } });
  });

  it('removes an emptied namespace, and _meta when nothing is left', () => {
    const d = doc({ _meta: { 'ai.streamscope/catalog': { category: 'Old' } } });
    expect(withCatalogMeta(d, {})._meta).toBeUndefined();
  });
});

describe('authKind', () => {
  it('reads OAuth from the hints, a key from a secret input, else headers or none', () => {
    expect(authKind(doc({ _meta: { 'ai.streamscope/catalog': { oauth: {} } } }))).toBe('oauth');
    expect(authKind(doc({ remotes: [{ url: 'https://x', headers: [{ name: 'Authorization', value: 'Bearer {t}', variables: { t: { isSecret: true } } }] }] }))).toBe('key');
    expect(authKind(doc({ remotes: [{ url: 'https://x', headers: [{ name: 'X-Org' }] }] }))).toBe('headers');
    expect(authKind(doc({ remotes: [{ url: 'https://x', headers: [{ name: 'X-Fixed', value: 'v' }] }] }))).toBe('none');
    expect(authKind(doc())).toBe('none');
  });
});

describe('parseServerJson', () => {
  it('refuses what is not a document', () => {
    expect('error' in parseServerJson('{')).toBe(true);
    expect('error' in parseServerJson('[]')).toBe(true);
    expect('error' in parseServerJson('{"name":"a","description":"b"}')).toBe(true);
    expect('error' in parseServerJson('{"name":"a","description":"b","version":"1","remotes":{}}')).toBe(true);
  });

  it('accepts a minimal document', () => {
    expect(displayName(doc())).toBe('io.example/x');
    expect(displayName(doc({ title: 'X' }))).toBe('X');
  });

  it('accepts a document that declares a package and no remote, keeping the package as written', () => {
    const packages = [{ registryType: 'npm', identifier: '@example/server', version: '1.2.3', transport: { type: 'stdio' } }];
    const d = doc({ packages });
    expect(d.remotes).toBeUndefined();
    expect(d.packages).toEqual(packages);
  });
});

describe('emptyServerJson', () => {
  it('starts with one streamable-HTTP remote', () => {
    expect(emptyServerJson().remotes).toEqual([{ type: 'streamable-http', url: '' }]);
  });
});

describe('previewUrl', () => {
  const remote = { url: 'https://{tenant}.example.com/{region}/mcp/{literal}', variables: { tenant: {}, region: { default: 'eu' } } };

  it('splices values and defaults, and leaves an undeclared or unfilled {var}', () => {
    expect(previewUrl(remote, { tenant: 'acme' })).toBe('https://acme.example.com/eu/mcp/{literal}');
    expect(previewUrl(remote, {})).toBe('https://{tenant}.example.com/eu/mcp/{literal}');
    expect(urlVariables(remote).map((v) => v.name)).toEqual(['tenant', 'region']);
  });
});

describe('changedUrlValues', () => {
  it('keeps only typed values that differ from the stored ones', () => {
    expect(changedUrlValues({ region: 'eu', tenant: 'acme' }, { region: 'us', tenant: 'acme' })).toEqual({ region: 'us' });
  });

  it('sends nothing for a blank field, which keeps the stored value', () => {
    expect(changedUrlValues({ region: 'eu' }, { region: '' })).toEqual({});
  });

  it('sends a variable that has no stored value yet', () => {
    expect(changedUrlValues({}, { region: 'eu', other: '' })).toEqual({ region: 'eu' });
  });
});
