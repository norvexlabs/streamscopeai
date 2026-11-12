/**
 * Reading and writing a catalog entry's `server.json` document (MCP Registry
 * schema 2025-12-11) in the console.
 *
 * The gateway's own facts live in the document's extension point,
 * `_meta."ai.streamscope/catalog"` (category, featured, liveness, tools,
 * toolCount, OAuth hints). The API types `_meta` as an open object, so the
 * namespace is read through `catalogMeta`, which keeps only well-typed fields.
 */
import type { components } from '../generated/api-types';
import { declaredInputs, type Remote, type Input } from './headerInputs';

export type ServerJson = components['schemas']['ServerJson'];
export type CatalogMeta = components['schemas']['CatalogMeta'];
export type OAuthHints = components['schemas']['OAuthHints'];

const CATALOG_META_KEY = 'ai.streamscope/catalog';
const SERVER_JSON_SCHEMA =
  'https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json';

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' ? v : undefined;
}

function strings(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((s): s is string => typeof s === 'string') : [];
}

/** The `_meta` object of a document, as plain data. */
export function metaOf(doc: ServerJson): Record<string, unknown> {
  const meta: unknown = doc._meta;
  return isObject(meta) ? meta : {};
}

/** The gateway's catalog facts of a document; a malformed field reads as absent. */
export function catalogMeta(doc: ServerJson): CatalogMeta {
  const raw = metaOf(doc)[CATALOG_META_KEY];
  if (!isObject(raw)) return {};
  const out: CatalogMeta = {};
  const category = str(raw.category);
  if (category) out.category = category;
  if (raw.featured === true) out.featured = true;
  const liveness = str(raw.liveness);
  if (liveness) out.liveness = liveness;
  if (typeof raw.toolCount === 'number') out.toolCount = raw.toolCount;
  if (Array.isArray(raw.tools)) {
    out.tools = raw.tools.flatMap((t) => {
      if (!isObject(t) || typeof t.name !== 'string') return [];
      const d = str(t.description);
      return [d ? { name: t.name, description: d } : { name: t.name }];
    });
  }
  if (isObject(raw.oauth)) {
    const o = raw.oauth;
    const hints: OAuthHints = {};
    for (const k of ['issuerUrl', 'authorizationUrl', 'tokenUrl', 'revocationUrl'] as const) {
      const v = str(o[k]);
      if (v) hints[k] = v;
    }
    const scopes = strings(o.defaultScopes);
    if (scopes.length > 0) hints.defaultScopes = scopes;
    out.oauth = hints;
  }
  return out;
}

/**
 * `_meta` with the catalog namespace replaced by `meta` (removed when empty),
 * every other namespace kept.
 *
 * openapi-typescript types the spec's open `_meta` object as
 * `Record<string, never>`, which no value fits; the one cast below is the
 * boundary between the plain object built here and that generated type.
 */
export function withCatalogMeta(doc: ServerJson, meta: CatalogMeta): ServerJson {
  const next: Record<string, unknown> = { ...metaOf(doc) };
  const cleaned = Object.fromEntries(
    Object.entries(meta).filter(([, v]) => v !== undefined && v !== null && v !== false && !(Array.isArray(v) && v.length === 0)),
  );
  if (Object.keys(cleaned).length > 0) next[CATALOG_META_KEY] = cleaned;
  else delete next[CATALOG_META_KEY];
  const out: ServerJson = { ...doc };
  if (Object.keys(next).length > 0) out._meta = next as Record<string, never>;
  else delete out._meta;
  return out;
}

/** The name the console shows: `title`, else `name`. */
export function displayName(doc: ServerJson): string {
  return doc.title || doc.name;
}

/** How an entry's first remote authenticates, for the catalog badges. */
export type AuthKind = 'oauth' | 'key' | 'headers' | 'none';

export function authKind(doc: ServerJson): AuthKind {
  if (catalogMeta(doc).oauth) return 'oauth';
  const remote = doc.remotes?.[0];
  if (!remote) return 'none';
  const inputs = declaredInputs(remote);
  if (inputs.some((d) => d.isSecret)) return 'key';
  if (inputs.length > 0) return 'headers';
  return 'none';
}

/** Parse a pasted `server.json`. Only the shape the form needs is checked —
 *  the server validates the whole document on save. */
export function parseServerJson(text: string): { doc: ServerJson } | { error: string } {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (e: unknown) {
    return { error: `Not valid JSON: ${e instanceof Error ? e.message : String(e)}` };
  }
  if (!isObject(raw)) return { error: 'A server.json document is a JSON object.' };
  for (const k of ['name', 'description', 'version'] as const) {
    if (typeof raw[k] !== 'string') return { error: `"${k}" must be a string.` };
  }
  if (raw.remotes !== undefined && !Array.isArray(raw.remotes)) return { error: '"remotes" must be an array.' };
  if (raw._meta !== undefined && !isObject(raw._meta)) return { error: '"_meta" must be an object.' };
  // The fields checked above are the type's required ones; the rest is
  // validated by the server, which answers with the precise rule a field breaks.
  return { doc: raw as ServerJson };
}

/** A new, empty document with one streamable-HTTP remote. */
export function emptyServerJson(): ServerJson {
  return {
    $schema: SERVER_JSON_SCHEMA,
    name: '',
    description: '',
    version: '1.0.0',
    remotes: [{ type: 'streamable-http', url: '' }],
  };
}

/** The URL variables of a remote, in declaration order. */
export function urlVariables(remote: Remote): Array<{ name: string; input: Input }> {
  return Object.entries(remote.variables ?? {}).map(([name, input]) => ({ name, input }));
}

/** A remote's URL with each `{var}` replaced by its value; a variable left
 *  blank falls back to its default, else stays `{var}`. */
export function previewUrl(remote: Remote, values: Record<string, string>, useDefaults = true): string {
  const vars = remote.variables ?? {};
  return (remote.url ?? '').replace(/\{([^{}]*)\}/g, (whole, name: string) => {
    if (!Object.hasOwn(vars, name)) return whole;
    // An edit is finished from stored and typed values only (the server fills
    // a default at create and adopt, never at an edit): `useDefaults` false.
    const v = values[name] || (useDefaults ? vars[name].default : '') || '';
    return v === '' ? whole : v;
  });
}

/** The URL variable values an edit changes: each typed value that is not
 *  blank and differs from the stored one. The server merges them onto the
 *  stored values, so a blank field keeps its stored value. */
export function changedUrlValues(
  stored: Record<string, string>,
  typed: Record<string, string>,
): Record<string, string> {
  return Object.fromEntries(Object.entries(typed).filter(([k, v]) => v !== '' && v !== stored[k]));
}
