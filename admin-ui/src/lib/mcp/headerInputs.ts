/**
 * The header inputs an MCP upstream declares (`server.json` `remotes[].headers`),
 * as the console edits them.
 *
 * A header is one of three shapes:
 * - an **input** — no `value`: the header's whole value is the input, id = the
 *   header name;
 * - a **fixed** header — a `value` naming no declared variable: sent as is, no
 *   input;
 * - a **template** — a `value` with `{var}` names declared in `variables`: each
 *   referenced variable is an input, id = `<header>/<var>`.
 *
 * Every input of an adopted upstream has one filler (`admin` | `user` |
 * `client`), kept in the remote's `_meta."ai.streamscope/inputs".fillers`. The
 * console keeps ONE filler per header row, so the variables of a template
 * always share a filler (the server refuses a mixed template), and offers
 * `client` only for a whole-header input (the server refuses a client-filled
 * template variable).
 *
 * The server validates every declaration again; these functions mirror its
 * reading only so the form can show the inputs a declaration produces.
 */
import type { components } from '../generated/api-types';

export type Remote = components['schemas']['Remote'];
export type RemoteType = components['schemas']['RemoteType'];
export type Input = components['schemas']['Input'];
type KeyValueInput = components['schemas']['KeyValueInput'];
export type Filler = components['schemas']['Filler'];

const INPUTS_META_KEY = 'ai.streamscope/inputs';

export type HeaderMode = 'input' | 'fixed' | 'template';

/** One variable of a template header, as edited. */
interface VariableRow {
  name: string;
  description: string;
  isSecret: boolean;
  isRequired: boolean;
  placeholder: string;
  /** Choices, comma-separated in the form. */
  choices: string;
}

/** One declared header, as edited. */
export interface HeaderRow {
  name: string;
  description: string;
  isSecret: boolean;
  isRequired: boolean;
  placeholder: string;
  choices: string;
  mode: HeaderMode;
  /** The fixed value or the `{var}` template; unused in `input` mode. */
  value: string;
  variables: VariableRow[];
  /** Who fills this header's input(s). Unused for a `fixed` header. */
  filler: Filler;
}

/** One input a declaration produces. */
export interface DeclaredInput {
  id: string;
  header: string;
  variable: string | null;
  input: Input;
  isSecret: boolean;
  isRequired: boolean;
}

/** The `{name}` tokens of a template, in order of first appearance. */
function templateTokens(template: string): string[] {
  const out: string[] = [];
  const re = /\{([^{}]*)\}/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(template)) !== null) {
    if (!out.includes(m[1])) out.push(m[1]);
  }
  return out;
}

/** The declared variables a template references, in order of first appearance.
 *  A `{x}` with no declared variable stays literal text. */
export function templateVars(template: string, declared: Record<string, Input> | undefined): string[] {
  const names = declared ?? {};
  return templateTokens(template).filter((t) => Object.hasOwn(names, t));
}

/** The inputs a remote declares, in declaration order. */
export function declaredInputs(remote: Remote): DeclaredInput[] {
  const out: DeclaredInput[] = [];
  for (const h of remote.headers ?? []) {
    if (h.value === undefined || h.value === null) {
      out.push({
        id: h.name,
        header: h.name,
        variable: null,
        input: h,
        isSecret: h.isSecret === true,
        isRequired: h.isRequired === true,
      });
      continue;
    }
    for (const v of templateVars(h.value, h.variables)) {
      const input = (h.variables ?? {})[v];
      out.push({
        id: `${h.name}/${v}`,
        header: h.name,
        variable: v,
        input,
        isSecret: input.isSecret === true || h.isSecret === true,
        isRequired: input.isRequired === true || h.isRequired === true,
      });
    }
  }
  return out;
}

/** The fillers recorded on a remote. */
export function remoteFillers(remote: Remote): Record<string, Filler> {
  return remote._meta?.[INPUTS_META_KEY]?.fillers ?? {};
}

const URL_HINT = /url|host|endpoint|domain|base|site|instance|region/i;

/** The filler an adopt or a new header starts with: an input that names a
 *  place to connect to (a URL, a host…) is the administrator's — a user-filled
 *  one would let a user point the gateway at a host its egress guard never
 *  vets — and everything else the user's. */
export function defaultFiller(d: Pick<DeclaredInput, 'id' | 'input'>): Filler {
  const text = [d.id, d.input.description ?? '', d.input.placeholder ?? ''].join(' ');
  const looksLikeUrl =
    URL_HINT.test(text) ||
    /^https?:\/\//i.test(d.input.default ?? '') ||
    /^https?:\/\//i.test(d.input.placeholder ?? '');
  return looksLikeUrl ? 'admin' : 'user';
}

/** The starting fillers of an adopt, one per header: a template whose
 *  variables would default differently goes to the administrator (the server
 *  refuses a template with mixed fillers, and a URL-looking variable must not
 *  be the user's). */
export function defaultFillers(inputs: DeclaredInput[]): Record<string, Filler> {
  const perHeader = new Map<string, Filler>();
  for (const d of inputs) {
    const f = defaultFiller(d);
    const prev = perHeader.get(d.header);
    perHeader.set(d.header, prev === undefined || prev === f ? f : 'admin');
  }
  return Object.fromEntries(inputs.map((d) => [d.id, perHeader.get(d.header) ?? 'user']));
}

/** Set one header's filler on every input it declares. */
export function withHeaderFiller(
  inputs: DeclaredInput[],
  fillers: Record<string, Filler>,
  header: string,
  filler: Filler,
): Record<string, Filler> {
  const next = { ...fillers };
  for (const d of inputs) if (d.header === header) next[d.id] = filler;
  return next;
}

/** The headers a declaration's inputs belong to, in order, with whether the
 *  header is a whole-header input (the only kind a client may fill). */
export function inputHeaders(inputs: DeclaredInput[]): Array<{ header: string; whole: boolean; ids: string[] }> {
  const out: Array<{ header: string; whole: boolean; ids: string[] }> = [];
  for (const d of inputs) {
    const g = out.find((x) => x.header === d.header);
    if (g) g.ids.push(d.id);
    else out.push({ header: d.header, whole: d.variable === null, ids: [d.id] });
  }
  return out;
}

/** Whether a filler is allowed for a header row: `client` only for a whole
 *  header (a template variable cannot be sent by the client). */
export function fillerAllowed(mode: HeaderMode, filler: Filler): boolean {
  return filler !== 'client' || mode === 'input';
}

function splitChoices(csv: string): string[] {
  return csv
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function inputFrom(row: {
  description: string;
  isSecret: boolean;
  isRequired: boolean;
  placeholder: string;
  choices: string;
}): Input {
  const input: Input = {};
  if (row.description.trim()) input.description = row.description.trim();
  if (row.isRequired) input.isRequired = true;
  if (row.isSecret) input.isSecret = true;
  if (row.placeholder.trim()) input.placeholder = row.placeholder.trim();
  const choices = splitChoices(row.choices);
  if (choices.length > 0) input.choices = choices;
  return input;
}

/** Fields of an `Input` the editor does not show, kept from the original so a
 *  save does not drop them (`default`, `format`). */
function carried(original: Input | undefined): Input {
  if (!original) return {};
  const out: Input = {};
  if (original.default !== undefined && original.default !== null) out.default = original.default;
  if (original.format !== undefined) out.format = original.format;
  return out;
}

/** The editor rows for a remote's headers. */
export function rowsFromRemote(remote: Remote): HeaderRow[] {
  const fillers = remoteFillers(remote);
  return (remote.headers ?? []).map((h) => {
    const vars = h.value != null ? templateVars(h.value, h.variables) : [];
    const mode: HeaderMode = h.value == null ? 'input' : vars.length > 0 ? 'template' : 'fixed';
    const firstId = mode === 'input' ? h.name : mode === 'template' ? `${h.name}/${vars[0]}` : null;
    return {
      name: h.name,
      description: h.description ?? '',
      isSecret: h.isSecret === true,
      isRequired: h.isRequired === true,
      placeholder: h.placeholder ?? '',
      choices: (h.choices ?? []).join(', '),
      mode,
      value: h.value ?? '',
      variables: Object.entries(h.variables ?? {}).map(([name, v]) => ({
        name,
        description: v.description ?? '',
        isSecret: v.isSecret === true,
        isRequired: v.isRequired === true,
        placeholder: v.placeholder ?? '',
        choices: (v.choices ?? []).join(', '),
      })),
      filler: (firstId !== null ? fillers[firstId] : undefined) ?? 'user',
    };
  });
}

/**
 * The `headers[]` and, when `withFillers`, the `_meta` fillers for the rows.
 * `original` is the remote the rows were read from: fields the editor does not
 * show (an input's `default` and `format`) are carried over by header name.
 */
export function remoteFromRows(
  base: { type: RemoteType; url: string; variables?: Record<string, Input> },
  rows: HeaderRow[],
  withFillers: boolean,
  original?: Remote,
): Remote {
  const byName = new Map((original?.headers ?? []).map((h) => [h.name.toLowerCase(), h]));
  const headers: KeyValueInput[] = [];
  const fillers: Record<string, Filler> = {};
  for (const row of rows) {
    const name = row.name.trim();
    if (!name) continue;
    const prev = byName.get(name.toLowerCase());
    const header: KeyValueInput = { name, ...carried(prev), ...inputFrom(row) };
    if (row.mode === 'fixed') {
      header.value = row.value;
      // A fixed header is no input: it carries no secret flag or default.
      delete header.isSecret;
      delete header.default;
    } else if (row.mode === 'template') {
      header.value = row.value;
      const variables: Record<string, Input> = {};
      for (const v of row.variables) {
        const vname = v.name.trim();
        if (!vname) continue;
        variables[vname] = { ...carried(prev?.variables?.[vname]), ...inputFrom(v) };
      }
      if (Object.keys(variables).length > 0) header.variables = variables;
    }
    headers.push(header);
    if (withFillers) {
      if (row.mode === 'input') fillers[name] = row.filler;
      if (row.mode === 'template') {
        for (const v of templateVars(row.value, header.variables)) fillers[`${name}/${v}`] = row.filler;
      }
    }
  }
  const remote: Remote = { type: base.type, url: base.url.trim() };
  if (base.variables && Object.keys(base.variables).length > 0) remote.variables = base.variables;
  if (headers.length > 0) remote.headers = headers;
  // Every `_meta` namespace but the gateway's is kept as the remote had it
  // (a vendor's object round-trips); the gateway's is rebuilt from the rows,
  // and left out when no filler is set.
  const meta: Record<string, unknown> = {};
  for (const [k, v] of Object.entries((original?._meta ?? {}) as Record<string, unknown>)) {
    if (k !== INPUTS_META_KEY) meta[k] = v;
  }
  if (withFillers && Object.keys(fillers).length > 0) meta[INPUTS_META_KEY] = { fillers };
  if (Object.keys(meta).length > 0) remote._meta = meta as Remote['_meta'];
  return remote;
}

/** A new empty header row. */
export function emptyHeaderRow(): HeaderRow {
  return {
    name: '',
    description: '',
    isSecret: false,
    isRequired: false,
    placeholder: '',
    choices: '',
    mode: 'input',
    value: '',
    variables: [],
    filler: 'user',
  };
}

/** The "Bearer token (shared)" preset: one admin-filled secret token sent as
 *  `Authorization: Bearer <token>` — the same for every user. */
export function bearerSharedRow(): HeaderRow {
  return {
    name: 'Authorization',
    description: 'Bearer token shared by every user',
    isSecret: true,
    isRequired: true,
    placeholder: '',
    choices: '',
    mode: 'template',
    value: 'Bearer {token}',
    variables: [
      { name: 'token', description: 'API token', isSecret: true, isRequired: true, placeholder: '', choices: '' },
    ],
    filler: 'admin',
  };
}

/** Problems the form can show before a save; the server refuses each too. */
export function rowWarnings(row: HeaderRow): string[] {
  const out: string[] = [];
  if (row.mode === 'template') {
    const declared = new Set(row.variables.map((v) => v.name.trim()).filter(Boolean));
    const tokens = templateTokens(row.value);
    for (const t of tokens) {
      if (!declared.has(t)) out.push(`{${t}} is not a declared variable and is sent literally`);
    }
    for (const v of declared) {
      if (!tokens.includes(v)) out.push(`variable ${v} is not used in the template`);
    }
    if (!tokens.some((t) => declared.has(t))) out.push('the template references no variable — it is a fixed header');
  }
  return out;
}

/** The lowercase header names a client must send for a remote. */
export function clientHeaderNames(remote: Remote): string[] {
  const fillers = remoteFillers(remote);
  const out: string[] = [];
  for (const d of declaredInputs(remote)) {
    if (fillers[d.id] === 'client') {
      const n = d.header.toLowerCase();
      if (!out.includes(n)) out.push(n);
    }
  }
  return out;
}

// ── values ─────────────────────────────────────────────────────────────────

/** What the form holds for one stored secret: keep it, replace it with
 *  `value`, or clear it. */
export interface SecretEdit {
  action: 'keep' | 'replace' | 'clear';
  value: string;
}

/** The admin values of a create or an adopt: a non-secret value under
 *  `inputs`, a secret one ONLY under `secret_inputs` (the audit trail blanks
 *  that key, never the other). Blank values are left out. */
export function splitAdminValues(
  inputs: DeclaredInput[],
  fillers: Record<string, Filler>,
  values: Record<string, string>,
): { inputs: Record<string, string>; secret_inputs: Record<string, string> } {
  const plain: Record<string, string> = {};
  const secret: Record<string, string> = {};
  for (const d of inputs) {
    if (fillers[d.id] !== 'admin') continue;
    const v = values[d.id] ?? '';
    if (v === '') continue;
    if (d.isSecret) secret[d.id] = v;
    else plain[d.id] = v;
  }
  return { inputs: plain, secret_inputs: secret };
}

/**
 * The three-state admin-value PATCH of an upstream edit.
 *
 * `inputs`: a changed non-secret value is set, one emptied is `null`
 * (cleared). `secret_inputs`: `null` would keep a value, so a kept secret is
 * simply left out; a replaced one is set; a cleared one is `""`. Only
 * admin-filled inputs are sent — a value for another filler is refused.
 */
export function adminValuesPatch(
  inputs: DeclaredInput[],
  fillers: Record<string, Filler>,
  current: { inputs: Record<string, string>; secret_input_ids: string[] },
  plain: Record<string, string>,
  secrets: Record<string, SecretEdit>,
): { inputs?: Record<string, string | null>; secret_inputs?: Record<string, string | null> } {
  const outPlain: Record<string, string | null> = {};
  const outSecret: Record<string, string | null> = {};
  for (const d of inputs) {
    if (fillers[d.id] !== 'admin') continue;
    if (d.isSecret) {
      const e = secrets[d.id];
      if (!e) continue;
      if (e.action === 'replace' && e.value !== '') outSecret[d.id] = e.value;
      else if (e.action === 'clear' && current.secret_input_ids.includes(d.id)) outSecret[d.id] = '';
    } else {
      const next = plain[d.id] ?? '';
      const prev = current.inputs[d.id];
      if (prev === undefined) {
        if (next !== '') outPlain[d.id] = next;
      } else if (next !== prev) {
        outPlain[d.id] = next === '' ? null : next;
      }
    }
  }
  const body: { inputs?: Record<string, string | null>; secret_inputs?: Record<string, string | null> } = {};
  if (Object.keys(outPlain).length > 0) body.inputs = outPlain;
  if (Object.keys(outSecret).length > 0) body.secret_inputs = outSecret;
  return body;
}

/** The required admin inputs that have neither a value nor a default. */
export function missingAdminValues(
  inputs: DeclaredInput[],
  fillers: Record<string, Filler>,
  has: (id: string) => boolean,
): string[] {
  return inputs
    .filter((d) => fillers[d.id] === 'admin' && d.isRequired && (d.input.default ?? '') === '' && !has(d.id))
    .map((d) => d.id);
}

/** One input of a portal connection, as the portal API describes it. */
export interface PortalInput {
  id: string;
  is_secret: boolean;
  filled: boolean;
  /** The user's own stored value of a NON-secret input, which the form
   *  prefills; absent or `null` for a secret one and when nothing is stored. */
  value?: string | null;
  is_required?: boolean;
  default?: string | null;
}

/** A stored value the form shows (prefilled), so editing the field edits it. */
function shownValue(i: PortalInput): string | null {
  return !i.is_secret && i.filled && typeof i.value === 'string' ? i.value : null;
}

/** The values a portal inputs form starts from: each shown stored value,
 *  every other field blank. */
export function portalInputsInitial(inputs: PortalInput[]): Record<string, string> {
  return Object.fromEntries(inputs.map((i) => [i.id, shownValue(i) ?? '']));
}

/**
 * The portal PATCH for a user's own inputs. A field prefilled with its
 * stored value sends nothing while unchanged, its new value when edited, and
 * `null` (erase) when emptied. A field whose stored value is not shown (a
 * secret) keeps it when left blank; `clear` lists the ids the user
 * explicitly cleared — a non-secret one is sent `null`, a secret one `""`
 * (a secret `null` keeps).
 */
export function portalInputsPatch(
  inputs: PortalInput[],
  values: Record<string, string>,
  clear: ReadonlySet<string>,
): { inputs?: Record<string, string | null>; secret_inputs?: Record<string, string | null> } {
  const plain: Record<string, string | null> = {};
  const secret: Record<string, string | null> = {};
  for (const i of inputs) {
    const v = values[i.id] ?? '';
    const bucket = i.is_secret ? secret : plain;
    const shown = shownValue(i);
    if (shown !== null && !clear.has(i.id)) {
      if (v === shown) continue;
      bucket[i.id] = v === '' ? null : v;
    } else if (v !== '') bucket[i.id] = v;
    else if (clear.has(i.id) && i.filled) bucket[i.id] = i.is_secret ? '' : null;
  }
  const body: { inputs?: Record<string, string | null>; secret_inputs?: Record<string, string | null> } = {};
  if (Object.keys(plain).length > 0) body.inputs = plain;
  if (Object.keys(secret).length > 0) body.secret_inputs = secret;
  return body;
}

/** The required inputs a save would leave without a value (no default, and
 *  nothing typed nor kept). */
export function portalInputsMissing(
  inputs: PortalInput[],
  values: Record<string, string>,
  clear: ReadonlySet<string>,
): string[] {
  return inputs
    .filter((i) => {
      if (!i.is_required || i.default != null || (values[i.id] ?? '') !== '') return false;
      const kept = i.filled && !clear.has(i.id) && shownValue(i) === null;
      return !kept;
    })
    .map((i) => i.id);
}
