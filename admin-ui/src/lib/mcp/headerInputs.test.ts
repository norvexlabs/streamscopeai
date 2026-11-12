import { describe, expect, it } from 'vitest';
import {
  adminValuesPatch,
  bearerSharedRow,
  clientHeaderNames,
  declaredInputs,
  defaultFiller,
  defaultFillers,
  inputHeaders,
  withHeaderFiller,
  emptyHeaderRow,
  fillerAllowed,
  missingAdminValues,
  portalInputsInitial,
  portalInputsMissing,
  portalInputsPatch,
  remoteFillers,
  remoteFromRows,
  rowWarnings,
  rowsFromRemote,
  splitAdminValues,
  templateVars,
  type Remote,
} from './headerInputs';

const jira: Remote = {
  type: 'streamable-http',
  url: 'https://mcp.example.com/mcp',
  headers: [
    { name: 'X-Jira-Url', description: 'Your Jira base URL', isRequired: true },
    { name: 'X-Jira-Token', isSecret: true, isRequired: true },
    { name: 'Authorization', value: 'Bearer {token}', variables: { token: { isSecret: true, isRequired: true } } },
    { name: 'X-Client', value: 'gateway' },
  ],
  _meta: {
    'ai.streamscope/inputs': {
      fillers: { 'X-Jira-Url': 'admin', 'X-Jira-Token': 'user', 'Authorization/token': 'admin' },
    },
  },
};

describe('declaredInputs', () => {
  it('lists a whole header, a template variable, and no fixed header', () => {
    const ids = declaredInputs(jira).map((d) => d.id);
    expect(ids).toEqual(['X-Jira-Url', 'X-Jira-Token', 'Authorization/token']);
  });

  it('marks a template variable secret when the variable or its header is', () => {
    const r: Remote = {
      url: 'https://x',
      headers: [{ name: 'A', isSecret: true, value: '{k}', variables: { k: {} } }],
    };
    expect(declaredInputs(r)[0].isSecret).toBe(true);
    expect(declaredInputs(jira).find((d) => d.id === 'Authorization/token')?.isSecret).toBe(true);
    expect(declaredInputs(jira).find((d) => d.id === 'X-Jira-Url')?.isSecret).toBe(false);
  });

  it('reads an undeclared {x} as literal text, not an input', () => {
    expect(templateVars('Bearer {token} {other}', { token: {} })).toEqual(['token']);
    const r: Remote = { url: 'https://x', headers: [{ name: 'A', value: '{nope}' }] };
    expect(declaredInputs(r)).toEqual([]);
  });

  it('counts a variable used twice once', () => {
    expect(templateVars('{a}-{a}-{b}', { a: {}, b: {} })).toEqual(['a', 'b']);
  });
});

describe('defaultFiller', () => {
  it('gives a URL-looking input to the administrator', () => {
    expect(defaultFiller({ id: 'X-Jira-Url', input: {} })).toBe('admin');
    expect(defaultFiller({ id: 'X-Instance', input: {} })).toBe('admin');
    expect(defaultFiller({ id: 'X-Target', input: { description: 'Server hostname' } })).toBe('admin');
    expect(defaultFiller({ id: 'X-Target', input: { placeholder: 'https://jira.example.com' } })).toBe('admin');
    expect(defaultFiller({ id: 'X-Target', input: { default: 'http://localhost' } })).toBe('admin');
  });

  it('gives every other input to the user', () => {
    expect(defaultFiller({ id: 'X-Jira-Token', input: { isSecret: true } })).toBe('user');
    expect(defaultFiller({ id: 'Authorization/token', input: { description: 'API token' } })).toBe('user');
  });
});

describe('defaultFillers', () => {
  it('gives each header one filler, the administrator\'s when its variables disagree', () => {
    const r: Remote = {
      url: 'https://x',
      headers: [
        { name: 'X-Auth', value: '{who}@{key}', variables: { who: { description: 'Server hostname' }, key: { isSecret: true } } },
        { name: 'X-Token', isSecret: true },
      ],
    };
    expect(defaultFillers(declaredInputs(r))).toEqual({ 'X-Auth/who': 'admin', 'X-Auth/key': 'admin', 'X-Token': 'user' });
    expect(defaultFiller({ id: 'X-Auth/key', input: { isSecret: true } })).toBe('user');
  });
});

describe('withHeaderFiller / inputHeaders', () => {
  it('moves every variable of a header together', () => {
    const inputs = declaredInputs(jira);
    const f = withHeaderFiller(inputs, remoteFillers(jira), 'Authorization', 'user');
    expect(f['Authorization/token']).toBe('user');
    expect(f['X-Jira-Url']).toBe('admin');
    expect(inputHeaders(inputs)).toEqual([
      { header: 'X-Jira-Url', whole: true, ids: ['X-Jira-Url'] },
      { header: 'X-Jira-Token', whole: true, ids: ['X-Jira-Token'] },
      { header: 'Authorization', whole: false, ids: ['Authorization/token'] },
    ]);
  });
});

describe('fillerAllowed', () => {
  it('offers client only for a whole header', () => {
    expect(fillerAllowed('input', 'client')).toBe(true);
    expect(fillerAllowed('template', 'client')).toBe(false);
    expect(fillerAllowed('template', 'admin')).toBe(true);
    expect(fillerAllowed('template', 'user')).toBe(true);
  });
});

describe('rowsFromRemote / remoteFromRows', () => {
  it('round-trips a declaration with its fillers', () => {
    const rows = rowsFromRemote(jira);
    expect(rows.map((r) => r.mode)).toEqual(['input', 'input', 'template', 'fixed']);
    expect(rows.map((r) => r.filler).slice(0, 3)).toEqual(['admin', 'user', 'admin']);
    const back = remoteFromRows({ type: 'streamable-http', url: jira.url ?? '' }, rows, true, jira);
    expect(back).toEqual(jira);
  });

  it('records one filler for every variable of a template', () => {
    const row = { ...emptyHeaderRow(), name: 'X-Auth', mode: 'template' as const, value: '{user}:{pass}', filler: 'user' as const };
    row.variables = [
      { name: 'user', description: '', isSecret: false, isRequired: true, placeholder: '', choices: '' },
      { name: 'pass', description: '', isSecret: true, isRequired: true, placeholder: '', choices: '' },
    ];
    const r = remoteFromRows({ type: 'sse', url: 'https://x' }, [row], true);
    expect(remoteFillers(r)).toEqual({ 'X-Auth/user': 'user', 'X-Auth/pass': 'user' });
  });

  it("keeps a vendor's _meta namespace on both the upstream and the catalog form", () => {
    const vendor = { 'io.example/vendor': { tier: 'gold' } };
    const original = { type: 'streamable-http', url: 'https://x', _meta: { ...vendor, 'ai.streamscope/inputs': { fillers: { Old: 'user' } } } } as unknown as Remote;
    const up = remoteFromRows({ type: 'streamable-http', url: 'https://x' }, [bearerSharedRow()], true, original);
    expect((up._meta as Record<string, unknown>)['io.example/vendor']).toEqual(vendor['io.example/vendor']);
    expect(remoteFillers(up)).toEqual({ 'Authorization/token': 'admin' });
    const doc = remoteFromRows({ type: 'streamable-http', url: 'https://x' }, [bearerSharedRow()], false, original);
    expect(doc._meta).toEqual(vendor);
  });

  it('leaves out fillers for a catalog document, and a nameless row', () => {
    const r = remoteFromRows({ type: 'streamable-http', url: ' https://x ' }, [emptyHeaderRow(), bearerSharedRow()], false);
    expect(r._meta).toBeUndefined();
    expect(r.url).toBe('https://x');
    expect(r.headers?.map((h) => h.name)).toEqual(['Authorization']);
  });

  it('drops the secret flag of a fixed header and the variables of a whole header', () => {
    const fixed = { ...emptyHeaderRow(), name: 'X-Fixed', mode: 'fixed' as const, value: 'v', isSecret: true };
    const whole = { ...emptyHeaderRow(), name: 'X-Whole', variables: [{ name: 'a', description: '', isSecret: false, isRequired: false, placeholder: '', choices: '' }] };
    const r = remoteFromRows({ type: 'streamable-http', url: 'https://x' }, [fixed, whole], true);
    expect(r.headers?.[0]).toEqual({ name: 'X-Fixed', value: 'v' });
    expect(r.headers?.[1]).toEqual({ name: 'X-Whole' });
    expect(remoteFillers(r)).toEqual({ 'X-Whole': 'user' });
  });

  it('keeps a default and format the editor does not show', () => {
    const src: Remote = { url: 'https://x', headers: [{ name: 'X-Region', default: 'eu', format: 'string' }] };
    const r = remoteFromRows({ type: 'streamable-http', url: 'https://x' }, rowsFromRemote(src), false, src);
    expect(r.headers?.[0].default).toBe('eu');
  });

  it('builds the shared bearer preset as an admin secret', () => {
    const r = remoteFromRows({ type: 'streamable-http', url: 'https://x' }, [bearerSharedRow()], true);
    expect(r.headers?.[0].value).toBe('Bearer {token}');
    expect(remoteFillers(r)).toEqual({ 'Authorization/token': 'admin' });
    expect(declaredInputs(r)[0]).toMatchObject({ id: 'Authorization/token', isSecret: true, isRequired: true });
  });
});

describe('rowWarnings', () => {
  it('names an undeclared token, an unused variable, and a template with no variable', () => {
    const row = { ...emptyHeaderRow(), name: 'A', mode: 'template' as const, value: 'x {y}' };
    row.variables = [{ name: 'z', description: '', isSecret: false, isRequired: false, placeholder: '', choices: '' }];
    const w = rowWarnings(row);
    expect(w.some((s) => s.includes('{y}'))).toBe(true);
    expect(w.some((s) => s.includes('variable z'))).toBe(true);
    expect(w.some((s) => s.includes('fixed header'))).toBe(true);
  });

  it('is quiet for a sound template and a whole header', () => {
    expect(rowWarnings(bearerSharedRow())).toEqual([]);
    expect(rowWarnings(emptyHeaderRow())).toEqual([]);
  });
});

describe('clientHeaderNames', () => {
  it('lists the lowercase whole headers a client sends', () => {
    const r: Remote = { ...jira, _meta: { 'ai.streamscope/inputs': { fillers: { 'X-Jira-Url': 'admin', 'X-Jira-Token': 'client', 'Authorization/token': 'admin' } } } };
    expect(clientHeaderNames(r)).toEqual(['x-jira-token']);
    expect(clientHeaderNames(jira)).toEqual([]);
  });
});

describe('splitAdminValues', () => {
  it('puts a secret only under secret_inputs and skips blanks and other fillers', () => {
    const inputs = declaredInputs(jira);
    const fillers = remoteFillers(jira);
    const out = splitAdminValues(inputs, fillers, {
      'X-Jira-Url': 'https://jira',
      'Authorization/token': 's3cret',
      'X-Jira-Token': 'user-value',
    });
    expect(out).toEqual({ inputs: { 'X-Jira-Url': 'https://jira' }, secret_inputs: { 'Authorization/token': 's3cret' } });
    expect(splitAdminValues(inputs, fillers, { 'X-Jira-Url': '' })).toEqual({ inputs: {}, secret_inputs: {} });
  });
});

describe('adminValuesPatch', () => {
  const inputs = declaredInputs(jira);
  const fillers = remoteFillers(jira);
  const current = { inputs: { 'X-Jira-Url': 'https://old' }, secret_input_ids: ['Authorization/token'] };

  it('sends nothing when nothing changed', () => {
    expect(adminValuesPatch(inputs, fillers, current, { 'X-Jira-Url': 'https://old' }, { 'Authorization/token': { action: 'keep', value: '' } })).toEqual({});
  });

  it('sets a changed value and clears an emptied one with null', () => {
    expect(adminValuesPatch(inputs, fillers, current, { 'X-Jira-Url': 'https://new' }, {}).inputs).toEqual({ 'X-Jira-Url': 'https://new' });
    expect(adminValuesPatch(inputs, fillers, current, { 'X-Jira-Url': '' }, {}).inputs).toEqual({ 'X-Jira-Url': null });
  });

  it('replaces a secret, clears it with "", and never sends a secret null', () => {
    const rep = adminValuesPatch(inputs, fillers, current, { 'X-Jira-Url': 'https://old' }, { 'Authorization/token': { action: 'replace', value: 'n' } });
    expect(rep).toEqual({ secret_inputs: { 'Authorization/token': 'n' } });
    const clr = adminValuesPatch(inputs, fillers, current, { 'X-Jira-Url': 'https://old' }, { 'Authorization/token': { action: 'clear', value: '' } });
    expect(clr).toEqual({ secret_inputs: { 'Authorization/token': '' } });
    const blank = adminValuesPatch(inputs, fillers, current, { 'X-Jira-Url': 'https://old' }, { 'Authorization/token': { action: 'replace', value: '' } });
    expect(blank).toEqual({});
  });

  it('does not clear a secret that has no value, and sends nothing for a non-admin input', () => {
    const none = { inputs: {}, secret_input_ids: [] };
    expect(adminValuesPatch(inputs, fillers, none, {}, { 'Authorization/token': { action: 'clear', value: '' } })).toEqual({});
    expect(adminValuesPatch(inputs, fillers, none, { 'X-Jira-Token': 'v' }, {})).toEqual({});
  });

  it('sets a value for an input that newly became the administrator\'s', () => {
    const f = { ...fillers, 'X-Jira-Token': 'admin' as const };
    expect(adminValuesPatch(inputs, f, current, { 'X-Jira-Url': 'https://old' }, { 'X-Jira-Token': { action: 'replace', value: 't' } })).toEqual({ secret_inputs: { 'X-Jira-Token': 't' } });
  });
});

describe('missingAdminValues', () => {
  it('names a required admin input without a value or default', () => {
    const inputs = declaredInputs(jira);
    const fillers = remoteFillers(jira);
    expect(missingAdminValues(inputs, fillers, () => false)).toEqual(['X-Jira-Url', 'Authorization/token']);
    expect(missingAdminValues(inputs, fillers, (id) => id === 'X-Jira-Url')).toEqual(['Authorization/token']);
    const withDefault: Remote = { url: 'https://x', headers: [{ name: 'X-Region', isRequired: true, default: 'eu' }] };
    expect(missingAdminValues(declaredInputs(withDefault), { 'X-Region': 'admin' }, () => false)).toEqual([]);
  });
});

describe('portalInputsPatch', () => {
  const inputs = [
    { id: 'X-Org', is_secret: false, filled: true },
    { id: 'X-Token', is_secret: true, filled: true },
    { id: 'X-New', is_secret: false, filled: false },
  ];

  it('keeps a blank field and sends nothing', () => {
    expect(portalInputsPatch(inputs, {}, new Set())).toEqual({});
  });

  it('sets typed values under the right key', () => {
    expect(portalInputsPatch(inputs, { 'X-Org': 'acme', 'X-Token': 't', 'X-New': 'n' }, new Set())).toEqual({
      inputs: { 'X-Org': 'acme', 'X-New': 'n' },
      secret_inputs: { 'X-Token': 't' },
    });
  });

  it('clears a filled non-secret with null and a filled secret with ""', () => {
    expect(portalInputsPatch(inputs, {}, new Set(['X-Org', 'X-Token', 'X-New']))).toEqual({
      inputs: { 'X-Org': null },
      secret_inputs: { 'X-Token': '' },
    });
  });

  it('prefers a typed value over a clear', () => {
    expect(portalInputsPatch(inputs, { 'X-Token': 'v' }, new Set(['X-Token']))).toEqual({ secret_inputs: { 'X-Token': 'v' } });
  });
});

describe('portal inputs prefilled with the user\'s own values', () => {
  const inputs = [
    { id: 'X-Org', is_secret: false, filled: true, value: 'acme', is_required: true },
    { id: 'X-Token', is_secret: true, filled: true, value: null, is_required: true },
    { id: 'X-Leak', is_secret: true, filled: true, value: 'never-shown' },
    { id: 'X-New', is_secret: false, filled: false, value: null, is_required: true },
  ];

  it('prefills a stored non-secret value and leaves a secret blank', () => {
    expect(portalInputsInitial(inputs)).toEqual({ 'X-Org': 'acme', 'X-Token': '', 'X-Leak': '', 'X-New': '' });
  });

  it('sends nothing for an untouched form', () => {
    expect(portalInputsPatch(inputs, portalInputsInitial(inputs), new Set())).toEqual({});
  });

  it('sends an edited prefilled value', () => {
    expect(portalInputsPatch(inputs, { ...portalInputsInitial(inputs), 'X-Org': 'globex' }, new Set())).toEqual({
      inputs: { 'X-Org': 'globex' },
    });
  });

  it('erases a prefilled value the user emptied, and a blank secret keeps', () => {
    expect(portalInputsPatch(inputs, { 'X-Org': '', 'X-Token': '' }, new Set())).toEqual({ inputs: { 'X-Org': null } });
  });

  it('erases a prefilled value through Clear too', () => {
    expect(portalInputsPatch(inputs, { 'X-Org': '' }, new Set(['X-Org']))).toEqual({ inputs: { 'X-Org': null } });
  });

  it('counts an emptied prefilled required input as missing, a kept secret as present', () => {
    const v = { ...portalInputsInitial(inputs), 'X-Org': '' };
    expect(portalInputsMissing(inputs, v, new Set())).toEqual(['X-Org', 'X-New']);
  });

  it('counts nothing missing once every required input has a value', () => {
    const v = { ...portalInputsInitial(inputs), 'X-New': 'n' };
    expect(portalInputsMissing(inputs, v, new Set())).toEqual([]);
  });

  it('counts a cleared secret as missing, and a required input with a default as present', () => {
    const withDefault = [...inputs, { id: 'X-Def', is_secret: false, filled: false, is_required: true, default: 'd' }];
    expect(portalInputsMissing(withDefault, { 'X-Org': 'acme', 'X-New': 'n' }, new Set(['X-Token']))).toEqual(['X-Token']);
  });
});
