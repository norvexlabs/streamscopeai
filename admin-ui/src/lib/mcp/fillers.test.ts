import { describe, expect, it } from 'vitest';
import { FILLER_HELP, FILLER_NAME, inputRoster } from './fillers';
import type { Remote } from './headerInputs';

const remote: Remote = {
  type: 'streamable-http',
  url: 'https://mcp.example.com/mcp',
  headers: [
    { name: 'X-Org', isRequired: true },
    { name: 'X-Region', isRequired: true, default: 'eu' },
    { name: 'X-Opt' },
    { name: 'X-Key', isSecret: true, isRequired: true },
    { name: 'X-User-Token', isSecret: true, isRequired: true },
    { name: 'X-Client', isRequired: true },
  ],
  _meta: {
    'ai.streamscope/inputs': {
      fillers: {
        'X-Org': 'admin',
        'X-Region': 'admin',
        'X-Opt': 'admin',
        'X-Key': 'admin',
        'X-User-Token': 'user',
        'X-Client': 'client',
      },
    },
  },
};

const byId = (rows: ReturnType<typeof inputRoster>) => Object.fromEntries(rows.map((r) => [r.id, r]));

describe('inputRoster', () => {
  it('flags a required administrator input without a value as missing, the rest by who fills them', () => {
    const r = byId(inputRoster(remote, {}, []));
    expect(r['X-Org'].state).toBe('missing');
    expect(r['X-Key'].state).toBe('missing');
    expect(r['X-Region'].state).toBe('unset');
    expect(r['X-Opt'].state).toBe('unset');
    expect(r['X-User-Token']).toMatchObject({ state: 'elsewhere', filler: 'user' });
    expect(r['X-Client']).toMatchObject({ state: 'elsewhere', filler: 'client' });
  });

  it('reads a set non-secret value and a stored secret as set, never showing the secret', () => {
    const r = byId(inputRoster(remote, { 'X-Org': 'acme', 'X-Key': 'leak' }, ['X-Key']));
    expect(r['X-Org']).toMatchObject({ state: 'set', value: 'acme' });
    expect(r['X-Key']).toMatchObject({ state: 'set', value: null });
  });

  it('does not count a value for a user input as the administrator having set it', () => {
    expect(byId(inputRoster(remote, { 'X-User-Token': 'x' }, ['X-User-Token']))['X-User-Token'].state).toBe('elsewhere');
  });
});

describe('filler wording', () => {
  it('names and explains every filler', () => {
    for (const f of ['admin', 'user', 'client'] as const) {
      expect(FILLER_NAME[f]).not.toBe('');
      expect(FILLER_HELP[f]).not.toBe('');
    }
    expect(FILLER_HELP.user).toContain('Sign-ins');
  });
});
