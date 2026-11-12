import { describe, expect, it } from 'vitest';
import {
  MAX_ARGS,
  MAX_ENV,
  applyCommandLine,
  emptyLaunchForm,
  formFromLaunch,
  launchFromForm,
  launchProblem,
  sameLaunch,
  slugProblem,
  type LocalLaunch,
} from './localServer';

const launch: LocalLaunch = {
  command: 'npx',
  args: ['-y', '@example/server', '--root', '/home/me/My Files'],
  env: [
    { name: 'REGION', value: 'eu' },
    { name: 'EMPTY', value: '' },
    { name: 'WORKDIR' },
    { name: 'API_TOKEN', secret: true },
  ],
};

/** A hand-typed variable row holding a value. */
const valued = (name: string, value: string) => ({ name, value, developerFilled: false, secret: false, locked: false });

describe('formFromLaunch / launchFromForm', () => {
  it('reads a variable without a value as developer-filled, and a secret as a locked one', () => {
    const form = formFromLaunch(launch);
    expect(form.env).toEqual([
      { name: 'REGION', value: 'eu', developerFilled: false, secret: false, locked: false },
      { name: 'EMPTY', value: '', developerFilled: false, secret: false, locked: false },
      { name: 'WORKDIR', value: '', developerFilled: true, secret: false, locked: false },
      { name: 'API_TOKEN', value: '', developerFilled: true, secret: true, locked: true },
    ]);
  });

  it('gives back the command line it was read from', () => {
    expect(launchFromForm(formFromLaunch(launch))).toEqual(launch);
  });

  it('reads a null value as no value', () => {
    const form = formFromLaunch({ command: 'x', args: [], env: [{ name: 'A', value: null }] });
    expect(form.env[0].developerFilled).toBe(true);
    expect(launchFromForm(form).env).toEqual([{ name: 'A' }]);
  });

  it('never sends a value for a secret or a developer-filled variable', () => {
    const form = emptyLaunchForm();
    form.command = 'run';
    form.env = [
      { name: 'TOKEN', value: 'leak', developerFilled: true, secret: true, locked: true },
      { name: 'TICKED', value: 'leak', developerFilled: false, secret: true, locked: false },
      { name: 'HOME_DIR', value: 'typed-then-toggled', developerFilled: true, secret: false, locked: false },
    ];
    expect(launchFromForm(form).env).toEqual([
      { name: 'TOKEN', secret: true },
      { name: 'TICKED', secret: true },
      { name: 'HOME_DIR' },
    ]);
  });

  it('keeps every argument row as typed, an empty one included', () => {
    const out = launchFromForm({
      command: '  uvx  ',
      args: ['', ' padded ', '--flag=a b', ''],
      env: [valued(' NAME ', ' v ')],
    });
    expect(out).toEqual({
      command: 'uvx',
      args: ['', ' padded ', '--flag=a b', ''],
      env: [{ name: 'NAME', value: ' v ' }],
    });
  });

  it('keeps a variable without a name, which the command line is then refused for', () => {
    const out = launchFromForm({ command: 'run', args: [], env: [valued('  ', 'x')] });
    expect(out.env).toEqual([{ name: '', value: 'x' }]);
    expect(launchProblem(out)).toContain('needs a name');
  });
});

describe('applyCommandLine', () => {
  const secret = { name: 'API_TOKEN', value: '', developerFilled: true, secret: true, locked: true };

  it('replaces the command and the arguments', () => {
    const before = { command: 'npx', args: ['-y', 'old'], env: [] };
    const { form, keptSecrets } = applyCommandLine(before, { command: 'uvx', args: ['new'], env: [] });
    expect(form).toEqual({ command: 'uvx', args: ['new'], env: [] });
    expect(keptSecrets).toEqual([]);
    expect(before).toEqual({ command: 'npx', args: ['-y', 'old'], env: [] });
  });

  it('sets the value of the row of the same name, adds a row for a new name, and keeps the other rows', () => {
    const before = {
      command: 'npx',
      args: [],
      env: [
        valued('REGION', 'eu'),
        { name: ' WORKDIR ', value: '', developerFilled: true, secret: false, locked: false },
        { name: 'TICKED', value: '', developerFilled: true, secret: true, locked: false },
        valued('KEPT', 'k'),
      ],
    };
    const { form, keptSecrets } = applyCommandLine(before, {
      command: 'npx',
      args: [],
      env: [
        { name: 'REGION', value: 'us' },
        { name: 'WORKDIR', value: '/w' },
        { name: 'TICKED', value: 't' },
        { name: 'ADDED', value: '' },
      ],
    });
    expect(form.env).toEqual([
      valued('REGION', 'us'),
      valued(' WORKDIR ', '/w'),
      valued('TICKED', 't'),
      valued('KEPT', 'k'),
      valued('ADDED', ''),
    ]);
    expect(keptSecrets).toEqual([]);
    expect(before.env[0].value).toBe('eu');
  });

  it('leaves a locked secret as it is and reports its name', () => {
    const before = { command: 'npx', args: [], env: [secret, valued('REGION', 'eu')] };
    const { form, keptSecrets } = applyCommandLine(before, {
      command: 'npx',
      args: [],
      env: [
        { name: 'API_TOKEN', value: 'leak' },
        { name: 'REGION', value: 'us' },
      ],
    });
    expect(form.env).toEqual([secret, valued('REGION', 'us')]);
    expect(keptSecrets).toEqual(['API_TOKEN']);
    expect(launchFromForm(form).env).toEqual([
      { name: 'API_TOKEN', secret: true },
      { name: 'REGION', value: 'us' },
    ]);
  });
});

describe('sameLaunch', () => {
  it('holds for the command line a form was read from', () => {
    expect(sameLaunch(launchFromForm(formFromLaunch(launch)), launch)).toBe(true);
  });

  it('reads an absent list as an empty one, and a null value as no value', () => {
    expect(sameLaunch({ command: 'x' }, { command: 'x', args: [], env: [] })).toBe(true);
    expect(sameLaunch({ command: 'x', env: [{ name: 'A', value: null }] }, { command: 'x', env: [{ name: 'A' }] })).toBe(
      true,
    );
  });

  it('tells apart each thing a save can change', () => {
    const args = launch.args ?? [];
    const env = launch.env ?? [];
    const changed: LocalLaunch[] = [
      { ...launch, command: 'uvx' },
      { ...launch, args: [...args, ''] },
      { ...launch, args: [...args].reverse() },
      { ...launch, env: env.slice(1) },
      { ...launch, env: [...env].reverse() },
      { ...launch, env: env.map((e) => (e.name === 'REGION' ? { ...e, value: 'us' } : e)) },
      { ...launch, env: env.map((e) => (e.name === 'EMPTY' ? { name: 'EMPTY' } : e)) },
      { ...launch, env: env.map((e) => (e.name === 'WORKDIR' ? { name: 'WORKDIR', secret: true } : e)) },
      { ...launch, env: env.map((e) => (e.name === 'REGION' ? { ...e, name: 'ZONE' } : e)) },
    ];
    for (const other of changed) expect(sameLaunch(launch, other)).toBe(false);
  });
});

describe('slugProblem', () => {
  it('accepts a letter followed by up to 30 of a–z, 0–9 and -', () => {
    for (const ok of ['a', 'github', 'my-server-2', 'a'.repeat(31)]) expect(slugProblem(ok)).toBeNull();
  });

  it('refuses the empty slug, a 32nd character, a leading digit or dash, and any other character', () => {
    for (const bad of ['', 'a'.repeat(32), '1abc', '-abc', 'Abc', 'a_b', 'a b', 'a.b']) {
      expect(slugProblem(bad)).not.toBeNull();
    }
  });
});

describe('launchProblem', () => {
  const base = (over: Partial<LocalLaunch> = {}): LocalLaunch => ({ command: 'npx', args: [], env: [], ...over });

  it('accepts a command alone and the command line at its limits', () => {
    expect(launchProblem(base())).toBeNull();
    expect(
      launchProblem(
        base({
          args: Array.from({ length: MAX_ARGS }, (_, i) => `a${i}`),
          env: Array.from({ length: MAX_ENV }, (_, i) => ({ name: `V${i}` })),
        }),
      ),
    ).toBeNull();
  });

  it('refuses a missing command', () => {
    expect(launchProblem(base({ command: '' }))).toContain('command');
  });

  it('refuses one argument or one variable past the limit', () => {
    expect(launchProblem(base({ args: Array.from({ length: MAX_ARGS + 1 }, () => 'a') }))).toContain(String(MAX_ARGS));
    expect(
      launchProblem(base({ env: Array.from({ length: MAX_ENV + 1 }, (_, i) => ({ name: `V${i}` })) })),
    ).toContain(String(MAX_ENV));
  });

  it('refuses a name that is not an environment variable name, and accepts each allowed shape', () => {
    for (const bad of ['1A', 'A-B', 'A B', 'A=B', '']) {
      expect(launchProblem(base({ env: [{ name: bad }] }))).not.toBeNull();
    }
    for (const ok of ['A', '_a', 'a1_B2']) expect(launchProblem(base({ env: [{ name: ok }] }))).toBeNull();
  });

  it('refuses a variable declared twice', () => {
    expect(launchProblem(base({ env: [{ name: 'A', value: '1' }, { name: 'A' }] }))).toContain('twice');
  });
});
