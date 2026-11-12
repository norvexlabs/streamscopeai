import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { parseCommandLine } from './parseCommandLine';

const ok = (env: { name: string; value: string }[], command: string, args: string[]) => ({
  ok: true,
  env,
  command,
  args,
});

describe('parseCommandLine', () => {
  it('splits words on a space, a tab and a newline only', () => {
    // A no-break, an em or an ideographic space is a character of its word:
    // the form then shows it, and the server refuses it by its own rule.
    for (const space of ['\u00a0', '\u2003', '\u3000', '\r', '\u000b']) {
      expect(parseCommandLine(`npx${space}-y pkg`)).toEqual(ok([], `npx${space}-y`, ['pkg']));
    }
    expect(parseCommandLine('npx \t\n -y')).toEqual(ok([], 'npx', ['-y']));
  });

  const SCRIPT = {
    ok: false,
    error: 'This is a shell script, not one command line — nothing goes through a shell.',
  };

  it.each([
    'npx -y a; rm -rf x',
    'npx -y a && b',
    'npx -y a & b',
    'npx -y a | tee log',
    'npx -y a > out',
    'npx -y a < in',
    '(npx -y a)',
    'npx -y `whoami`',
    'npx -y $(whoami)',
    'npx -y a # a comment',
    '# npx -y a',
    'A=1;npx',
  ])('refuses the unquoted shell syntax of %s', (line) => {
    expect(parseCommandLine(line)).toEqual(SCRIPT);
  });

  it.each([
    ["npx -y 'a; b' \"c | d\" e\\&f", ['-y', 'a; b', 'c | d', 'e&f']],
    ['npx a#b $HOME ${x} $ "$(date)" \'`id`\'', ['a#b', '$HOME', '${x}', '$', '$(date)', '`id`']],
    ['npx \\# "#" \'#\'', ['#', '#', '#']],
  ])('takes quoted or escaped shell syntax as text: %s', (line, args) => {
    expect(parseCommandLine(line)).toEqual(ok([], 'npx', args));
  });

  it('splits plain words on any run of whitespace', () => {
    expect(parseCommandLine('npx -y @example/server')).toEqual(ok([], 'npx', ['-y', '@example/server']));
    expect(parseCommandLine('  npx \t -y\n@example/server  ')).toEqual(ok([], 'npx', ['-y', '@example/server']));
    expect(parseCommandLine('uvx')).toEqual(ok([], 'uvx', []));
  });

  it('takes everything between single quotes literally', () => {
    expect(parseCommandLine(`run 'two words' 'a "b" \\ $HOME'`)).toEqual(ok([], 'run', ['two words', 'a "b" \\ $HOME']));
  });

  it('drops a backslash inside double quotes only before ", \\, $ and `', () => {
    expect(parseCommandLine('run "two words" "say \\"hi\\"" "a\\\\b" "it\'s"')).toEqual(
      ok([], 'run', ['two words', 'say "hi"', 'a\\b', "it's"]),
    );
    expect(parseCommandLine('run "\\$" "\\$HOME" "\\`" "\\`id\\`"')).toEqual(ok([], 'run', ['$', '$HOME', '`', '`id`']));
  });

  it('keeps a backslash inside double quotes before any other character', () => {
    expect(parseCommandLine('run "\\a" "c\\nd" "C:\\dir" "\\\'" "\\ "')).toEqual(
      ok([], 'run', ['\\a', 'c\\nd', 'C:\\dir', "\\'", '\\ ']),
    );
  });

  it('removes a backslash-newline inside double quotes', () => {
    expect(parseCommandLine('run "a\\\nb" "\\\n"')).toEqual(ok([], 'run', ['ab', '']));
  });

  it('removes a backslash-newline outside quotes, where it neither joins nor splits words', () => {
    expect(parseCommandLine('run a\\\nb c \\\n d\\\n')).toEqual(ok([], 'run', ['ab', 'c', 'd']));
    expect(parseCommandLine('A\\\n=1 npx \\\n  -y pkg')).toEqual(ok([{ name: 'A', value: '1' }], 'npx', ['-y', 'pkg']));
    expect(parseCommandLine('\\\n')).toEqual({ ok: false, error: expect.stringContaining('empty') });
  });

  it('joins quoted and unquoted pieces that touch into one word, and keeps an empty quoted word', () => {
    expect(parseCommandLine(`run --root='/My Files'/x "" ''`)).toEqual(ok([], 'run', ['--root=/My Files/x', '', '']));
  });

  it('reads a backslash outside quotes as escaping the next character', () => {
    expect(parseCommandLine('cat my\\ file a\\\\b \\"q \\\'s')).toEqual(ok([], 'cat', ['my file', 'a\\b', '"q', "'s"]));
  });

  it('reads the leading NAME=value words as the environment', () => {
    expect(parseCommandLine(`REGION=eu _a1=x NAME='two words' Q="a \\"b\\"" EMPTY= npx -y pkg`)).toEqual(
      ok(
        [
          { name: 'REGION', value: 'eu' },
          { name: '_a1', value: 'x' },
          { name: 'NAME', value: 'two words' },
          { name: 'Q', value: 'a "b"' },
          { name: 'EMPTY', value: '' },
        ],
        'npx',
        ['-y', 'pkg'],
      ),
    );
  });

  it('keeps a value holding "=" whole', () => {
    expect(parseCommandLine('URL=http://h/?a=b run')).toEqual(ok([{ name: 'URL', value: 'http://h/?a=b' }], 'run', []));
  });

  it('keeps the first position and the last value of a variable set twice', () => {
    expect(parseCommandLine('A=1 B=2 A=3 run')).toEqual(
      ok(
        [
          { name: 'A', value: '3' },
          { name: 'B', value: '2' },
        ],
        'run',
        [],
      ),
    );
  });

  it('reads a NAME=value word after the command as an argument', () => {
    expect(parseCommandLine('A=1 run --x=y B=2')).toEqual(ok([{ name: 'A', value: '1' }], 'run', ['--x=y', 'B=2']));
  });

  it('reads a word that is not NAME=value as the command, whatever "=" it holds', () => {
    expect(parseCommandLine('1A=x run')).toEqual(ok([], '1A=x', ['run']));
    expect(parseCommandLine('A-B=x run')).toEqual(ok([], 'A-B=x', ['run']));
    expect(parseCommandLine('=x run')).toEqual(ok([], '=x', ['run']));
  });

  it('reads a word whose NAME= is quoted or escaped as the command', () => {
    expect(parseCommandLine(`'A=1' run`)).toEqual(ok([], 'A=1', ['run']));
    expect(parseCommandLine('"A"=1 run')).toEqual(ok([], 'A=1', ['run']));
    expect(parseCommandLine('A\\=1 run')).toEqual(ok([], 'A=1', ['run']));
  });

  it('refuses empty and whitespace-only input', () => {
    expect(parseCommandLine('')).toEqual({ ok: false, error: expect.stringContaining('empty') });
    expect(parseCommandLine(' \t\n ')).toEqual({ ok: false, error: expect.stringContaining('empty') });
  });

  it('refuses an unterminated single quote', () => {
    expect(parseCommandLine("run 'never closed")).toEqual({ ok: false, error: expect.stringContaining('single quote') });
  });

  it('refuses an unterminated double quote, an escaped closing one included', () => {
    expect(parseCommandLine('run "never closed')).toEqual({ ok: false, error: expect.stringContaining('double quote') });
    expect(parseCommandLine('run "ends escaped\\"')).toEqual({ ok: false, error: expect.stringContaining('double quote') });
  });

  it('refuses a trailing backslash', () => {
    expect(parseCommandLine('run arg\\')).toEqual({ ok: false, error: expect.stringContaining('backslash') });
  });

  it('refuses a line that only sets variables', () => {
    expect(parseCommandLine('A=1 B=2')).toEqual({ ok: false, error: expect.stringContaining('no command') });
  });
});

/**
 * The server renders a stored command line as the one line the lists show,
 * and that line is what an administrator copies back into the paste field.
 * `render` restates that renderer's rule: a part made only of ASCII letters,
 * digits and `_@%+:,./-` is written as it is; any other part, an empty one
 * included, goes between single quotes with each `'` written `'\''`. The
 * line is every variable that has a value as `NAME=` + its quoted value,
 * then the quoted command, then each quoted argument, joined by one space.
 */
interface EnvPart {
  name: string;
  value: string | null;
}

function quoted(part: string): string {
  return /^[A-Za-z0-9_@%+:,./-]+$/.test(part) ? part : `'${part.replace(/'/g, "'\\''")}'`;
}

function render(env: EnvPart[], command: string, args: string[]): string {
  return [
    ...env.flatMap((e) => (e.value === null ? [] : [`${e.name}=${quoted(e.value)}`])),
    quoted(command),
    ...args.map(quoted),
  ].join(' ');
}

/** What the parser gives for a line rendered from these parts. */
function readBack(env: EnvPart[], command: string, args: string[]) {
  return ok(
    env.flatMap((e) => (e.value === null ? [] : [{ name: e.name, value: e.value }])),
    command,
    args,
  );
}

describe('parseCommandLine reads back what the server renders', () => {
  const fixtures: { line: string; env: EnvPart[]; command: string; args: string[] }[] = [
    {
      line: "API_KEY='a b' npx -y @scope/pkg@1.0.0 'it'\\''s'",
      env: [{ name: 'API_KEY', value: 'a b' }],
      command: 'npx',
      args: ['-y', '@scope/pkg@1.0.0', "it's"],
    },
    {
      line: "REGION=eu uvx mcp-server '--root=/srv'",
      env: [
        { name: 'REGION', value: 'eu' },
        { name: 'TOKEN', value: null },
      ],
      command: 'uvx',
      args: ['mcp-server', '--root=/srv'],
    },
    {
      line: `'/opt/my tools/run' '' '$HOME' 'a"b\\c' '~/x' '#1'`,
      env: [],
      command: '/opt/my tools/run',
      args: ['', '$HOME', 'a"b\\c', '~/x', '#1'],
    },
    {
      line: "EMPTY='' 'A=b' 'two\nlines'",
      env: [{ name: 'EMPTY', value: '' }],
      command: 'A=b',
      args: ['two\nlines'],
    },
  ];

  it.each(fixtures)('renders and reads back $line', ({ line, env, command, args }) => {
    expect(render(env, command, args)).toBe(line);
    expect(parseCommandLine(line)).toEqual(readBack(env, command, args));
  });

  // Every part is any string: the characters a shell gives a meaning to are
  // drawn often, any code point otherwise. No command is excluded:
  //  - an empty command is rendered `''`, which reads back as a command that
  //    is the empty string;
  //  - a command spelling `NAME=value` is rendered between quotes, `=` not
  //    being a bare character, and a quoted `NAME=` is a word, never an
  //    assignment.
  // The environment is the one constrained input: a name is a shell variable
  // name and appears once, as the server stores it, because the parser folds
  // a name set twice into one variable. A variable with no value is not
  // rendered, so it is not read back.
  const part = () =>
    fc.string({
      unit: fc.oneof(
        fc.constantFrom(
          "'", '"', '\\', '$', '`', ' ', '\t', '\n', '=', '#', '~', 'a', 'Z', '0', '-', '/', 'é', '日', '😀',
          ';', '&', '|', '<', '>', '(', ')', '\u00a0', '\u2003', '\u3000',
        ),
        fc.string({ unit: 'binary', minLength: 1, maxLength: 1 }),
      ),
    });
  const envParts = () =>
    fc.uniqueArray(
      fc.record({
        name: fc.stringMatching(/^[A-Za-z_][A-Za-z0-9_]*$/),
        value: fc.option(part(), { nil: null }),
      }),
      { selector: (e) => e.name, maxLength: 6 },
    );

  it('gives back exactly the command, arguments and valued variables of any rendered line', () => {
    fc.assert(
      fc.property(envParts(), part(), fc.array(part(), { maxLength: 8 }), (env, command, args) => {
        expect(parseCommandLine(render(env, command, args))).toEqual(readBack(env, command, args));
      }),
    );
  });

  // The renderer quotes every character a shell reads, so a rendered line is
  // never a script; the same line with one of them typed bare, as a word of
  // its own or glued to the last one, always is — whatever the parts hold.
  it('refuses any rendered line once a shell operator is typed outside quotes', () => {
    fc.assert(
      fc.property(
        envParts(),
        part(),
        fc.array(part(), { maxLength: 4 }),
        fc.constantFrom(';', '&', '|', '<', '>', '(', ')', '`', '$(', '&&', '||'),
        fc.boolean(),
        (env, command, args, operator, glued) => {
          const line = `${render(env, command, args)}${glued ? '' : ' '}${operator} next`;
          expect(parseCommandLine(line)).toEqual({
            ok: false,
            error: 'This is a shell script, not one command line — nothing goes through a shell.',
          });
        },
      ),
    );
  });
});
