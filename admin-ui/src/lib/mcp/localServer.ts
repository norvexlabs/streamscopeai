/**
 * A local MCP server's command line in the console: the form rows the editor
 * binds to, the `LocalLaunch` they describe and the hints mirroring the
 * server's rules. The one-line command the lists show is rendered by the
 * server (`command_line`), never here.
 *
 * A local server runs on each developer's machine; the console only stores
 * the command line that client provisioning writes into their client config.
 */
import type { components } from '../generated/api-types';

export type LocalLaunch = components['schemas']['LocalLaunch'];
type LocalEnv = components['schemas']['LocalEnv'];

/** The server's limits, mirrored as hints: the server is the authority. */
export const MAX_ARGS = 64;
export const MAX_ENV = 32;
const SLUG_PATTERN = /^[a-z][a-z0-9-]{0,30}$/;
const ENV_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;

/** One environment variable as the editor shows it. */
interface EnvRow {
  name: string;
  /** The value everyone gets; ignored while `developerFilled` or `secret`. */
  value: string;
  /** No value is stored: each developer fills it in their own config. */
  developerFilled: boolean;
  /** Declared secret: always developer-filled, and never holds a value. */
  secret: boolean;
  /** Secret in the loaded command line: the server keeps the mark for as long
   *  as the variable exists, so the editor never lets it be unticked. */
  locked: boolean;
}

/** The command line as the editor binds it. */
export interface LaunchForm {
  command: string;
  args: string[];
  env: EnvRow[];
}

export function emptyLaunchForm(): LaunchForm {
  return { command: '', args: [], env: [] };
}

/** The editor rows of a stored or prefilled command line. */
export function formFromLaunch(launch: LocalLaunch): LaunchForm {
  return {
    command: launch.command,
    args: [...(launch.args ?? [])],
    env: (launch.env ?? []).map((e) => {
      const secret = e.secret === true;
      const hasValue = !secret && e.value !== undefined && e.value !== null;
      return {
        name: e.name,
        value: hasValue ? (e.value ?? '') : '',
        developerFilled: !hasValue,
        secret,
        locked: secret,
      };
    }),
  };
}

/**
 * The command line the rows describe. Every argument row is one argument,
 * an empty one included: a row leaves only through its delete button. An
 * environment row is kept even without a name, for `launchProblem` to
 * refuse. A secret or developer-filled variable carries no value.
 */
export function launchFromForm(form: LaunchForm): LocalLaunch {
  return {
    command: form.command.trim(),
    args: [...form.args],
    env: form.env.map((r): LocalEnv => {
      const name = r.name.trim();
      if (r.secret) return { name, secret: true };
      if (r.developerFilled) return { name };
      return { name, value: r.value };
    }),
  };
}

/**
 * The rows after a pasted command line is applied to them: its command and
 * arguments replace the form's, and each of its variables sets the value of
 * the row of that name, or adds a row. A locked secret row is left as it is
 * and its name is reported in `keptSecrets`. Rows the line does not name
 * stay.
 */
export function applyCommandLine(
  form: LaunchForm,
  line: { command: string; args: readonly string[]; env: readonly { name: string; value: string }[] },
): { form: LaunchForm; keptSecrets: string[] } {
  const env = form.env.map((r) => ({ ...r }));
  const keptSecrets: string[] = [];
  for (const { name, value } of line.env) {
    const row = env.find((r) => r.name.trim() === name);
    if (!row) {
      env.push({ name, value, developerFilled: false, secret: false, locked: false });
    } else if (row.locked) {
      keptSecrets.push(name);
    } else {
      row.value = value;
      row.developerFilled = false;
      row.secret = false;
    }
  }
  return { form: { command: line.command, args: [...line.args], env }, keptSecrets };
}

/**
 * Whether two command lines start the same thing: the command, each
 * argument in order, and each variable's name, value and secrecy in order.
 */
export function sameLaunch(a: LocalLaunch, b: LocalLaunch): boolean {
  const shape = (l: LocalLaunch) =>
    JSON.stringify([
      l.command,
      l.args ?? [],
      (l.env ?? []).map((e) => [e.name, e.secret === true, e.secret === true ? null : (e.value ?? null)]),
    ]);
  return shape(a) === shape(b);
}

/** Why a slug is refused, or null. An empty slug is the caller's to allow. */
export function slugProblem(slug: string): string | null {
  if (SLUG_PATTERN.test(slug)) return null;
  return 'The slug is 1 to 31 characters, starts with a letter, and holds only a–z, 0–9 and "-".';
}

/** The first rule a command line breaks, or null. */
export function launchProblem(launch: LocalLaunch): string | null {
  if (launch.command === '') return 'Enter the command that starts the server.';
  const env = launch.env ?? [];
  if ((launch.args ?? []).length > MAX_ARGS) return `A command line holds at most ${MAX_ARGS} arguments.`;
  if (env.length > MAX_ENV) return `A command line holds at most ${MAX_ENV} environment variables.`;
  const seen = new Set<string>();
  for (const e of env) {
    if (e.name === '') return 'Every environment variable needs a name: name it or remove its row.';
    if (!ENV_NAME_PATTERN.test(e.name)) {
      return `"${e.name}" is not an environment variable name: letters, digits and "_", not starting with a digit.`;
    }
    if (seen.has(e.name)) return `The environment variable ${e.name} is declared twice.`;
    seen.add(e.name);
  }
  return null;
}
