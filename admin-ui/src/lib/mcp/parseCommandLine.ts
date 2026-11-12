/**
 * Splits a pasted command line into the environment variables set before
 * the command, the command and its arguments, by POSIX shell quoting:
 *
 * - a space, a tab and a newline separate words — nothing else does: a
 *   no-break or ideographic space stays inside its word, where the server
 *   refuses it as it does any character that does not show;
 * - outside quotes, what only a shell gives a meaning to is refused, the
 *   line left as it is: `;`, `&`, `|`, `<`, `>`, `(`, `)`, a backtick, `$(`,
 *   and a `#` that starts a word. A local server is one command started
 *   directly — nothing goes through a shell;
 * - single quotes take everything up to the next single quote literally;
 * - inside double quotes a backslash is an escape only before `"`, `\`,
 *   `$`, `` ` `` and a newline: before the first four it is dropped and the
 *   character kept, a backslash-newline is a line continuation and both
 *   characters are dropped, and before any other character the backslash
 *   stays, both characters kept;
 * - outside quotes, a backslash makes the next character literal, and a
 *   backslash-newline is a line continuation: both characters are dropped;
 * - a leading run of `NAME=value` words is the environment, where `NAME=`
 *   is typed outside any quote (`NAME='two words'` is one variable, and
 *   `'NAME=x'` is a word like any other);
 * - the first other word is the command, and every word after it an
 *   argument, `--x=y` included.
 *
 * Nothing is expanded: no variable, glob, tilde or substitution. A variable
 * set twice keeps its first position and its last value.
 */

type ParsedCommandLine =
  | { ok: true; env: { name: string; value: string }[]; command: string; args: string[] }
  | { ok: false; error: string };

const ASSIGNMENT = /^([A-Za-z_][A-Za-z0-9_]*)=/;

const SHELL_SCRIPT = 'This is a shell script, not one command line — nothing goes through a shell.';
const SHELL_OPERATORS = ';&|<>()`';

interface Word {
  text: string;
  /** How many leading characters of `text` were typed outside any quote and
   *  without a backslash. */
  plainPrefix: number;
}

function splitWords(line: string): { ok: true; words: Word[] } | { ok: false; error: string } {
  const words: Word[] = [];
  let text = '';
  let inWord = false;
  let plainPrefix = Number.POSITIVE_INFINITY;
  const endPlain = () => {
    if (plainPrefix > text.length) plainPrefix = text.length;
  };
  const push = () => {
    if (!inWord) return;
    words.push({ text, plainPrefix: Math.min(plainPrefix, text.length) });
    text = '';
    inWord = false;
    plainPrefix = Number.POSITIVE_INFINITY;
  };

  let i = 0;
  while (i < line.length) {
    const c = line[i];
    if (c === ' ' || c === '\t' || c === '\n') {
      push();
      i += 1;
    } else if (c === "'") {
      const close = line.indexOf("'", i + 1);
      if (close < 0) return { ok: false, error: 'A single quote is never closed.' };
      endPlain();
      inWord = true;
      text += line.slice(i + 1, close);
      i = close + 1;
    } else if (c === '"') {
      endPlain();
      inWord = true;
      i += 1;
      let closed = false;
      while (i < line.length) {
        const d = line[i];
        if (d === '"') {
          closed = true;
          i += 1;
          break;
        }
        const escaped = d === '\\' ? line[i + 1] : undefined;
        if (escaped === '"' || escaped === '\\' || escaped === '$' || escaped === '`') {
          text += escaped;
          i += 2;
        } else if (escaped === '\n') {
          i += 2;
        } else {
          text += d;
          i += 1;
        }
      }
      if (!closed) return { ok: false, error: 'A double quote is never closed.' };
    } else if (c === '\\') {
      if (i + 1 >= line.length) return { ok: false, error: 'The line ends with a backslash that escapes nothing.' };
      if (line[i + 1] === '\n') {
        // A line continuation: it neither starts nor ends a word.
        i += 2;
      } else {
        endPlain();
        inWord = true;
        text += line[i + 1];
        i += 2;
      }
    } else if (SHELL_OPERATORS.includes(c) || (c === '$' && line[i + 1] === '(') || (c === '#' && !inWord)) {
      return { ok: false, error: SHELL_SCRIPT };
    } else {
      inWord = true;
      text += c;
      i += 1;
    }
  }
  push();
  return { ok: true, words };
}

export function parseCommandLine(line: string): ParsedCommandLine {
  const split = splitWords(line);
  if (!split.ok) return split;
  const { words } = split;
  if (words.length === 0) return { ok: false, error: 'The command line is empty.' };

  const env: { name: string; value: string }[] = [];
  let next = 0;
  for (; next < words.length; next += 1) {
    const w = words[next];
    const match = ASSIGNMENT.exec(w.text);
    if (!match || match[0].length > w.plainPrefix) break;
    const name = match[1];
    const value = w.text.slice(match[0].length);
    const known = env.find((e) => e.name === name);
    if (known) known.value = value;
    else env.push({ name, value });
  }
  if (next >= words.length) {
    return { ok: false, error: 'The line sets variables but has no command after them.' };
  }
  return {
    ok: true,
    env,
    command: words[next].text,
    args: words.slice(next + 1).map((w) => w.text),
  };
}
