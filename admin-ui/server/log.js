/**
 * The console's log lines, in the fields the gateway's services write theirs
 * with: one JSON object per line carrying `timestamp` (UTC, RFC 3339),
 * `level`, `fields.message` and `target`, so a log collector reads every
 * service alike and each line says when it was written.
 *
 * `installJsonConsole` replaces the process's `console` output methods — the
 * rest (`trace`, `table`, `assert`, `count`, `timeEnd`) print through them,
 * though a `group` no longer indents — so every caller, this project's code,
 * SvelteKit's own error reports and a library alike, is covered without importing a logger; and it reports
 * an uncaught exception or rejection as one such line before the process exits.
 * Invariant: the entry installs it before anything logs. What the runtime
 * writes past `console` (a Node warning) keeps the runtime's own format.
 */

import { format, inspect } from 'node:util';

const TARGET = 'admin_ui';

/** @typedef {'DEBUG' | 'INFO' | 'WARN' | 'ERROR'} Level */

/**
 * One log line, without its newline. The arguments are formatted as `console`
 * formats them (an `Error` with its stack), and the message stays one line:
 * JSON escapes its newlines.
 * @param {Level} level
 * @param {unknown[]} args
 * @param {Date} [now]
 * @returns {string}
 */
export function logLine(level, args, now = new Date()) {
  return JSON.stringify({
    timestamp: now.toISOString(),
    level,
    fields: { message: format(...args) },
    target: TARGET,
  });
}

/** Ignored, as Node's own console ignores it: a log line that cannot be
 *  written (a closed pipe) must not end the process for every user. */
function ignoreWriteError() {}

/** Route `console.debug/info/log/dir/dirxml` to stdout and `console.warn/error`
 *  to stderr, each as one {@link logLine}, and log an uncaught exception or
 *  rejection the same way before exiting with status 1. */
export function installJsonConsole() {
  for (const stream of [process.stdout, process.stderr]) stream.on('error', ignoreWriteError);
  /** @param {Level} level @param {NodeJS.WriteStream} stream @param {unknown[]} args */
  const write = (level, stream, args) => {
    stream.write(`${logLine(level, args)}\n`, ignoreWriteError);
  };
  /** @param {Level} level @param {NodeJS.WriteStream} stream */
  const writer = (level, stream) => (/** @type {unknown[]} */ ...args) => write(level, stream, args);
  console.debug = writer('DEBUG', process.stdout);
  console.info = writer('INFO', process.stdout);
  console.log = writer('INFO', process.stdout);
  console.warn = writer('WARN', process.stderr);
  console.error = writer('ERROR', process.stderr);
  /** @param {unknown} item @param {import('node:util').InspectOptions} [options] */
  console.dir = (item, options) =>
    write('INFO', process.stdout, [inspect(item, { customInspect: false, ...options })]);
  console.dirxml = console.log;
  // An unhandled rejection reaches this handler too: Node's default mode
  // raises it as an uncaught exception.
  process.on('uncaughtException', (error) => {
    try {
      write('ERROR', process.stderr, ['uncaught exception, exiting:', error]);
    } catch {
      // An error whose own formatting throws: still say why the process ends.
      process.stderr.write('uncaught exception, exiting (unprintable error)\n', ignoreWriteError);
    }
    process.exit(1);
  });
}
