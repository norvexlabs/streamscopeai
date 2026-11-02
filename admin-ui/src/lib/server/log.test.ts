import { afterEach, describe, expect, it, vi } from 'vitest';
import { installJsonConsole, logLine } from '../../../server/log.js';

const at = new Date('2026-10-22T13:29:05.228Z');

describe('logLine', () => {
  it('is one JSON line in the services’ shape, stamped in UTC', () => {
    const line = logLine('WARN', ['refused a sign-in for tenant %s', 'acme'], at);
    expect(JSON.parse(line)).toEqual({
      timestamp: '2026-10-22T13:29:05.228Z',
      level: 'WARN',
      fields: { message: 'refused a sign-in for tenant acme' },
      target: 'admin_ui',
    });
  });

  it('keeps an error’s stack inside its one line', () => {
    const line = logLine('ERROR', ['OIDC begin unreachable:', new Error('boom')], at);
    expect(line).not.toContain('\n');
    const message: string = JSON.parse(line).fields.message;
    expect(message).toMatch(/^OIDC begin unreachable: Error: boom\n\s+at /);
  });
});

describe('installJsonConsole', () => {
  const saved = { ...console };
  const emitters: [NodeJS.EventEmitter, string][] = [
    [process, 'uncaughtException'],
    [process.stdout, 'error'],
    [process.stderr, 'error'],
  ];
  const before = emitters.map(([emitter, event]) => emitter.listeners(event));
  afterEach(() => {
    Object.assign(console, saved);
    emitters.forEach(([emitter, event], i) => {
      for (const listener of emitter.listeners(event)) {
        if (!before[i].includes(listener)) emitter.off(event, listener as (...args: unknown[]) => void);
      }
    });
    vi.restoreAllMocks();
  });

  it('writes debug, info, log and dir to stdout and warn and error to stderr, each at its level', () => {
    const out = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
    const err = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
    installJsonConsole();
    console.debug('d');
    console.info('i');
    console.log('l');
    console.warn('w');
    console.error('e');
    console.dir({ a: 1 });
    const levels = (spy: typeof out) =>
      spy.mock.calls.map(([chunk]) => {
        const { level, fields } = JSON.parse(String(chunk));
        return `${level} ${fields.message}`;
      });
    expect(levels(out)).toEqual(['DEBUG d', 'INFO i', 'INFO l', 'INFO { a: 1 }']);
    expect(levels(err)).toEqual(['WARN w', 'ERROR e']);
    expect(String(out.mock.calls[0][0]).endsWith('}\n')).toBe(true);
  });

  it('reports an uncaught exception as one line, stack included, and exits with status 1', () => {
    const err = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
    const exit = vi.spyOn(process, 'exit').mockImplementation((() => undefined) as never);
    installJsonConsole();
    const handler = process.listeners('uncaughtException').at(-1);
    handler?.(new Error('ORIGIN is required'), 'uncaughtException');
    const { level, fields } = JSON.parse(String(err.mock.calls[0][0]));
    expect(level).toBe('ERROR');
    expect(fields.message).toMatch(/^uncaught exception, exiting: Error: ORIGIN is required\n\s+at /);
    expect(exit).toHaveBeenCalledWith(1);
  });
});
