// Portal Home: what its To do card lists and how its daily strip is drawn.
// The server decides every input (which keys expire, which MCP servers wait,
// which CLI hosts are out of date); this only orders and shapes them.

import type { PortalHome } from './api-types.js';

/** One line of the To do card, each fixed somewhere else. */
export type HomeTodo =
  | { kind: 'no_key' }
  | { kind: 'key'; id: string; name: string | null; prefix: string; expiresAt: string; expired: boolean }
  | { kind: 'mcp'; names: string[]; count: number }
  | { kind: 'cli'; host: string; os: string; version: string; latest: string };

/** The To do lines, most urgent first: no key yet, then the keys (expired
 *  before expiring), the MCP servers waiting on the caller (one line), then
 *  each out-of-date CLI host. Empty = the card is hidden. A limit near its cap
 *  is not a line: it shows on its meter.
 *
 *  A caller reaching the gateway without a key (an OAuth sign-in) has traffic
 *  and is set up, so "no key yet" needs no key AND no traffic in 7 days. */
export function homeTodos(home: PortalHome, now: number): HomeTodo[] {
  const todos: HomeTodo[] = [];
  if (!home.has_active_key && home.last_7_days.requests === 0) todos.push({ kind: 'no_key' });
  const keys = home.expiring_keys.map((k) => ({
    kind: 'key' as const,
    id: k.id,
    name: k.name ?? null,
    prefix: k.key_prefix,
    expiresAt: k.expires_at,
    expired: new Date(k.expires_at).getTime() <= now,
  }));
  // Stable: the server's order (soonest first) holds within each group.
  todos.push(...keys.filter((k) => k.expired), ...keys.filter((k) => !k.expired));
  if (home.mcp_sign_in.length > 0) {
    todos.push({
      kind: 'mcp',
      names: home.mcp_sign_in.map((s) => s.name),
      count: Math.max(home.mcp_sign_in_total, home.mcp_sign_in.length),
    });
  }
  for (const h of home.cli_updates) {
    todos.push({ kind: 'cli', host: h.host, os: h.os, version: h.version, latest: home.cli_version });
  }
  return todos;
}

/** One bar of the daily strip. */
interface SpendBar {
  day: string;
  requests: number;
  /** The day's spend, `null` when it straddles a currency change. */
  amount: number | null;
  currency: string | null;
  /** Height as a share of the tallest bar, 0..1. */
  ratio: number;
  today: boolean;
}

/** The strip's bars, oldest first, scaled to the highest-spending day. A day
 *  without a single figure (two currencies) draws no bar; a week that spent
 *  nothing draws every bar flat. The last day is today. */
export function spendBars(days: PortalHome['daily']): SpendBar[] {
  const max = Math.max(0, ...days.map((d) => d.spend?.amount ?? 0));
  return days.map((d, i) => {
    const amount = d.spend ? d.spend.amount : null;
    return {
      day: d.day,
      requests: d.requests,
      amount,
      currency: d.spend?.currency ?? null,
      ratio: max > 0 && amount != null ? Math.max(0, amount) / max : 0,
      today: i === days.length - 1,
    };
  });
}
