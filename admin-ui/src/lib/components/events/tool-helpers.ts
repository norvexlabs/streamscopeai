// Shared formatters for tool_call + tool_result conversation events.
// Source of truth for rendering tool events across the session view and the
// /tool-calls invocation feed — keep identical logic on both surfaces so a
// tool call looks the same everywhere it appears.

export function formatArgs(args: unknown): string {
  if (!args) return '{}';
  if (typeof args === 'string') {
    try { return JSON.stringify(JSON.parse(args), null, 2); } catch { return args; }
  }
  return JSON.stringify(args, null, 2);
}

export function formatArgValue(val: unknown): string {
  if (val === null || val === undefined) return 'null';
  if (typeof val === 'string') return val;
  return JSON.stringify(val);
}

export function parseArgs(args: unknown): Record<string, unknown> | null {
  if (!args) return null;
  if (typeof args === 'object' && !Array.isArray(args)) return args as Record<string, unknown>;
  if (typeof args === 'string') {
    try {
      const p = JSON.parse(args);
      return typeof p === 'object' && !Array.isArray(p) ? p : null;
    } catch { return null; }
  }
  return null;
}

export function parseJsonObj(text: string | null | undefined): Record<string, unknown> | null {
  if (!text) return null;
  try {
    const p = JSON.parse(text);
    return typeof p === 'object' && !Array.isArray(p) ? p : null;
  } catch { return null; }
}
