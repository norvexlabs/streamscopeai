/**
 * What the console's upstream Test button tells the administrator, read from
 * the `McpUpstreamTestResult` the gateway returns.
 *
 * The test calls the upstream with the administrator's own values only, so a
 * `needs_*` status is not a failure: the upstream waits for a value a user or
 * the client supplies on a real call. Each such status names the inputs it
 * waits for.
 */
import type { components } from '../generated/api-types';

export type UpstreamTestResult = components['schemas']['McpUpstreamTestResult'];

/** `ok` reached the upstream; `pending` waits for someone else's value;
 *  `error` is a failure the administrator acts on. */
type UpstreamTestTone = 'ok' | 'pending' | 'error';

export interface UpstreamTestSummary {
  tone: UpstreamTestTone;
  text: string;
  /** Who acts next, and where; `null` when nothing is waiting. */
  next: string | null;
  /** `edit` when the fix is in this upstream's own settings. */
  fix: 'edit' | null;
}

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? '' : 's'}`;
}

function withDetail(text: string, error: string | null | undefined): string {
  return error ? `${text}: ${error}` : `${text}.`;
}

export function upstreamTestSummary(r: UpstreamTestResult): UpstreamTestSummary {
  switch (r.status) {
    case 'ok':
      return {
        tone: 'ok',
        text: `Connected — ${plural(r.tools.length, 'tool')}, ${plural(r.prompts.length, 'prompt')}, ${plural(r.resources.length, 'resource')}.`,
        next: null,
        fix: null,
      };
    case 'needs_user_value': {
      const ids = r.needs_user_input_ids.join(', ') || 'a required input';
      return {
        tone: 'pending',
        text: `Not called: each user fills ${ids} in the portal, and the test has no user.`,
        next: `Each user fills ${ids} once in the portal (MCP → Sign-ins). Until then the gateway tells that user's client where to go.`,
        fix: null,
      };
    }
    case 'needs_client_value': {
      const ids = r.needs_client_input_ids.join(', ') || 'a required header';
      return {
        tone: 'pending',
        text: `Not called: the client sends ${ids} on each request, and the test has no client.`,
        next: `The client sends ${ids} on every request; the portal Quickstart and \`ssai provision\` write it into the client's config.`,
        fix: null,
      };
    }
    case 'needs_user_sign_in':
      return {
        tone: 'pending',
        text: 'Not called: each call carries a user’s own OAuth sign-in, and the test has no user.',
        next: 'Each user signs in once from the portal (MCP → Sign-ins); the console cannot test with a user’s token.',
        fix: null,
      };
    case 'unavailable':
      // An administrator value is missing, unreadable or no longer fits its
      // declaration: each is fixed in the upstream's own settings.
      return {
        tone: 'error',
        text: withDetail('Unavailable', r.error),
        next: "Fix it in this upstream's settings.",
        fix: 'edit',
      };
    case 'redirected':
      return {
        tone: 'error',
        text: withDetail('The upstream answered with a redirect, which the gateway never follows', r.error),
        next: null,
        fix: null,
      };
    case 'http_error':
      return { tone: 'error', text: withDetail('HTTP error', r.error), next: null, fix: null };
    case 'jsonrpc_error':
      return { tone: 'error', text: withDetail('JSON-RPC error', r.error), next: null, fix: null };
    default:
      return { tone: 'error', text: withDetail(r.status, r.error), next: null, fix: null };
  }
}
