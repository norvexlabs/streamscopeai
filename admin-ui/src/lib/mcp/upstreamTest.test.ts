import { describe, expect, it } from 'vitest';
import { upstreamTestSummary, type UpstreamTestResult } from './upstreamTest';

function result(over: Partial<UpstreamTestResult>): UpstreamTestResult {
  return {
    upstream_id: '00000000-0000-0000-0000-000000000001',
    upstream_name: 'u',
    upstream_url: 'https://mcp.example.com/mcp',
    auth_mode: 'headers',
    status: 'ok',
    error: null,
    needs_user_input_ids: [],
    needs_client_input_ids: [],
    tools: [],
    prompts: [],
    resources: [],
    ...over,
  };
}

describe('upstreamTestSummary', () => {
  it('counts what an ok upstream lists, singular and plural', () => {
    const s = upstreamTestSummary(
      result({
        tools: [{ name: 'a' }, { name: 'b' }],
        prompts: [{ name: 'p' }],
        resources: [],
      }),
    );
    expect(s).toEqual({ tone: 'ok', text: 'Connected — 2 tools, 1 prompt, 0 resources.', next: null, fix: null });
  });

  it('names the inputs a user fills, and is pending, not an error', () => {
    const s = upstreamTestSummary(result({ status: 'needs_user_value', needs_user_input_ids: ['X-Org', 'X-Token'] }));
    expect(s.tone).toBe('pending');
    expect(s.text).toContain('X-Org, X-Token');
    expect(s.text).toContain('portal');
  });

  it('names the headers the client sends', () => {
    const s = upstreamTestSummary(result({ status: 'needs_client_value', needs_client_input_ids: ['Authorization'] }));
    expect(s.tone).toBe('pending');
    expect(s.text).toContain('Authorization');
    expect(s.text).toContain('client');
  });

  it('reads a per-user OAuth upstream as waiting for a sign-in', () => {
    expect(upstreamTestSummary(result({ status: 'needs_user_sign_in', auth_mode: 'per_user_oauth' })).tone).toBe('pending');
  });

  it('carries the gateway detail on each failure status', () => {
    for (const status of ['unavailable', 'redirected', 'http_error', 'jsonrpc_error']) {
      const s = upstreamTestSummary(result({ status, error: 'boom' }));
      expect(s.tone).toBe('error');
      expect(s.text.endsWith(': boom')).toBe(true);
    }
  });

  it('ends a failure without detail with a full stop', () => {
    expect(upstreamTestSummary(result({ status: 'http_error' })).text).toBe('HTTP error.');
  });

  it('shows an unknown status as an error under its own name', () => {
    expect(upstreamTestSummary(result({ status: 'something_new', error: 'x' }))).toEqual({
      tone: 'error',
      text: 'something_new: x',
      next: null,
      fix: null,
    });
  });

  it('sends a user\'s missing value to the portal Sign-ins page, naming the inputs', () => {
    const s = upstreamTestSummary(result({ status: 'needs_user_value', needs_user_input_ids: ['X-Org'] }));
    expect(s.next).toContain('X-Org');
    expect(s.next).toContain('MCP → Sign-ins');
    expect(s.fix).toBeNull();
  });

  it('says a client header is written by the Quickstart and the CLI', () => {
    const s = upstreamTestSummary(result({ status: 'needs_client_value', needs_client_input_ids: ['X-Token'] }));
    expect(s.next).toContain('X-Token');
    expect(s.next).toContain('ssai provision');
  });

  it('sends a per-user OAuth upstream to the portal sign-in', () => {
    expect(upstreamTestSummary(result({ status: 'needs_user_sign_in' })).next).toContain('signs in once from the portal');
  });

  it('offers the upstream editor only where the administrator\'s own value is the fix', () => {
    expect(upstreamTestSummary(result({ status: 'unavailable', error: 'X-Key is not set' })).fix).toBe('edit');
    for (const status of ['ok', 'needs_user_value', 'needs_client_value', 'needs_user_sign_in', 'redirected', 'http_error', 'jsonrpc_error']) {
      expect(upstreamTestSummary(result({ status })).fix).toBeNull();
    }
  });
});
