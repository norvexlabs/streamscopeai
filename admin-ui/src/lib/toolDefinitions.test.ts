import { beforeEach, describe, expect, it, vi } from 'vitest';

// Every read is recorded with the plane's client it went through; the answer
// is whatever `answer` holds when the read is made.
const calls = vi.hoisted(() => [] as { client: string; path: string; init: unknown }[]);
const answer = vi.hoisted(() => ({ current: { data: { hash: 'h', definition: [], size_bytes: 2, tools: null } } as unknown }));
vi.mock('#lib/api-client.js', () => ({
	adminApi: { GET: (path: string, init: unknown) => (calls.push({ client: 'admin', path, init }), Promise.resolve(answer.current)) },
}));
vi.mock('#lib/portal-client.js', () => ({
	portalApi: { GET: (path: string, init: unknown) => (calls.push({ client: 'portal', path, init }), Promise.resolve(answer.current)) },
}));

const { fetchToolDefinition } = await import('./toolDefinitions.js');

beforeEach(() => {
	calls.length = 0;
	answer.current = { data: { hash: 'h', definition: [], size_bytes: 2, tools: null } };
});

describe('fetchToolDefinition', () => {
	it('reads the admin route with the protocol alone on the console', async () => {
		await fetchToolDefinition({ selfScoped: false, workspaceId: () => 'ws-1' }, 'abc', 'chat_completions');
		expect(calls).toEqual([
			{
				client: 'admin',
				path: '/api/v1/admin/audit/tool-definitions/{hash}',
				init: { params: { path: { hash: 'abc' }, query: { protocol: 'chat_completions' } } },
			},
		]);
	});

	it('reads the portal route in the viewed workspace with the protocol on the portal', async () => {
		await fetchToolDefinition({ selfScoped: true, workspaceId: () => 'ws-1' }, 'abc', 'anthropic_messages');
		expect(calls).toEqual([
			{
				client: 'portal',
				path: '/api/v1/portal/audit/tool-definitions/{hash}',
				init: { params: { path: { hash: 'abc' }, query: { workspace_id: 'ws-1', protocol: 'anthropic_messages' } } },
			},
		]);
	});

	it('names neither a workspace nor a protocol it was not given', async () => {
		await fetchToolDefinition({ selfScoped: true, workspaceId: () => undefined }, 'abc');
		await fetchToolDefinition({ selfScoped: false, workspaceId: () => undefined }, 'abc');
		expect(calls.map((c) => (c.init as { params: { query: unknown } }).params.query)).toEqual([{}, {}]);
	});

	it('answers the definition, or null when the read fails', async () => {
		const plane = { selfScoped: false, workspaceId: () => undefined };
		expect(await fetchToolDefinition(plane, 'abc')).toEqual({ hash: 'h', definition: [], size_bytes: 2, tools: null });
		answer.current = { error: { error: { code: 'audit_record_not_found' } } };
		expect(await fetchToolDefinition(plane, 'abc')).toBeNull();
	});
});
