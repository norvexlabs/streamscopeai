import { describe, expect, it } from 'vitest';
import type { Me } from '#lib/api-types.js';
import { consoleUser } from './console-user';

const me: Me = {
  id: 'a1',
  email: 'a@example.test',
  role: 'admin',
  is_active: true,
  is_super_admin: false,
  created_at: '2026-10-20T00:00:00Z',
  appliance: false,
  tenant_slug: 'acme',
};

describe('consoleUser', () => {
  it('a_console_user_never_carries_the_token', () => {
    const { user, token } = consoleUser({ ...me, token: 'jwt' });
    expect(token).toBe('jwt');
    expect('token' in user).toBe(false);
    expect(JSON.stringify(user)).not.toContain('jwt');
  });

  it('keeps every identity field, and an answer without a token gives none', () => {
    const { user, token } = consoleUser(me);
    expect(user).toEqual(me);
    expect(token).toBeUndefined();
    expect(consoleUser({ ...me, token: null }).token).toBeUndefined();
  });
});
