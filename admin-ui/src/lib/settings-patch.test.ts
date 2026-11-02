import { describe, expect, it } from 'vitest';
import { settingsPatchBody } from './settings-patch';

describe('settingsPatchBody', () => {
  it('drops an emptied field instead of resetting the setting', () => {
    expect(settingsPatchBody({ tenant_daily_budget: null, tenant_budget_mode: 'enforce' })).toEqual({
      tenant_budget_mode: 'enforce',
    });
  });

  it('sends null for a key the caller means to clear', () => {
    expect(settingsPatchBody({ proxy_public_url: null, retention_days: null }, ['proxy_public_url'])).toEqual({
      proxy_public_url: null,
    });
  });

  it('keeps values, including false and 0', () => {
    expect(settingsPatchBody({ debug_mode: false, retention_days: 0, log_level: undefined })).toEqual({
      debug_mode: false,
      retention_days: 0,
    });
  });
});
