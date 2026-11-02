import type { components } from './generated/api-types';

type TenantSettings = components['schemas']['TenantSettings'];

/** The body `updateSettings` sends: `undefined` is dropped, and so is a `null`
 * unless its key is named in `clears` — on the wire a `null` deletes the
 * tenant's override, which an emptied number input must not do by accident. */
export function settingsPatchBody(
  settings: Partial<TenantSettings>,
  clears: readonly (keyof TenantSettings)[] = [],
): Partial<TenantSettings> {
  const body: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(settings)) {
    if (value === undefined) continue;
    if (value === null && !clears.includes(key as keyof TenantSettings)) continue;
    body[key] = value;
  }
  return body as Partial<TenantSettings>;
}
