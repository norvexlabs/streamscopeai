/**
 * Expiry presets shared by every key-mint surface (create form, automation
 * mint modal, portal automation panel).
 */
export type ExpiryPreset = 'never' | '30d' | '90d' | '1y';

/** Preset → absolute ISO timestamp (undefined = never expires). */
export function presetToExpiresAt(preset: ExpiryPreset): string | undefined {
  if (preset === 'never') return undefined;
  const now = new Date();
  if (preset === '30d') now.setDate(now.getDate() + 30);
  else if (preset === '90d') now.setDate(now.getDate() + 90);
  else if (preset === '1y') now.setFullYear(now.getFullYear() + 1);
  return now.toISOString();
}
