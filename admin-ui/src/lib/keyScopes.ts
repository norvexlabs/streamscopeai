/**
 * Automation-key (`ak-`) scope + key-kind vocabulary — the single place the UI
 * names them. Scope values mirror the console role words (`admin`/`read_only`)
 * plus the SYSTEM-tenant-only `super_admin` operator scope.
 */

export function scopeLabel(scope: string | null | undefined): string {
  switch (scope) {
    case 'read_only':
      return 'Read-only';
    case 'admin':
      return 'Admin';
    case 'super_admin':
      return 'Operator (super-admin)';
    default:
      return scope ?? '';
  }
}

/** Key-kind labels for the unified inventory (`GET /api/v1/admin/keys`). */
export function keyKindLabel(kind: string | null | undefined): string {
  switch (kind) {
    case 'sk':
      return 'Gateway';
    case 'vk':
      return 'Gateway (BYOK)';
    case 'ak_admin':
      return 'Admin automation';
    case 'ak_portal':
      return 'Portal automation';
    default:
      return kind ?? '';
  }
}

/** Owner kinds of the unified inventory. */
export function ownerKindLabel(kind: string | null | undefined): string {
  switch (kind) {
    case 'service':
      return 'Service account';
    case 'agent':
      return 'Agent';
    default:
      return 'User';
  }
}
