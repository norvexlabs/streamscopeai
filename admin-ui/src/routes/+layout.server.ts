import type { LayoutServerLoad } from './$types';
import { authMode } from '#lib/server/auth-mode.js';

export const load: LayoutServerLoad = ({ cookies }) => {
  // Global, plane-agnostic data inherited by the per-tenant layouts. Per-plane
  // identity (admin user / portal user) loads in the tenant layouts.
  return {
    authMode: authMode(),
    sidebarCollapsed: cookies.get('sidebar_collapsed') === 'true',
  };
};
