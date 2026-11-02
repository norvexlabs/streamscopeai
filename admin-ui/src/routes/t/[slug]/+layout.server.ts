export function load({ locals }) {
  // hooks.server.ts validated the path-scoped session cookie for this tenant and
  // populated locals.user. sidebarCollapsed / authMode are inherited from the
  // root layout.
  return {
    user: locals.user || null,
  };
}
