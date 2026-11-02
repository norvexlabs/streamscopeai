import { redirect } from '@sveltejs/kit';

// Bare /portal/t/<slug>/mcp lands on Connections — sidebar's first child of the
// MCP Gateway cluster.
export function load({ params }) {
  redirect(302, `/portal/t/${params.slug}/mcp/connections`);
}
