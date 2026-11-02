import type { PageServerLoad } from './$types';
import { ORIGIN } from '#lib/server/origin.js';
import { oidcRegistration } from '#lib/oidc-urls.js';

// The URLs this tenant's identity provider must have registered. Built from the
// same origin and helper the login/logout handlers send, so what the page shows
// is exactly what the provider will be asked to match.
export const load: PageServerLoad = ({ params }) => ({
  oidcRegistration: oidcRegistration(ORIGIN, params.slug),
});
