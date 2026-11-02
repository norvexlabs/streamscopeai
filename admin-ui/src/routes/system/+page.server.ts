import { redirect } from '@sveltejs/kit';
import { checkSetupNeeded } from '#lib/server/tenant-auth.js';

export async function load() {
  // `/system` is the platform administrator's entry: the SYSTEM tenant's
  // console, whose own auth branch redirects to its login without a session.
  if (await checkSetupNeeded()) redirect(303, '/setup');
  redirect(303, '/t/system/');
}
