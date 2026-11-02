import { redirect } from '@sveltejs/kit';
import { homePath } from '#lib/home.js';

export function load({ locals, params }) {
  redirect(302, `/t/${params.slug}${homePath(locals.user)}`);
}
