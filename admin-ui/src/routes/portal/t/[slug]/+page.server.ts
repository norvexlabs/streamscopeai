import { redirect } from '@sveltejs/kit';
import { portalHomePath } from '#lib/home.js';

export function load({ params }) {
  // The portal's landing page, matching where /portal itself sends a member.
  redirect(302, portalHomePath(params.slug));
}
