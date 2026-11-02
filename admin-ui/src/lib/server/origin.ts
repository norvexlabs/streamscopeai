import { parseOrigin } from '../../../server/origin.js';

/**
 * The browser-facing origin of this UI — the one every URL handed to an
 * identity provider is built on. Read once, here, so the login handler, the
 * logout handler and the Authentication page cannot disagree about it; and
 * read by the same rule as the server entry, which pins it as the origin
 * SvelteKit checks a form POST against. The fallback serves only a local run
 * without ORIGIN — the image refuses to start so.
 */
const pinned = process.env.ORIGIN ? parseOrigin(process.env.ORIGIN) : undefined;
export const ORIGIN = pinned ? `${pinned.protocol}://${pinned.host}` : 'http://localhost:3000';
