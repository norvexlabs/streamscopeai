import type { Me, PortalMe } from '#lib/api-types.js';

declare global {
  const __APP_VERSION__: string;
  namespace App {
    interface Locals {
      /** The console identity `/auth/me` answered while validating the session,
       *  built by `consoleUser`, which leaves out the token: this object reaches
       *  the page as layout data, where script can read it. */
      user?: Omit<Me, 'token'>;
      token?: string;
      portal_token?: string;
      /**
       * The portal identity `hooks.server.ts` already fetched while validating
       * the session. Kept so the tenant layout renders from it instead of
       * asking again — validating and loading identity are the same call, and
       * making it twice was costing every portal page a second round trip.
       */
      portal_me?: PortalMe;
    }
  }
}

export {};
