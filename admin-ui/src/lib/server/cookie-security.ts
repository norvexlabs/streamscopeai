/**
 * Whether session cookies carry the `Secure` attribute.
 *
 * **Default true, and deliberately not derived from `NODE_ENV`.** Keying this
 * off a Node convention meant it was set by whichever deploy shape happened to
 * remember: the VM appliance set it in its compose file, the Helm chart and the
 * container image did not, and Kubernetes therefore issued session cookies a
 * browser would send over cleartext. Defaulting to true inverts that failure
 * mode — a shape that forgets to configure anything gets the safe behaviour,
 * and only an explicit opt-out turns it off.
 *
 * The opt-out exists for a deployment served over plain HTTP, where a `Secure`
 * cookie is never sent back and every login silently fails. Two shapes take it:
 * the e2e stack, which reaches the UI at `http://e2e-admin-ui:3001`, and a
 * Docker install left on loopback, where the installer writes the opt-out
 * explicitly and restores the default the moment TLS is configured. The
 * appliance and the Helm chart are HTTPS and never set it.
 */
export function cookiesAreSecure(): boolean {
  return process.env.COOKIE_SECURE !== 'false';
}
