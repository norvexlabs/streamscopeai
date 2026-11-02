import { describe, expect, it } from 'vitest';
import { mediaUrl } from '#lib/media.js';

/**
 * A stored blob is named (hash, kind, owning request); each plane builds its
 * own route from the name. The portal cannot read the console's media route,
 * its own one proves ownership through the request, and a teammate's blob in
 * a shared workspace needs the workspace being viewed.
 */
describe('mediaUrl', () => {
  it('builds the console route under the console prefix, with nothing the portal needs', () => {
    expect(mediaUrl('acme', '/t/acme/sessions/s', 'abc', 'chat_image', 'r-1', 'w-1')).toBe(
      '/t/acme/api/v1/admin/audit/media/abc?blob_type=chat_image',
    );
  });

  it('builds the portal route, with its owning request, under the portal prefix', () => {
    expect(mediaUrl('acme', '/portal/t/acme/sessions/s', 'abc', 'chat_image', 'r-1')).toBe(
      '/portal/t/acme/api/v1/portal/audit/media/abc?blob_type=chat_image&request_id=r-1',
    );
  });

  it('carries the viewed portal workspace', () => {
    expect(mediaUrl('acme', '/portal/t/acme/sessions/s', 'abc', 'chat_image', 'r-1', 'w-1')).toBe(
      '/portal/t/acme/api/v1/portal/audit/media/abc?blob_type=chat_image&request_id=r-1&workspace_id=w-1',
    );
  });

  it('never points the portal at the console route', () => {
    expect(mediaUrl('acme', '/portal/t/acme/audit', 'abc', 'response_body', 'r-1')).not.toContain('/api/v1/admin/');
  });

  it('keeps a hostile hash inside the media route', () => {
    for (const pathname of ['/t/acme/s', '/portal/t/acme/s']) {
      const url = mediaUrl('acme', pathname, '../../keys?x=', 'chat_image', 'r-1');
      expect(url).toContain('/audit/media/..%2F..%2Fkeys%3Fx%3D?blob_type=chat_image');
      expect(new URL(url, 'https://h').pathname).toMatch(/\/audit\/media\/[^/]+$/);
    }
  });

  it('gives the portal no URL without the owning request, and the console one', () => {
    expect(mediaUrl('acme', '/portal/t/acme/audit', 'abc', 'response_body')).toBe('');
    expect(mediaUrl('acme', '/t/acme/audit', 'abc', 'response_body')).not.toBe('');
  });
});
