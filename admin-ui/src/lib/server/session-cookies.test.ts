import { describe, expect, it } from 'vitest';
import {
  ID_TOKEN_OMITTED,
  MAX_ID_TOKEN_CHUNKS,
  idTokenChunkName,
  idTokenChunks,
  idTokenHint,
  joinIdToken,
} from './session-cookies';

describe('ID-token cookie', () => {
  it('stores a small token in one cookie and hands it back whole', () => {
    const token = 'eyJ.' + 'a'.repeat(1000) + '.sig';
    expect(idTokenChunks(token)).toEqual([token]);
    expect(idTokenHint(joinIdToken(idTokenChunks(token)))).toBe(token);
  });

  // A group-laden token (AD FS form_post) is split, never dropped: AD FS
  // returns the user after sign-out only when the hint is sent.
  it('splits a large token and reassembles it exactly', () => {
    const token = 'eyJ.' + 'b'.repeat(5000) + '.sig';
    const chunks = idTokenChunks(token);
    expect(chunks.length).toBe(2);
    expect(chunks.every((c) => c.length <= 3000)).toBe(true);
    expect(joinIdToken(chunks)).toBe(token);
  });

  it('stores the marker past the bound, which offers no hint', () => {
    const token = 'eyJ.' + 'c'.repeat(3000 * MAX_ID_TOKEN_CHUNKS) + '.sig';
    expect(idTokenChunks(token)).toEqual([ID_TOKEN_OMITTED]);
    expect(idTokenHint(joinIdToken(idTokenChunks(token)))).toBeNull();
  });

  it('names chunk 0 as the cookie itself', () => {
    expect(idTokenChunkName('oidc_id_token_admin_acme', 0)).toBe('oidc_id_token_admin_acme');
    expect(idTokenChunkName('oidc_id_token_admin_acme', 2)).toBe('oidc_id_token_admin_acme.2');
  });

  // A missing middle chunk must not splice the ends into a different token.
  it('stops at the first missing chunk', () => {
    expect(joinIdToken(['a', undefined, 'c'])).toBe('a');
    expect(joinIdToken([undefined, 'b'])).toBeUndefined();
  });

  it('offers no hint when there is no cookie', () => {
    expect(idTokenHint(undefined)).toBeNull();
    expect(idTokenHint('')).toBeNull();
  });
});
