import { describe, it, expect, beforeEach, vi } from 'vitest';
import { useJwt } from '../src/jwt';

// base64url-encode helper for building test tokens
function b64url(obj: unknown): string {
  return btoa(JSON.stringify(obj)).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function makeToken(claims: Record<string, unknown>): string {
  return `${b64url({ alg: 'HS256' })}.${b64url(claims)}.sig`;
}

describe('useJwt', () => {
  // Module-level reactive state — reset both storage and the live ref
  // between tests so one spec's token doesn't leak into the next.
  beforeEach(() => {
    localStorage.clear();
    useJwt().clear();
  });

  it('starts empty after clear', () => {
    const jwt = useJwt();
    expect(jwt.token.value).toBe('');
    expect(jwt.claims.value).toBeNull();
  });

  it('hydrates token on module import (via re-import)', async () => {
    const t = makeToken({ sub: 'u1', exp: Date.now() / 1000 + 3600 });
    localStorage.setItem('tritonJWT', t);
    // vi.resetModules() forces the jwt module to re-run its top-level
    // ref initializer, which reads localStorage at import time.
    vi.resetModules();
    const mod = await import('../src/jwt');
    const jwt = mod.useJwt();
    expect(jwt.token.value).toBe(t);
    expect(jwt.claims.value?.sub).toBe('u1');
    jwt.clear();
  });

  it('persists token to localStorage on setToken', () => {
    const jwt = useJwt();
    const t = makeToken({ sub: 'u2', exp: 9_999_999_999 });
    jwt.setToken(t);
    expect(localStorage.getItem('tritonJWT')).toBe(t);
  });

  it('clears both token and storage', () => {
    const jwt = useJwt();
    jwt.setToken(makeToken({ sub: 'u3', exp: 9_999_999_999 }));
    jwt.clear();
    expect(jwt.token.value).toBe('');
    expect(localStorage.getItem('tritonJWT')).toBeNull();
  });

  it('decodes standard user claims', () => {
    const jwt = useJwt();
    jwt.setToken(
      makeToken({
        sub: 'user-1',
        org: 'org-1',
        org_name: 'Acme',
        role: 'org_admin',
        name: 'Alice',
        mcp: false,
        exp: 9_999_999_999,
      })
    );
    const c = jwt.claims.value!;
    expect(c.sub).toBe('user-1');
    expect(c.org).toBe('org-1');
    expect(c.orgName).toBe('Acme');
    expect(c.role).toBe('org_admin');
    expect(c.name).toBe('Alice');
    expect(c.mustChangePassword).toBe(false);
    expect(c.exp).toBe(9_999_999_999);
  });

  it('isExpired is true for past exp', () => {
    const jwt = useJwt();
    jwt.setToken(makeToken({ sub: 'u', exp: 100 })); // ancient epoch
    expect(jwt.isExpired.value).toBe(true);
  });

  it('isExpired is false for future exp', () => {
    const jwt = useJwt();
    jwt.setToken(makeToken({ sub: 'u', exp: 9_999_999_999 }));
    expect(jwt.isExpired.value).toBe(false);
  });

  it('isExpired is true when no token', () => {
    const jwt = useJwt();
    expect(jwt.isExpired.value).toBe(true);
  });

  it('returns null claims for malformed token', () => {
    const jwt = useJwt();
    jwt.setToken('not-a-jwt');
    expect(jwt.claims.value).toBeNull();
    // Malformed token is treated as expired so AuthGate re-prompts.
    expect(jwt.isExpired.value).toBe(true);
  });

  it('mustChangePassword reflects mcp claim', () => {
    const jwt = useJwt();
    jwt.setToken(makeToken({ sub: 'u', exp: 9_999_999_999, mcp: true }));
    expect(jwt.claims.value?.mustChangePassword).toBe(true);
  });
});

describe('useJwt reactivity across instances', () => {
  beforeEach(() => localStorage.clear());

  it('subsequent useJwt() observes setToken from first instance', () => {
    const a = useJwt();
    const b = useJwt();
    a.setToken(
      `${btoa(JSON.stringify({}))}.${btoa(JSON.stringify({ sub: 'shared', exp: 9_999_999_999 }))}.x`
    );
    // Both instances read from same reactive source.
    expect(b.token.value).toBe(a.token.value);
    expect(b.claims.value?.sub).toBe('shared');
  });
});

// Silence the console.warn emitted by claim-decoder when we intentionally
// feed garbage in the malformed-token test (keeps vitest output clean).
vi.spyOn(console, 'warn').mockImplementation(() => {});
