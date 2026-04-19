import { ref, computed, type Ref, type ComputedRef } from 'vue';

const STORAGE_KEY = 'tritonJWT';

export interface JwtClaims {
  sub: string;
  org: string;
  orgName: string;
  role: string;
  name: string;
  mustChangePassword: boolean;
  exp: number;
}

export interface UseJwt {
  token: Ref<string>;
  claims: ComputedRef<JwtClaims | null>;
  isExpired: ComputedRef<boolean>;
  isAdmin: ComputedRef<boolean>;
  setToken: (t: string) => void;
  clear: () => void;
}

// Module-level reactive state. All useJwt() callers share the same token
// source so a login in one component propagates to every observer without
// an app-wide pinia singleton — the browser only ever has one active JWT.
const token = ref<string>(typeof localStorage !== 'undefined' ? (localStorage.getItem(STORAGE_KEY) ?? '') : '');

interface RawClaims {
  sub?: unknown;
  org?: unknown;
  org_name?: unknown;
  role?: unknown;
  name?: unknown;
  mcp?: unknown;
  exp?: unknown;
}

function decodeClaims(t: string): JwtClaims | null {
  if (!t) return null;
  const parts = t.split('.');
  if (parts.length !== 3) return null;
  const payloadSegment = parts[1];
  if (!payloadSegment) return null;
  try {
    // base64url → base64 → JSON
    const b64 = payloadSegment.replace(/-/g, '+').replace(/_/g, '/');
    const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
    const raw = JSON.parse(atob(padded)) as RawClaims;
    return {
      sub: typeof raw.sub === 'string' ? raw.sub : '',
      org: typeof raw.org === 'string' ? raw.org : '',
      orgName: typeof raw.org_name === 'string' ? raw.org_name : '',
      role: typeof raw.role === 'string' ? raw.role : '',
      name: typeof raw.name === 'string' ? raw.name : '',
      mustChangePassword: raw.mcp === true,
      exp: typeof raw.exp === 'number' ? raw.exp : 0,
    };
  } catch (err) {
    console.warn('useJwt: failed to decode JWT payload', err);
    return null;
  }
}

export function useJwt(): UseJwt {
  const claims = computed<JwtClaims | null>(() => decodeClaims(token.value));
  const isExpired = computed<boolean>(() => {
    const c = claims.value;
    if (!c) return true;
    return Date.now() / 1000 >= c.exp;
  });
  const isAdmin = computed<boolean>(() => {
    const role = claims.value?.role ?? '';
    return role === 'org_admin' || role === 'super_admin';
  });

  function setToken(t: string): void {
    localStorage.setItem(STORAGE_KEY, t);
    token.value = t;
  }

  function clear(): void {
    localStorage.removeItem(STORAGE_KEY);
    token.value = '';
  }

  return { token, claims, isExpired, isAdmin, setToken, clear };
}
