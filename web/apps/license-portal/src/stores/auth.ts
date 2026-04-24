import { computed } from 'vue';
import { defineStore } from 'pinia';
import { useJwt } from '@triton/auth';

const MCP_KEY = 'triton_lp_mcp';

export const useAuthStore = defineStore('auth', () => {
  const jwt = useJwt();

  // mustChangePassword is derived from the JWT claims (set via setToken) so
  // it survives page reloads as long as the JWT is stored in localStorage.
  // sessionStorage is used as a write-through fallback for the brief window
  // between login (setMustChange called) and the next navigation guard
  // evaluation, and to handle edge cases where the JWT claim is absent.
  const mustChangePassword = computed<boolean>(() => {
    if (jwt.claims.value?.mustChangePassword) return true;
    if (typeof sessionStorage !== 'undefined') {
      return sessionStorage.getItem(MCP_KEY) === 'true';
    }
    return false;
  });

  function setMustChange(v: boolean): void {
    if (typeof sessionStorage !== 'undefined') {
      if (v) sessionStorage.setItem(MCP_KEY, 'true');
      else sessionStorage.removeItem(MCP_KEY);
    }
  }

  const originalClear = jwt.clear;
  function clear(): void {
    originalClear();
    if (typeof sessionStorage !== 'undefined') {
      sessionStorage.removeItem(MCP_KEY);
    }
  }

  return { ...jwt, clear, mustChangePassword, setMustChange };
});
