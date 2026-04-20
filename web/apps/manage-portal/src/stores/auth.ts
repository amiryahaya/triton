import { defineStore } from 'pinia';
import { useJwt } from '@triton/auth';

// Thin pinia wrapper over the @triton/auth useJwt() composable so
// consumers can reach the JWT state via the standard defineStore flow.
// Per-form UX state (login error / busy spinner) lives in App.vue where
// the login API call fires, not here — keeping the store free of
// request-cycle ephemera.
export const useAuthStore = defineStore('auth', () => useJwt());
