import { defineStore } from 'pinia';
import { createHttp, createManageApi, type ManageApi, type Http } from '@triton/api-client';
import { useToast } from '@triton/ui';
import { useAuthStore } from './auth';

// Lazily-constructed singleton so Pinia consumers can share one HTTP
// client + one ManageApi instance. Cached at module scope because the
// underlying JWT lives in localStorage — resetting the store between
// tenant switches would not rebuild this cleanly, so we leave the
// authHeader closure to re-read the live token on every request.
let cached: ManageApi | null = null;

export const useApiClient = defineStore('apiClient', () => {
  function get(): ManageApi {
    if (cached) return cached;
    const auth = useAuthStore();
    const toast = useToast();
    const authHeader = (): Record<string, string> =>
      auth.token ? { Authorization: `Bearer ${auth.token}` } : {};
    const http = createHttp({
      baseUrl: '/api',
      authHeader,
      onUnauthorized: () => {
        auth.clear();
        toast.error({ title: 'Session expired', description: 'Please sign in again.' });
      },
    });
    // enrolAgent uses direct fetch() — stash authHeader on the http obj
    // so manageServer.ts can splice it into the request headers.
    (http as Http & { _authHeader?: () => Record<string, string> })._authHeader = authHeader;
    cached = createManageApi(http);
    return cached;
  }
  return { get };
});
