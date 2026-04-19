import { defineStore } from 'pinia';
import { createHttp, createReportApi, type ReportApi } from '@triton/api-client';
import { useToast } from '@triton/ui';
import { useAuthStore } from './auth';

// Lazily-constructed singleton so Pinia consumers can share one HTTP
// client + one ReportApi instance. Cached at module scope because the
// underlying JWT lives in localStorage — resetting the store between
// tenant switches would not rebuild this cleanly, so we leave the
// authHeader closure to re-read the live token on every request.
let cached: ReportApi | null = null;

export const useApiClient = defineStore('apiClient', () => {
  function get(): ReportApi {
    if (cached) return cached;
    const auth = useAuthStore();
    const toast = useToast();
    const http = createHttp({
      baseUrl: '/api',
      authHeader: (): Record<string, string> =>
        auth.token ? { Authorization: `Bearer ${auth.token}` } : {},
      onUnauthorized: () => {
        auth.clear();
        toast.error({
          title: 'Session expired',
          description: 'Please sign in again.',
        });
      },
    });
    cached = createReportApi(http);
    return cached;
  }
  return { get };
});
