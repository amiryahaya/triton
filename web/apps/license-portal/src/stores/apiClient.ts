import { defineStore } from 'pinia';
import { createHttp, createLicenseApi, type LicenseApi } from '@triton/api-client';
import { useToast } from '@triton/ui';
import { useAuthStore } from './auth';

let cached: LicenseApi | null = null;

export const useApiClient = defineStore('apiClient', () => {
  function get(): LicenseApi {
    if (cached) return cached;
    const auth = useAuthStore();
    const toast = useToast();
    const http = createHttp({
      baseUrl: '/api',
      authHeader: (): Record<string, string> =>
        auth.key ? { 'X-Triton-Admin-Key': auth.key } : {},
      onUnauthorized: () => {
        auth.clear();
        toast.error({
          title: 'Session expired',
          description: 'Please re-enter the admin key.',
        });
      },
    });
    cached = createLicenseApi(http);
    return cached;
  }
  return { get };
});
