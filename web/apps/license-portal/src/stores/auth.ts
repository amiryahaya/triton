import { defineStore } from 'pinia';
import { useAdminKey } from '@triton/auth';

export const useAuthStore = defineStore('auth', () => {
  const admin = useAdminKey();
  return admin;
});
