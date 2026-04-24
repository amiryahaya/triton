import { ref } from 'vue';
import { defineStore } from 'pinia';
import { useJwt } from '@triton/auth';

export const useAuthStore = defineStore('auth', () => {
  const jwt = useJwt();
  const mustChangePassword = ref(false);
  function setMustChange(v: boolean) { mustChangePassword.value = v; }
  return { ...jwt, mustChangePassword, setMustChange };
});
