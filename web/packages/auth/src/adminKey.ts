import { ref, type Ref } from 'vue';

const STORAGE_KEY = 'triton_admin_key';
const IDLE_MS = 30 * 60 * 1000;

export interface UseAdminKey {
  key: Ref<string>;
  setKey: (k: string) => void;
  clear: () => void;
  touch: () => void;
  stop: () => void;
}

export function useAdminKey(): UseAdminKey {
  const key = ref<string>(sessionStorage.getItem(STORAGE_KEY) ?? '');
  let idleElapsed = 0;
  const timer = setInterval(() => {
    if (key.value) {
      idleElapsed += 60_000;
      if (idleElapsed >= IDLE_MS) {
        clear();
      }
    }
  }, 60_000);

  function touch(): void {
    idleElapsed = 0;
  }
  function setKey(k: string): void {
    sessionStorage.setItem(STORAGE_KEY, k);
    key.value = k;
    touch();
  }
  function clear(): void {
    sessionStorage.removeItem(STORAGE_KEY);
    key.value = '';
  }
  function stop(): void {
    clearInterval(timer);
  }

  return { key, setKey, clear, touch, stop };
}
