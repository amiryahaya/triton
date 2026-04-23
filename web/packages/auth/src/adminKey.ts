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

// Module-scoped singleton state. Every caller of useAdminKey() shares
// the same ref + timer so TAuthGate and the apiClient auth store see
// the same key. Previously each call created its own instance, so
// setKey in one did not propagate to the other — the SPA would render
// after the gate accepted the key but the apiClient's authHeader
// closure still read an empty key, yielding 401s immediately.
let keyRef: Ref<string> | null = null;
let idleElapsed = 0;
let timer: ReturnType<typeof setInterval> | null = null;

function ensureInit(): Ref<string> {
  if (keyRef) return keyRef;
  keyRef = ref<string>(sessionStorage.getItem(STORAGE_KEY) ?? '');
  timer = setInterval(() => {
    if (keyRef && keyRef.value) {
      idleElapsed += 60_000;
      if (idleElapsed >= IDLE_MS) clearState();
    }
  }, 60_000);
  return keyRef;
}

function clearState(): void {
  sessionStorage.removeItem(STORAGE_KEY);
  if (keyRef) keyRef.value = '';
  idleElapsed = 0;
}

export function useAdminKey(): UseAdminKey {
  const key = ensureInit();

  function touch(): void {
    idleElapsed = 0;
  }
  function setKey(k: string): void {
    sessionStorage.setItem(STORAGE_KEY, k);
    key.value = k;
    touch();
  }
  function clear(): void {
    clearState();
  }
  function stop(): void {
    // Tear down the singleton completely so the next useAdminKey()
    // call re-initialises from sessionStorage. Exists mainly for tests
    // that want a clean slate per spec; production code calls this on
    // app shutdown (which normally never happens in a SPA).
    if (timer) {
      clearInterval(timer);
      timer = null;
    }
    keyRef = null;
    idleElapsed = 0;
  }

  return { key, setKey, clear, touch, stop };
}
