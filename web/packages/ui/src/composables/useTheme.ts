import { ref, computed, watch, type Ref, type ComputedRef } from 'vue';

export type ThemeMode = 'dark' | 'light' | 'system';
export type ResolvedTheme = 'dark' | 'light';

const STORAGE_KEY = 'tritonTheme';

export interface UseTheme {
  mode: Ref<ThemeMode>;
  resolved: ComputedRef<ResolvedTheme>;
  setMode: (m: ThemeMode) => void;
}

function getStoredMode(): ThemeMode {
  const v = localStorage.getItem(STORAGE_KEY);
  return v === 'dark' || v === 'light' ? v : 'system';
}

function systemPrefersLight(): boolean {
  return typeof matchMedia === 'function'
    ? matchMedia('(prefers-color-scheme: light)').matches
    : false;
}

function apply(theme: ResolvedTheme): void {
  document.documentElement.setAttribute('data-theme', theme);
}

export function useTheme(): UseTheme {
  const mode = ref<ThemeMode>(getStoredMode());
  const resolved = computed<ResolvedTheme>(() => {
    if (mode.value === 'system') {
      return systemPrefersLight() ? 'light' : 'dark';
    }
    return mode.value;
  });

  apply(resolved.value);
  watch(resolved, (t) => apply(t), { flush: 'sync' });

  function setMode(m: ThemeMode): void {
    if (m === 'system') {
      localStorage.removeItem(STORAGE_KEY);
    } else {
      localStorage.setItem(STORAGE_KEY, m);
    }
    mode.value = m;
  }

  return { mode, resolved, setMode };
}
