import {
  ref,
  computed,
  watch,
  effectScope,
  type Ref,
  type ComputedRef,
  type EffectScope,
} from 'vue';

export type ThemeMode = 'dark' | 'light' | 'system';
export type ResolvedTheme = 'dark' | 'light';

const STORAGE_KEY = 'tritonTheme';
const MQ_LIGHT = '(prefers-color-scheme: light)';

export interface UseTheme {
  mode: Ref<ThemeMode>;
  resolved: ComputedRef<ResolvedTheme>;
  setMode: (m: ThemeMode) => void;
}

function getStoredMode(): ThemeMode {
  const v = localStorage.getItem(STORAGE_KEY);
  return v === 'dark' || v === 'light' ? v : 'system';
}

function apply(theme: ResolvedTheme): void {
  document.documentElement.setAttribute('data-theme', theme);
}

// Singleton state so every call returns the same instance and we never
// accumulate watchers or listeners. `useTheme()` should be invoked once at
// the app root; components just read CSS variables.
interface ThemeState {
  api: UseTheme;
  scope: EffectScope;
  mql: MediaQueryList | null;
  mqlHandler: ((ev: MediaQueryListEvent) => void) | null;
}

let _state: ThemeState | null = null;

function createTheme(): ThemeState {
  const scope = effectScope(true);
  let mql: MediaQueryList | null = null;
  let mqlHandler: ((ev: MediaQueryListEvent) => void) | null = null;

  const api = scope.run(() => {
    // System preference tracked as a reactive ref so `resolved` re-evaluates
    // when the OS theme flips while mode === 'system'.
    const systemLight = ref<boolean>(
      typeof matchMedia === 'function' ? matchMedia(MQ_LIGHT).matches : false
    );

    if (typeof matchMedia === 'function') {
      mql = matchMedia(MQ_LIGHT);
      mqlHandler = (ev) => {
        systemLight.value = ev.matches;
      };
      mql.addEventListener('change', mqlHandler);
    }

    const mode = ref<ThemeMode>(getStoredMode());
    const resolved = computed<ResolvedTheme>(() => {
      if (mode.value === 'system') return systemLight.value ? 'light' : 'dark';
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
  })!;

  return { api, scope, mql, mqlHandler };
}

export function useTheme(): UseTheme {
  if (!_state) _state = createTheme();
  return _state.api;
}

/**
 * Dispose the theme singleton. Only useful in tests that need to
 * re-initialise `useTheme` between cases.
 * @internal
 */
export function __resetThemeForTest(): void {
  if (_state) {
    if (_state.mql && _state.mqlHandler) {
      _state.mql.removeEventListener('change', _state.mqlHandler);
    }
    _state.scope.stop();
    _state = null;
  }
}
