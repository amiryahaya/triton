import { describe, it, expect, beforeEach, vi } from 'vitest';
import { useTheme, __resetThemeForTest } from '../src/composables/useTheme';

// MediaQueryList stub that can emit `change` events on demand.
function makeMQL(initial: boolean) {
  const listeners: Array<(ev: MediaQueryListEvent) => void> = [];
  const mql = {
    matches: initial,
    addEventListener: vi.fn((_type: string, l: (ev: MediaQueryListEvent) => void) => {
      listeners.push(l);
    }),
    removeEventListener: vi.fn((_type: string, l: (ev: MediaQueryListEvent) => void) => {
      const i = listeners.indexOf(l);
      if (i >= 0) listeners.splice(i, 1);
    }),
  };
  function emit(matches: boolean) {
    mql.matches = matches;
    for (const l of [...listeners]) l({ matches } as MediaQueryListEvent);
  }
  return { mql, emit };
}

describe('useTheme', () => {
  beforeEach(() => {
    localStorage.clear();
    document.documentElement.removeAttribute('data-theme');
    __resetThemeForTest();
    vi.restoreAllMocks();
  });

  it('defaults to dark when no preference stored and no system hint', () => {
    const { mql } = makeMQL(false);
    vi.stubGlobal('matchMedia', vi.fn(() => mql));

    const theme = useTheme();
    expect(theme.resolved.value).toBe('dark');
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark');
  });

  it('respects prefers-color-scheme: light on first visit', () => {
    const { mql } = makeMQL(true);
    vi.stubGlobal('matchMedia', vi.fn(() => mql));

    const theme = useTheme();
    expect(theme.resolved.value).toBe('light');
    expect(document.documentElement.getAttribute('data-theme')).toBe('light');
  });

  it('restores stored user preference over system', () => {
    localStorage.setItem('tritonTheme', 'light');
    const { mql } = makeMQL(false);
    vi.stubGlobal('matchMedia', vi.fn(() => mql));

    const theme = useTheme();
    expect(theme.mode.value).toBe('light');
    expect(theme.resolved.value).toBe('light');
  });

  it('setMode persists and updates DOM', () => {
    const { mql } = makeMQL(false);
    vi.stubGlobal('matchMedia', vi.fn(() => mql));

    const theme = useTheme();
    theme.setMode('light');
    expect(localStorage.getItem('tritonTheme')).toBe('light');
    expect(document.documentElement.getAttribute('data-theme')).toBe('light');
    expect(theme.resolved.value).toBe('light');
  });

  it('setMode("system") removes stored preference', () => {
    localStorage.setItem('tritonTheme', 'dark');
    const { mql } = makeMQL(true);
    vi.stubGlobal('matchMedia', vi.fn(() => mql));

    const theme = useTheme();
    theme.setMode('system');
    expect(localStorage.getItem('tritonTheme')).toBeNull();
    expect(theme.resolved.value).toBe('light');
  });

  it('reacts to OS preference change while mode="system"', () => {
    const { mql, emit } = makeMQL(false);
    vi.stubGlobal('matchMedia', vi.fn(() => mql));

    const theme = useTheme();
    expect(theme.resolved.value).toBe('dark');

    emit(true);
    expect(theme.resolved.value).toBe('light');
    expect(document.documentElement.getAttribute('data-theme')).toBe('light');

    emit(false);
    expect(theme.resolved.value).toBe('dark');
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark');
  });

  it('returns the same singleton across calls (no watcher accumulation)', () => {
    const { mql } = makeMQL(false);
    vi.stubGlobal('matchMedia', vi.fn(() => mql));

    const a = useTheme();
    const b = useTheme();
    expect(a).toBe(b);
  });
});
