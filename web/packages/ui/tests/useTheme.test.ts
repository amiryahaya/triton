import { describe, it, expect, beforeEach, vi } from 'vitest';
import { useTheme } from '../src/composables/useTheme';

describe('useTheme', () => {
  beforeEach(() => {
    localStorage.clear();
    document.documentElement.removeAttribute('data-theme');
    vi.restoreAllMocks();
  });

  it('defaults to dark when no preference stored and no system hint', () => {
    const matchMedia = vi.fn().mockReturnValue({
      matches: false,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    });
    vi.stubGlobal('matchMedia', matchMedia);

    const theme = useTheme();
    expect(theme.resolved.value).toBe('dark');
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark');
  });

  it('respects prefers-color-scheme: light on first visit', () => {
    vi.stubGlobal('matchMedia', vi.fn().mockReturnValue({
      matches: true, addEventListener: vi.fn(), removeEventListener: vi.fn(),
    }));

    const theme = useTheme();
    expect(theme.resolved.value).toBe('light');
    expect(document.documentElement.getAttribute('data-theme')).toBe('light');
  });

  it('restores stored user preference over system', () => {
    localStorage.setItem('tritonTheme', 'light');
    vi.stubGlobal('matchMedia', vi.fn().mockReturnValue({
      matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn(),
    }));

    const theme = useTheme();
    expect(theme.mode.value).toBe('light');
    expect(theme.resolved.value).toBe('light');
  });

  it('setMode persists and updates DOM', () => {
    vi.stubGlobal('matchMedia', vi.fn().mockReturnValue({
      matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn(),
    }));

    const theme = useTheme();
    theme.setMode('light');
    expect(localStorage.getItem('tritonTheme')).toBe('light');
    expect(document.documentElement.getAttribute('data-theme')).toBe('light');
    expect(theme.resolved.value).toBe('light');
  });

  it('setMode("system") removes stored preference', () => {
    localStorage.setItem('tritonTheme', 'dark');
    vi.stubGlobal('matchMedia', vi.fn().mockReturnValue({
      matches: true, addEventListener: vi.fn(), removeEventListener: vi.fn(),
    }));

    const theme = useTheme();
    theme.setMode('system');
    expect(localStorage.getItem('tritonTheme')).toBeNull();
    expect(theme.resolved.value).toBe('light');
  });
});
