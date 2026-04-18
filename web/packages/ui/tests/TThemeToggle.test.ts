import { describe, it, expect, beforeEach, vi } from 'vitest';
import { mount } from '@vue/test-utils';
import TThemeToggle from '../src/shell/TThemeToggle.vue';
import { __resetThemeForTest } from '../src/composables/useTheme';

function makeMQL(initial: boolean) {
  return {
    matches: initial,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
  };
}

describe('TThemeToggle', () => {
  beforeEach(() => {
    localStorage.clear();
    document.documentElement.removeAttribute('data-theme');
    __resetThemeForTest();
    vi.restoreAllMocks();
  });

  it('cycles dark → light → system on clicks', async () => {
    const mql = makeMQL(false);
    vi.stubGlobal('matchMedia', vi.fn(() => mql));

    const w = mount(TThemeToggle);
    // starts at 'dark' (default, no stored preference + system says dark)
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark');

    await w.trigger('click'); // dark → light
    expect(document.documentElement.getAttribute('data-theme')).toBe('light');

    await w.trigger('click'); // light → system (resolves to dark per mql)
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark');
    expect(localStorage.getItem('tritonTheme')).toBeNull();
  });
});
