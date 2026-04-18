import { describe, it, expect } from 'vitest';
import { mount } from '@vue/test-utils';
import TAppShell from '../src/shell/TAppShell.vue';

describe('TAppShell', () => {
  it('sets portal-accent CSS var on root', () => {
    const w = mount(TAppShell, {
      props: { portalAccent: '#a78bfa' },
      slots: { sidebar: '<aside>S</aside>', default: '<div>main</div>' },
    });
    const style = (w.element as HTMLElement).getAttribute('style') ?? '';
    expect(style).toContain('--portal-accent');
    expect(style).toContain('#a78bfa');
  });

  it('renders topbar slot', () => {
    const w = mount(TAppShell, {
      props: { portalAccent: '#22d3ee' },
      slots: { topbar: '<span class="t-crumb">Overview</span>', default: 'body' },
    });
    expect(w.find('.t-crumb').exists()).toBe(true);
  });
});
