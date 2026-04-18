import { describe, it, expect } from 'vitest';
import { mount } from '@vue/test-utils';
import TPanel from '../src/composite/TPanel.vue';

describe('TPanel', () => {
  it('renders title prop in header', () => {
    const w = mount(TPanel, {
      props: { title: 'Migration trend' },
      slots: { default: '<p>body</p>' },
    });
    expect(w.find('.t-panel-title').text()).toBe('Migration trend');
  });

  it('renders subtitle when provided', () => {
    const w = mount(TPanel, {
      props: { title: 'X', subtitle: '· 12 weeks' },
      slots: { default: 'body' },
    });
    expect(w.text()).toContain('· 12 weeks');
  });

  it('renders action slot', () => {
    const w = mount(TPanel, {
      props: { title: 'X' },
      slots: {
        default: 'body',
        action: '<a class="act" href="#">Open →</a>',
      },
    });
    expect(w.find('.act').exists()).toBe(true);
  });
});
