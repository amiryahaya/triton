import { describe, it, expect, beforeEach } from 'vitest';
import { mount } from '@vue/test-utils';
import TAuthGate from '../src/TAuthGate.vue';

describe('TAuthGate (adminKey)', () => {
  beforeEach(() => sessionStorage.clear());

  it('shows prompt when no key stored', () => {
    const w = mount(TAuthGate, {
      props: { type: 'adminKey' },
      slots: { default: '<div class="inner">app</div>' },
    });
    expect(w.find('.t-admin-prompt').exists()).toBe(true);
    expect(w.find('.inner').exists()).toBe(false);
  });

  it('renders default slot when key stored', () => {
    sessionStorage.setItem('triton_admin_key', 'abc');
    const w = mount(TAuthGate, {
      props: { type: 'adminKey' },
      slots: { default: '<div class="inner">app</div>' },
    });
    expect(w.find('.inner').exists()).toBe(true);
  });
});
