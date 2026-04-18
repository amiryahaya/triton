import { describe, it, expect } from 'vitest';
import { mount } from '@vue/test-utils';
import TAvatar from '../src/atoms/TAvatar.vue';
import TKbd from '../src/atoms/TKbd.vue';

describe('TAvatar', () => {
  it('derives initials from name', () => {
    const w = mount(TAvatar, { props: { name: 'Jane Doe' } });
    expect(w.text()).toBe('JD');
  });

  it('handles single name', () => {
    const w = mount(TAvatar, { props: { name: 'Arif' } });
    expect(w.text()).toBe('AR');
  });

  it('accepts explicit initials override', () => {
    const w = mount(TAvatar, { props: { name: 'ignored', initials: 'OP' } });
    expect(w.text()).toBe('OP');
  });
});

describe('TKbd', () => {
  it('renders key content', () => {
    const w = mount(TKbd, { slots: { default: '⌘K' } });
    expect(w.text()).toBe('⌘K');
  });
});
