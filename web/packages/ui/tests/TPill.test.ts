import { describe, it, expect } from 'vitest';
import { mount } from '@vue/test-utils';
import TPill from '../src/atoms/TPill.vue';

describe('TPill', () => {
  it.each([
    'safe', 'warn', 'deprecated', 'unsafe', 'info', 'neutral', 'enterprise'
  ] as const)('renders %s variant', (variant) => {
    const w = mount(TPill, { props: { variant }, slots: { default: 'x' } });
    expect(w.classes()).toContain(`t-pill--${variant}`);
  });

  it('shows leading dot by default', () => {
    const w = mount(TPill, { props: { variant: 'safe' }, slots: { default: 'Safe' } });
    expect(w.find('.t-dot').exists()).toBe(true);
  });

  it('hides leading dot when dot=false', () => {
    const w = mount(TPill, { props: { variant: 'info', dot: false }, slots: { default: 'v1.0' } });
    expect(w.find('.t-dot').exists()).toBe(false);
  });

  it('defaults to neutral variant', () => {
    const w = mount(TPill, { slots: { default: 'Draft' } });
    expect(w.classes()).toContain('t-pill--neutral');
  });

  it('binds title prop to root element', () => {
    const w = mount(TPill, { props: { title: 'Tooltip text' }, slots: { default: 'x' } });
    expect(w.attributes('title')).toBe('Tooltip text');
  });
});
