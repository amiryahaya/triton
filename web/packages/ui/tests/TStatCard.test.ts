import { describe, it, expect } from 'vitest';
import { mount } from '@vue/test-utils';
import TStatCard from '../src/composite/TStatCard.vue';

describe('TStatCard', () => {
  it('renders label + value', () => {
    const w = mount(TStatCard, { props: { label: 'PQC ready', value: '68%' } });
    expect(w.text()).toContain('PQC ready');
    expect(w.text()).toContain('68%');
  });

  it('renders delta with direction class', () => {
    const w = mount(TStatCard, {
      props: { label: 'Unsafe', value: 214, delta: '↓ 12', deltaDir: 'up' },
    });
    expect(w.find('.t-stat-delta').classes()).toContain('is-up');
  });

  it('applies accent variable when prop set', () => {
    const w = mount(TStatCard, {
      props: { label: 'PQC', value: '68%', accent: 'var(--unsafe)' },
    });
    const style = (w.element as HTMLElement).getAttribute('style');
    expect(style).toContain('--stat-accent');
  });
});
