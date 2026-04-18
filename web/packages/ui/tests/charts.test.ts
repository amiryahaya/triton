import { describe, it, expect, vi } from 'vitest';
import { mount } from '@vue/test-utils';
import TLineChart from '../src/charts/TLineChart.vue';
import TBarChart from '../src/charts/TBarChart.vue';

vi.mock('chart.js/auto', () => {
  return {
    default: vi.fn().mockImplementation(() => ({
      destroy: vi.fn(),
      update: vi.fn(),
    })),
  };
});

describe('TLineChart', () => {
  it('renders a canvas element', () => {
    const w = mount(TLineChart, {
      props: { labels: ['W1', 'W2'], values: [20, 35] },
    });
    expect(w.find('canvas').exists()).toBe(true);
  });
});

describe('TBarChart', () => {
  it('renders a canvas element', () => {
    const w = mount(TBarChart, {
      props: { labels: ['Mon', 'Tue'], values: [10, 20] },
    });
    expect(w.find('canvas').exists()).toBe(true);
  });
});
