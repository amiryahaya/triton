import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount } from '@vue/test-utils';
import { createTestingPinia } from '@pinia/testing';
import Dashboard from '../../src/views/Dashboard.vue';
import { useDashboardStore } from '../../src/stores/dashboard';

beforeEach(() => {
  vi.clearAllMocks();
});

describe('Dashboard view', () => {
  it('starts polling on mount and stops on unmount', () => {
    const w = mount(Dashboard, {
      global: {
        plugins: [createTestingPinia({ createSpy: vi.fn })],
        stubs: ['TStatCard'],
      },
    });
    const store = useDashboardStore();
    expect(store.startPolling).toHaveBeenCalledTimes(1);
    w.unmount();
    expect(store.stopPolling).toHaveBeenCalledTimes(1);
  });

  it('renders 5 stat cards', () => {
    const w = mount(Dashboard, {
      global: {
        plugins: [createTestingPinia({ createSpy: vi.fn })],
        stubs: { TStatCard: { template: '<div class="stat-stub"><slot /></div>' } },
      },
    });
    expect(w.findAll('.stat-stub').length).toBe(5);
    w.unmount();
  });

  it('renders the last-push delta hint when stats loaded', () => {
    const w = mount(Dashboard, {
      global: {
        plugins: [
          createTestingPinia({
            createSpy: vi.fn,
            initialState: {
              dashboard: {
                stats: {
                  hostsCount: 2,
                  activeAgents: 1,
                  runningJobs: 0,
                  queuedJobs: 0,
                  failedJobsToday: 0,
                  pushQueueDepth: 4,
                  lastPushAgeSeconds: 125,
                },
                loading: false,
              },
            },
          }),
        ],
        stubs: {
          TStatCard: {
            props: ['label', 'value', 'delta'],
            template: '<div class="stat-stub" :data-label="label" :data-delta="delta">{{ value }}</div>',
          },
        },
      },
    });
    const pushCard = w.findAll('.stat-stub').find((c) => c.attributes('data-label') === 'Push queue');
    expect(pushCard).toBeTruthy();
    expect(pushCard!.attributes('data-delta')).toBe('last push: 2m ago');
    w.unmount();
  });
});
