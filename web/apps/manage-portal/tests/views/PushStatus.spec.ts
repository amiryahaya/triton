import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount } from '@vue/test-utils';
import { createTestingPinia } from '@pinia/testing';
import PushStatus from '../../src/views/PushStatus.vue';
import { usePushStatusStore } from '../../src/stores/pushstatus';

beforeEach(() => {
  vi.clearAllMocks();
});

describe('PushStatus view', () => {
  it('starts polling on mount and stops on unmount', () => {
    const w = mount(PushStatus, {
      global: {
        plugins: [createTestingPinia({ createSpy: vi.fn })],
        stubs: ['TStatCard', 'TPanel'],
      },
    });
    const store = usePushStatusStore();
    expect(store.startPolling).toHaveBeenCalledTimes(1);
    w.unmount();
    expect(store.stopPolling).toHaveBeenCalledTimes(1);
  });

  it('hides the error panel when last_push_error is empty', () => {
    const w = mount(PushStatus, {
      global: {
        plugins: [
          createTestingPinia({
            createSpy: vi.fn,
            initialState: {
              pushstatus: {
                status: {
                  queue_depth: 3,
                  oldest_row_age_seconds: 10,
                  last_push_error: '',
                  consecutive_failures: 0,
                  last_pushed_at: '2026-04-20T10:00:00Z',
                },
                loading: false,
              },
            },
          }),
        ],
        stubs: {
          TStatCard: { template: '<div class="stat-stub"><slot /></div>' },
          TPanel: { template: '<section class="panel-stub"><slot /></section>' },
        },
      },
    });
    expect(w.find('.panel-stub').exists()).toBe(false);
    w.unmount();
  });

  it('renders the error excerpt and truncates to 400 chars', () => {
    const longError = 'E'.repeat(600);
    const w = mount(PushStatus, {
      global: {
        plugins: [
          createTestingPinia({
            createSpy: vi.fn,
            initialState: {
              pushstatus: {
                status: {
                  queue_depth: 0,
                  oldest_row_age_seconds: 0,
                  last_push_error: longError,
                  consecutive_failures: 4,
                  last_pushed_at: null,
                },
                loading: false,
              },
            },
          }),
        ],
        stubs: {
          TStatCard: { template: '<div class="stat-stub"><slot /></div>' },
          TPanel: {
            props: ['title'],
            template: '<section class="panel-stub" :data-title="title"><slot /></section>',
          },
        },
      },
    });
    const panel = w.find('.panel-stub');
    expect(panel.exists()).toBe(true);
    expect(panel.attributes('data-title')).toBe('Last push error');
    const pre = panel.find('pre');
    expect(pre.text().length).toBe(400);
    expect(pre.text()).toBe('E'.repeat(400));
    w.unmount();
  });

  it('formats the oldest-row age via fmtAge', () => {
    const w = mount(PushStatus, {
      global: {
        plugins: [
          createTestingPinia({
            createSpy: vi.fn,
            initialState: {
              pushstatus: {
                status: {
                  queue_depth: 0,
                  oldest_row_age_seconds: 125, // 2m
                  last_push_error: '',
                  consecutive_failures: 0,
                  last_pushed_at: null,
                },
                loading: false,
              },
            },
          }),
        ],
        stubs: {
          TStatCard: {
            props: ['label', 'value'],
            template: '<div class="stat-stub" :data-label="label" :data-value="value" />',
          },
          TPanel: { template: '<section />' },
        },
      },
    });
    const cards = w.findAll('.stat-stub');
    const oldest = cards.find((c) => c.attributes('data-label') === 'Oldest row');
    expect(oldest).toBeTruthy();
    expect(oldest!.attributes('data-value')).toBe('2m');
    w.unmount();
  });
});
