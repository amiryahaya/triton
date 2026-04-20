import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import { createTestingPinia } from '@pinia/testing';
import Licence from '../../src/views/Licence.vue';
import type { LicenceSummary } from '@triton/api-client';

// Stub vue-router's useRouter so we can assert on the push spy without
// having to wire up a full router.
const pushSpy = vi.fn();
vi.mock('vue-router', () => ({
  useRouter: () => ({ push: pushSpy }),
}));

beforeEach(() => {
  vi.clearAllMocks();
  pushSpy.mockClear();
});

function makeSummary(overrides: Partial<LicenceSummary> = {}): LicenceSummary {
  return {
    tier: 'pro',
    features: { manage: true },
    limits: {
      seats: { cap: 10, used: 3 },
      hosts: { cap: 50, used: 12 },
      agents: { cap: 20, used: 4 },
      scans: { cap: 1000, used: 250, soft_buffer_ceiling: 1100 },
    },
    license_server_url: 'https://ls.example.com:9443/api',
    instance_id: '00000000-0000-0000-0000-000000000111',
    last_pushed_at: '2026-04-21T01:00:00Z',
    last_push_error: '',
    consecutive_failures: 0,
    ...overrides,
  };
}

describe('Licence view', () => {
  // Stub the composite UI components so tests don't depend on their
  // internal markup — we only care the view passes the right data.
  const stubs = {
    TStatCard: {
      props: ['label', 'value'],
      template: '<div class="t-stat-card-stub"><span class="label">{{ label }}</span><span class="value">{{ value }}</span></div>',
    },
    TPanel: {
      props: ['title'],
      template: '<section class="t-panel-stub" :data-title="title"><slot /></section>',
    },
    TButton: {
      template: '<button><slot /></button>',
    },
  };

  it('renders tier, limits, and heartbeat when summary is loaded', async () => {
    const wrapper = mount(Licence, {
      global: {
        stubs,
        plugins: [
          createTestingPinia({
            createSpy: vi.fn,
            initialState: {
              licence: {
                summary: makeSummary(),
                loading: false,
                error: '',
              },
            },
          }),
        ],
      },
    });
    await flushPromises();

    const html = wrapper.html();
    // Tier stat card
    expect(html).toContain('pro');
    expect(html).toContain('enabled'); // features.manage mapped to readable label
    // Limits table — 4 rows rendered.
    expect(wrapper.findAll('table.limits tbody tr')).toHaveLength(4);
    expect(html).toContain('Seats');
    expect(html).toContain('Hosts');
    expect(html).toContain('Agents');
    expect(html).toContain('Scans (monthly)');
    // Soft buffer annotation surfaces.
    expect(html).toContain('soft buffer: 1100');
    // Heartbeat shortens the URL to host.
    expect(html).toContain('ls.example.com:9443');
    // Instance ID renders in the monospace dd.
    expect(html).toContain('00000000-0000-0000-0000-000000000111');

    wrapper.unmount();
  });

  it('hides the error panel when push state is healthy', async () => {
    const wrapper = mount(Licence, {
      global: {
        stubs,
        plugins: [
          createTestingPinia({
            createSpy: vi.fn,
            initialState: {
              licence: {
                summary: makeSummary({ last_push_error: '', consecutive_failures: 0 }),
                loading: false,
                error: '',
              },
            },
          }),
        ],
      },
    });
    await flushPromises();

    // No t-panel with title "Push failure" should be present.
    const panels = wrapper.findAll('.t-panel-stub');
    const errorPanel = panels.find((p) => p.attributes('data-title') === 'Push failure');
    expect(errorPanel).toBeUndefined();

    wrapper.unmount();
  });

  it('shows the error panel when consecutive_failures > 0', async () => {
    const wrapper = mount(Licence, {
      global: {
        stubs,
        plugins: [
          createTestingPinia({
            createSpy: vi.fn,
            initialState: {
              licence: {
                summary: makeSummary({
                  last_push_error: 'upstream 500: licence server unreachable',
                  consecutive_failures: 3,
                }),
                loading: false,
                error: '',
              },
            },
          }),
        ],
      },
    });
    await flushPromises();

    const panels = wrapper.findAll('.t-panel-stub');
    const errorPanel = panels.find((p) => p.attributes('data-title') === 'Push failure');
    expect(errorPanel).toBeDefined();
    const html = errorPanel!.html();
    expect(html).toContain('3'); // failure count rendered
    expect(html).toContain('upstream 500');

    wrapper.unmount();
  });
});
