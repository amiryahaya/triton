import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import { createTestingPinia } from '@pinia/testing';
import Hosts from '../../src/views/Hosts.vue';
import { useHostsStore } from '../../src/stores/hosts';
import { useZonesStore } from '../../src/stores/zones';

// jsdom doesn't ship a real localStorage watcher, but the hosts store
// does `watch(filter, ...)` with writes to localStorage. Keep a no-op
// shim so the watcher doesn't throw.
beforeEach(() => {
  vi.clearAllMocks();
  localStorage.clear();
});

function mountWithState() {
  return mount(Hosts, {
    global: {
      plugins: [
        createTestingPinia({
          createSpy: vi.fn,
          initialState: {
            zones: {
              items: [
                { id: 'z-1', name: 'Corporate', description: '', created_at: '', updated_at: '' },
                { id: 'z-2', name: 'DMZ',       description: '', created_at: '', updated_at: '' },
              ],
              loading: false,
            },
            hosts: {
              items: [
                {
                  id: 'h-1',
                  hostname: 'web-01',
                  ip: '10.0.0.10',
                  zone_id: 'z-1',
                  os: 'linux',
                  created_at: '',
                  updated_at: '',
                },
                {
                  id: 'h-2',
                  hostname: 'db-01',
                  ip: '10.0.0.20',
                  zone_id: 'z-2',
                  os: 'linux',
                  created_at: '',
                  updated_at: '',
                },
              ],
              loading: false,
              filter: { zoneID: undefined },
            },
          },
        }),
      ],
    },
  });
}

describe('Hosts view', () => {
  it('calls zones.fetch + hosts.fetch on mount and renders rows', async () => {
    const wrapper = mountWithState();
    const hosts = useHostsStore();
    const zones = useZonesStore();
    await flushPromises();

    expect(hosts.fetch).toHaveBeenCalledTimes(1);
    expect(zones.fetch).toHaveBeenCalledTimes(1);
    const html = wrapper.html();
    expect(html).toContain('web-01');
    expect(html).toContain('db-01');
    // Zone column resolves id → name.
    expect(html).toContain('Corporate');
    expect(html).toContain('DMZ');
  });

  it('refetches hosts when the zone filter changes', async () => {
    const wrapper = mountWithState();
    const hosts = useHostsStore();
    await flushPromises();

    // Reset counts after mount-time fetch so we can isolate the filter trigger.
    (hosts.fetch as ReturnType<typeof vi.fn>).mockClear();

    hosts.filter.zoneID = 'z-1';
    await flushPromises();

    expect(hosts.fetch).toHaveBeenCalledTimes(1);
    wrapper.unmount();
  });

  it('renders cascade-aware delete confirmation', async () => {
    const wrapper = mountWithState();
    await flushPromises();

    const deleteBtn = wrapper.find('[data-test="host-delete-h-1"]');
    expect(deleteBtn.exists()).toBe(true);
    await deleteBtn.trigger('click');
    await flushPromises();

    const modal = document.querySelector('[data-test="confirm-dialog"]');
    expect(modal).not.toBeNull();
    const modalText = modal!.textContent ?? '';
    expect(modalText).toContain('web-01');
    expect(modalText).toContain('set host_id to NULL');
    expect(modalText).toContain('cannot be undone');
    wrapper.unmount();
  });
});
