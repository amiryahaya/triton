import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import { createTestingPinia } from '@pinia/testing';
import Hosts from '../../src/views/Hosts.vue';
import { useHostsStore } from '../../src/stores/hosts';
import { useTagsStore } from '../../src/stores/tags';

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
            tags: {
              items: [
                { id: 't-1', name: 'production', color: '#6366F1', created_at: '' },
                { id: 't-2', name: 'database',   color: '#6366F1', created_at: '' },
              ],
              loading: false,
            },
            hosts: {
              items: [
                {
                  id: 'h-1',
                  ip: '10.0.0.10',
                  hostname: 'web-01',
                  tags: [{ id: 't-1', name: 'production', color: '#6366F1', created_at: '' }],
                  os: 'linux',
                  created_at: '',
                  updated_at: '',
                },
                {
                  id: 'h-2',
                  ip: '10.0.0.20',
                  hostname: 'db-01',
                  tags: [{ id: 't-2', name: 'database', color: '#6366F1', created_at: '' }],
                  os: 'linux',
                  created_at: '',
                  updated_at: '',
                },
              ],
              loading: false,
              filter: { tagID: undefined },
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
    const tags = useTagsStore();
    await flushPromises();

    expect(hosts.fetch).toHaveBeenCalledTimes(1);
    expect(tags.fetch).toHaveBeenCalledTimes(1);
    const html = wrapper.html();
    expect(html).toContain('web-01');
    expect(html).toContain('db-01');
  });

  it('fetches tags and hosts on mount', async () => {
    const wrapper = mountWithState();
    const hosts = useHostsStore();
    const tags = useTagsStore();
    await flushPromises();

    // Both stores are fetched on mount: tags for the filter dropdown,
    // hosts for the table. Hosts.vue calls Promise.all([tags.fetch(), hosts.fetch()]).
    expect(tags.fetch).toHaveBeenCalledTimes(1);
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
