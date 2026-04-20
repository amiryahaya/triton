import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import { createTestingPinia } from '@pinia/testing';
import Zones from '../../src/views/Zones.vue';
import { useZonesStore } from '../../src/stores/zones';

describe('Zones view', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('calls zones.fetch on mount and renders rows from the store', async () => {
    const wrapper = mount(Zones, {
      global: {
        plugins: [
          createTestingPinia({
            createSpy: vi.fn,
            initialState: {
              zones: {
                items: [
                  {
                    id: 'z-1',
                    name: 'Corporate',
                    description: 'HQ network',
                    created_at: '2026-04-19T10:00:00Z',
                    updated_at: '2026-04-19T10:00:00Z',
                  },
                  {
                    id: 'z-2',
                    name: 'DMZ',
                    description: '',
                    created_at: '2026-04-19T11:00:00Z',
                    updated_at: '2026-04-19T11:00:00Z',
                  },
                ],
                loading: false,
              },
            },
          }),
        ],
      },
    });

    const store = useZonesStore();
    await flushPromises();

    expect(store.fetch).toHaveBeenCalledTimes(1);
    const html = wrapper.html();
    expect(html).toContain('Corporate');
    expect(html).toContain('DMZ');
    expect(html).toContain('HQ network');
  });

  it('opens the form modal when New zone is clicked', async () => {
    const wrapper = mount(Zones, {
      global: {
        plugins: [createTestingPinia({ createSpy: vi.fn })],
      },
    });
    await flushPromises();

    // Initially the modal is not rendered (TModal uses v-if + Teleport).
    expect(document.querySelector('.t-modal')).toBeNull();

    const buttons = wrapper.findAll('button');
    const newBtn = buttons.find((b) => b.text().includes('New zone'));
    expect(newBtn).toBeTruthy();
    await newBtn!.trigger('click');
    await flushPromises();

    expect(document.querySelector('.t-modal')).not.toBeNull();
    expect(document.body.textContent).toContain('New zone');
    wrapper.unmount();
  });
});
