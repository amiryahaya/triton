import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import { createTestingPinia } from '@pinia/testing';
import Organisations from '../../src/views/Organisations.vue';
import { useApiClient } from '../../src/stores/apiClient';

beforeEach(() => { vi.clearAllMocks(); });

const ORGS = [
  {
    id: 'O1', name: 'Acme', contact: 'alice@acme.com', notes: '',
    createdAt: '2026-04-10T00:00:00Z', updatedAt: '2026-04-10T00:00:00Z',
  },
  {
    id: 'O2', name: 'Globex', contact: '', notes: 'partner',
    createdAt: '2026-04-12T00:00:00Z', updatedAt: '2026-04-20T00:00:00Z',
  },
];

function mountWith(orgs = ORGS) {
  const pinia = createTestingPinia({ createSpy: vi.fn, stubActions: false });
  const w = mount(Organisations, {
    global: { plugins: [pinia] },
  });
  const client = useApiClient();
  vi.spyOn(client, 'get').mockReturnValue({
    orgs: vi.fn().mockResolvedValue(orgs),
    deleteOrg: vi.fn().mockResolvedValue(undefined),
    createOrg: vi.fn().mockResolvedValue(orgs[0]),
  } as unknown as ReturnType<typeof client.get>);
  // Re-mount so onMounted fires with the stub in place.
  w.unmount();
  const w2 = mount(Organisations, {
    global: { plugins: [pinia] },
  });
  return w2;
}

describe('Organisations view', () => {
  it('renders rows for each org from the bare array', async () => {
    const w = mountWith();
    await flushPromises();
    await flushPromises();
    const html = w.html();
    expect(html).toContain('Acme');
    expect(html).toContain('Globex');
    expect(html).toContain('alice@acme.com');
    expect(html).toContain('partner');
    w.unmount();
  });

  it('opens OrganisationForm modal when "New organisation" is clicked', async () => {
    const w = mountWith();
    await flushPromises();
    await flushPromises();

    const buttons = w.findAll('button');
    const newBtn = buttons.find((b) => b.text().includes('New organisation'));
    expect(newBtn).toBeTruthy();
    await newBtn!.trigger('click');
    await flushPromises();

    expect(document.querySelector('.t-modal')).not.toBeNull();
    w.unmount();
  });
});
