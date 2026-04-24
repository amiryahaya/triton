import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import { createTestingPinia } from '@pinia/testing';
import Organisations from '../../src/views/Organisations.vue';
import { useApiClient } from '../../src/stores/apiClient';

beforeEach(() => { vi.clearAllMocks(); });

const ORGS = [
  {
    id: 'O1', name: 'Acme', contact: 'alice@acme.com', notes: '',
    suspended: false, activeActivations: 3, hasSeatedLicenses: true,
    createdAt: '2026-04-10T00:00:00Z', updatedAt: '2026-04-10T00:00:00Z',
  },
  {
    id: 'O2', name: 'Globex', contact: '', notes: 'partner',
    suspended: true, activeActivations: 0, hasSeatedLicenses: false,
    createdAt: '2026-04-12T00:00:00Z', updatedAt: '2026-04-20T00:00:00Z',
  },
];

function makeMockClient(orgs = ORGS) {
  return {
    orgs: vi.fn().mockResolvedValue(orgs),
    deleteOrg: vi.fn().mockResolvedValue(undefined),
    createOrg: vi.fn().mockResolvedValue(orgs[0]),
    suspendOrg: vi.fn().mockResolvedValue(undefined),
  };
}

function mountWith(orgs = ORGS) {
  const pinia = createTestingPinia({ createSpy: vi.fn, stubActions: false });
  const w = mount(Organisations, {
    global: { plugins: [pinia] },
  });
  const client = useApiClient();
  vi.spyOn(client, 'get').mockReturnValue(
    makeMockClient(orgs) as unknown as ReturnType<typeof client.get>,
  );
  // Re-mount so onMounted fires with the stub in place.
  w.unmount();
  const w2 = mount(Organisations, {
    global: { plugins: [pinia] },
  });
  return { wrapper: w2, client };
}

describe('Organisations view', () => {
  it('renders rows for each org from the bare array', async () => {
    const { wrapper: w } = mountWith();
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
    const { wrapper: w } = mountWith();
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

  it('shows activation count when org has seated licenses', async () => {
    const { wrapper: w } = mountWith();
    await flushPromises();
    await flushPromises();

    // Acme: hasSeatedLicenses=true, activeActivations=3
    expect(w.html()).toContain('3');
    w.unmount();
  });

  it('shows em-dash when org has no seated licenses', async () => {
    const { wrapper: w } = mountWith();
    await flushPromises();
    await flushPromises();

    // Globex: hasSeatedLicenses=false → shows '—'
    expect(w.html()).toContain('—');
    w.unmount();
  });

  it('shows Suspended pill for a suspended org', async () => {
    const { wrapper: w } = mountWith();
    await flushPromises();
    await flushPromises();

    // Globex is suspended
    expect(w.html()).toContain('Suspended');
    w.unmount();
  });

  it('does not show Suspended pill for an active org', async () => {
    const singleActive = [{ ...ORGS[0], suspended: false }];
    const { wrapper: w } = mountWith(singleActive);
    await flushPromises();
    await flushPromises();

    expect(w.html()).not.toContain('Suspended');
    w.unmount();
  });

  it('calls suspendOrg(id, true) when Suspend is clicked', async () => {
    const activeOnly = [{ ...ORGS[0], suspended: false }];
    const { wrapper: w, client } = mountWith(activeOnly);
    await flushPromises();
    await flushPromises();

    const suspendBtn = w.find('[data-test="org-suspend-O1"]');
    expect(suspendBtn.exists()).toBe(true);
    expect(suspendBtn.text()).toBe('Suspend');
    await suspendBtn.trigger('click');
    await flushPromises();

    const mockGet = client.get as ReturnType<typeof vi.fn>;
    expect(mockGet().suspendOrg).toHaveBeenCalledWith('O1', true);
    w.unmount();
  });

  it('calls suspendOrg(id, false) when Unsuspend is clicked', async () => {
    const suspendedOnly = [{ ...ORGS[1], id: 'O2', suspended: true }];
    const { wrapper: w, client } = mountWith(suspendedOnly);
    await flushPromises();
    await flushPromises();

    const unsuspendBtn = w.find('[data-test="org-suspend-O2"]');
    expect(unsuspendBtn.exists()).toBe(true);
    expect(unsuspendBtn.text()).toBe('Unsuspend');
    await unsuspendBtn.trigger('click');
    await flushPromises();

    const mockGet = client.get as ReturnType<typeof vi.fn>;
    expect(mockGet().suspendOrg).toHaveBeenCalledWith('O2', false);
    w.unmount();
  });
});
