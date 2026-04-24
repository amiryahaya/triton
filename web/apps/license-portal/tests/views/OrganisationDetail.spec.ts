import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import { createTestingPinia } from '@pinia/testing';
import { createRouter, createMemoryHistory } from 'vue-router';
import OrganisationDetail from '../../src/views/OrganisationDetail.vue';
import { useApiClient } from '../../src/stores/apiClient';

beforeEach(() => { vi.clearAllMocks(); });

const BASE_ORG = {
  id: 'O1', name: 'Acme', contact: 'alice@acme.com', notes: '',
  suspended: false, activeActivations: 2, hasSeatedLicenses: true,
  createdAt: '2026-04-10T00:00:00Z', updatedAt: '2026-04-10T00:00:00Z',
};

async function mountDetail(org = BASE_ORG) {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [{ path: '/orgs/:id', component: { template: '<div/>' } }],
  });
  await router.push('/orgs/O1');
  await router.isReady();

  const pinia = createTestingPinia({ createSpy: vi.fn, stubActions: false });
  const w0 = mount(OrganisationDetail, { global: { plugins: [pinia, router] } });
  const client = useApiClient();
  vi.spyOn(client, 'get').mockReturnValue({
    org: vi.fn().mockResolvedValue(org),
    licences: vi.fn().mockResolvedValue([]),
    suspendOrg: vi.fn().mockResolvedValue(undefined),
  } as unknown as ReturnType<typeof client.get>);
  w0.unmount();
  const w = mount(OrganisationDetail, { global: { plugins: [pinia, router] } });
  return { wrapper: w, client };
}

describe('OrganisationDetail view', () => {
  it('shows Active status pill for a non-suspended org', async () => {
    const { wrapper: w } = await mountDetail({ ...BASE_ORG, suspended: false });
    await flushPromises();
    await flushPromises();

    expect(w.html()).toContain('Active');
    expect(w.html()).not.toContain('Suspended');
    w.unmount();
  });

  it('shows Suspended status pill for a suspended org', async () => {
    const { wrapper: w } = await mountDetail({ ...BASE_ORG, suspended: true });
    await flushPromises();
    await flushPromises();

    expect(w.html()).toContain('Suspended');
    w.unmount();
  });

  it('suspend button reads "Suspend" when org is active', async () => {
    const { wrapper: w } = await mountDetail({ ...BASE_ORG, suspended: false });
    await flushPromises();
    await flushPromises();

    const btn = w.find('[data-test="org-detail-suspend"]');
    expect(btn.exists()).toBe(true);
    expect(btn.text()).toBe('Suspend');
    w.unmount();
  });

  it('suspend button reads "Unsuspend" when org is suspended', async () => {
    const { wrapper: w } = await mountDetail({ ...BASE_ORG, suspended: true });
    await flushPromises();
    await flushPromises();

    const btn = w.find('[data-test="org-detail-suspend"]');
    expect(btn.exists()).toBe(true);
    expect(btn.text()).toBe('Unsuspend');
    w.unmount();
  });

  it('clicking Suspend calls suspendOrg(id, true)', async () => {
    const { wrapper: w, client } = await mountDetail({ ...BASE_ORG, suspended: false });
    await flushPromises();
    await flushPromises();

    const btn = w.find('[data-test="org-detail-suspend"]');
    await btn.trigger('click');
    await flushPromises();

    const mockGet = client.get as ReturnType<typeof vi.fn>;
    expect(mockGet().suspendOrg).toHaveBeenCalledWith('O1', true);
    w.unmount();
  });

  it('clicking Unsuspend calls suspendOrg(id, false)', async () => {
    const { wrapper: w, client } = await mountDetail({ ...BASE_ORG, suspended: true });
    await flushPromises();
    await flushPromises();

    const btn = w.find('[data-test="org-detail-suspend"]');
    await btn.trigger('click');
    await flushPromises();

    const mockGet = client.get as ReturnType<typeof vi.fn>;
    expect(mockGet().suspendOrg).toHaveBeenCalledWith('O1', false);
    w.unmount();
  });
});
