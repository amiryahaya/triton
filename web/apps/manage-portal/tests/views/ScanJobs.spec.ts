import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import { createTestingPinia } from '@pinia/testing';
import ScanJobs from '../../src/views/ScanJobs.vue';
import { useScanJobsStore } from '../../src/stores/scanjobs';
import { useZonesStore } from '../../src/stores/zones';

beforeEach(() => {
  vi.clearAllMocks();
});

function mountWithState() {
  return mount(ScanJobs, {
    global: {
      plugins: [
        createTestingPinia({
          createSpy: vi.fn,
          initialState: {
            zones: {
              items: [
                { id: 'z-1', name: 'Corporate', description: '', created_at: '', updated_at: '' },
              ],
              loading: false,
            },
            scanjobs: {
              items: [
                {
                  id: 'job-1',
                  tenant_id: 't-1',
                  zone_id: 'z-1',
                  host_id: 'h-1',
                  profile: 'standard',
                  status: 'running',
                  cancel_requested: false,
                  enqueued_at: '2026-04-20T10:00:00Z',
                  progress_text: '42%',
                  error_message: '',
                },
                {
                  id: 'job-2',
                  tenant_id: 't-1',
                  zone_id: 'z-1',
                  host_id: 'h-2',
                  profile: 'quick',
                  status: 'completed',
                  cancel_requested: false,
                  enqueued_at: '2026-04-20T09:55:00Z',
                  progress_text: 'done',
                  error_message: '',
                },
                {
                  id: 'job-3',
                  tenant_id: 't-1',
                  zone_id: 'z-1',
                  host_id: 'h-3',
                  profile: 'quick',
                  status: 'failed',
                  cancel_requested: false,
                  enqueued_at: '2026-04-20T09:50:00Z',
                  progress_text: '',
                  error_message: 'boom',
                },
              ],
              selected: null,
              loading: false,
              filter: {},
            },
          },
        }),
      ],
    },
  });
}

describe('ScanJobs view', () => {
  it('starts polling on mount and stops on unmount, fetches zones', async () => {
    const wrapper = mountWithState();
    const jobs = useScanJobsStore();
    const zones = useZonesStore();
    await flushPromises();

    expect(zones.fetch).toHaveBeenCalledTimes(1);
    expect(jobs.startPolling).toHaveBeenCalledTimes(1);
    wrapper.unmount();
    expect(jobs.stopPolling).toHaveBeenCalledTimes(1);
  });

  it('renders rows with correct status pill variants', async () => {
    const wrapper = mountWithState();
    await flushPromises();

    const html = wrapper.html();
    // One row per job — assert by count rather than by id text since
    // the `id` column slot renders only the Cancel button (or nothing).
    const rows = wrapper.findAll('.t-tbl-row');
    expect(rows.length).toBe(3);
    expect(html).toContain('running');
    expect(html).toContain('completed');
    expect(html).toContain('failed');
    // running → warn, completed → safe, failed → unsafe.
    expect(html).toMatch(/t-pill--warn/);
    expect(html).toMatch(/t-pill--safe/);
    expect(html).toMatch(/t-pill--unsafe/);
  });

  it('shows Cancel only for queued/running jobs', async () => {
    const wrapper = mountWithState();
    await flushPromises();

    const cancelButtons = wrapper
      .findAll('button')
      .filter((b) => b.text().trim() === 'Cancel');
    // 1 running job → 1 cancel button. Completed + failed do not show it.
    expect(cancelButtons.length).toBe(1);
  });

  it('changing the status filter triggers a refetch', async () => {
    const wrapper = mountWithState();
    const jobs = useScanJobsStore();
    await flushPromises();
    // startPolling fires fetch once internally in the real store, but
    // createTestingPinia auto-stubs it — so we only see the watcher fire.
    const callsBefore = (jobs.fetch as ReturnType<typeof vi.fn>).mock.calls.length;

    jobs.filter.status = 'running';
    await flushPromises();

    const callsAfter = (jobs.fetch as ReturnType<typeof vi.fn>).mock.calls.length;
    expect(callsAfter).toBeGreaterThan(callsBefore);
    wrapper.unmount();
  });

  it('row click opens the detail drawer and fetches job detail', async () => {
    const wrapper = mountWithState();
    const jobs = useScanJobsStore();
    await flushPromises();

    // TDataTable renders rows as `.t-tbl-row` divs. Click the first one
    // (job-1) to trigger the `row-click` emit.
    const rows = wrapper.findAll('.t-tbl-row');
    expect(rows.length).toBe(3);
    await rows[0].trigger('click');
    await flushPromises();

    // Drawer should be rendered (title "Scan Job" in drawer header).
    const drawer = wrapper.find('.drawer');
    expect(drawer.exists()).toBe(true);
    // Detail fetch called with the clicked id.
    expect(jobs.getDetail).toHaveBeenCalledWith('job-1');
    wrapper.unmount();
  });
});
