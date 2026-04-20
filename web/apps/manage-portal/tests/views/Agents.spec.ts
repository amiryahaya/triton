import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import { createTestingPinia } from '@pinia/testing';
import Agents from '../../src/views/Agents.vue';
import { useAgentsStore } from '../../src/stores/agents';
import { useZonesStore } from '../../src/stores/zones';

beforeEach(() => {
  vi.clearAllMocks();
});

function mountWithState() {
  return mount(Agents, {
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
            agents: {
              items: [
                {
                  id: 'a-1',
                  name: 'scanner-01',
                  zone_id: 'z-1',
                  cert_serial: 'abc',
                  cert_expires_at: '2027-01-01T00:00:00Z',
                  status: 'active',
                  created_at: '',
                  updated_at: '',
                },
                {
                  id: 'a-2',
                  name: 'scanner-02',
                  zone_id: 'z-1',
                  cert_serial: 'def',
                  cert_expires_at: '2027-01-01T00:00:00Z',
                  status: 'pending',
                  created_at: '',
                  updated_at: '',
                },
                {
                  id: 'a-3',
                  name: 'scanner-old',
                  zone_id: 'z-1',
                  cert_serial: 'ghi',
                  cert_expires_at: '2024-01-01T00:00:00Z',
                  status: 'revoked',
                  created_at: '',
                  updated_at: '',
                },
              ],
              loading: false,
            },
          },
        }),
      ],
    },
  });
}

describe('Agents view', () => {
  it('calls agents.fetch on mount and renders rows with status pills', async () => {
    const wrapper = mountWithState();
    const agents = useAgentsStore();
    const zones = useZonesStore();
    await flushPromises();

    expect(agents.fetch).toHaveBeenCalledTimes(1);
    expect(zones.fetch).toHaveBeenCalledTimes(1);

    const html = wrapper.html();
    expect(html).toContain('scanner-01');
    expect(html).toContain('scanner-02');
    expect(html).toContain('scanner-old');
    // TPill renders a span with a variant-suffixed class.
    expect(html).toMatch(/t-pill--safe/);
    expect(html).toMatch(/t-pill--warn/);
    expect(html).toMatch(/t-pill--unsafe/);
  });

  it('hides Revoke button for already-revoked agents', async () => {
    const wrapper = mountWithState();
    await flushPromises();

    const revokeButtons = wrapper
      .findAll('button')
      .filter((b) => b.text().trim() === 'Revoke');
    // Two non-revoked agents in the fixture → two revoke buttons.
    expect(revokeButtons.length).toBe(2);
  });

  it('calls agents.enrol when the enrol form is submitted', async () => {
    const wrapper = mountWithState();
    const agents = useAgentsStore();
    // Override the stubbed action so the view's `await agents.enrol(...)`
    // gets a filename back and the success toast fires.
    (agents.enrol as ReturnType<typeof vi.fn>).mockResolvedValue(
      'agent-test-123.tar.gz',
    );
    await flushPromises();

    // Open the enrol modal via the header button.
    const enrolBtn = wrapper
      .findAll('button')
      .find((b) => b.text().includes('Enrol agent'));
    expect(enrolBtn).toBeTruthy();
    await enrolBtn!.trigger('click');
    await flushPromises();

    // Modal is teleported to body — look for the name input there.
    const nameInput = document.querySelector(
      '.t-modal input',
    ) as HTMLInputElement | null;
    expect(nameInput).toBeTruthy();
    nameInput!.value = 'new-agent';
    nameInput!.dispatchEvent(new Event('input'));
    await flushPromises();

    // Find the primary submit button in the modal footer.
    const submitBtn = Array.from(
      document.querySelectorAll('.t-modal-foot button'),
    ).find((b) => b.textContent?.includes('Enrol and download')) as HTMLButtonElement | undefined;
    expect(submitBtn).toBeTruthy();
    submitBtn!.click();
    await flushPromises();

    expect(agents.enrol).toHaveBeenCalledTimes(1);
    expect(agents.enrol).toHaveBeenCalledWith(
      expect.objectContaining({ name: 'new-agent' }),
    );
    wrapper.unmount();
  });
});
