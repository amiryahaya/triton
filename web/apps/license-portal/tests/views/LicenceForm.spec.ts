import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import LicenceForm from '../../src/views/modals/LicenceForm.vue';

beforeEach(() => { vi.clearAllMocks(); });

const ORGS = [
  { id: 'O1', name: 'Acme', contact: '', notes: '',
    createdAt: '2026-04-10T00:00:00Z', updatedAt: '2026-04-10T00:00:00Z' },
];

function mountForm() {
  return mount(LicenceForm, {
    props: { open: true, orgs: ORGS },
  });
}

describe('LicenceForm', () => {
  it('disables submit when seats=0 and scans=0', async () => {
    const w = mountForm();
    await flushPromises();

    const btn = document.querySelector('[data-test="submit-create"]') as HTMLButtonElement;
    expect(btn).not.toBeNull();
    expect(btn.disabled).toBe(true);

    const hint = document.querySelector('[data-test="validation-hint"]');
    expect(hint?.textContent).toContain('At least one of seats or scans');
    w.unmount();
  });

  it('enables submit when seats=0 and scans>0', async () => {
    const w = mountForm();
    await flushPromises();

    const scansInput = document.querySelector('[data-test="input-scans"]') as HTMLInputElement;
    scansInput.value = '500';
    scansInput.dispatchEvent(new Event('input'));
    await flushPromises();

    const btn = document.querySelector('[data-test="submit-create"]') as HTMLButtonElement;
    expect(btn.disabled).toBe(false);
    w.unmount();
  });

  it('enables submit when seats>0 and scans=0', async () => {
    const w = mountForm();
    await flushPromises();

    const seatsInput = document.querySelector('[data-test="input-seats"]') as HTMLInputElement;
    seatsInput.value = '5';
    seatsInput.dispatchEvent(new Event('input'));
    await flushPromises();

    const btn = document.querySelector('[data-test="submit-create"]') as HTMLButtonElement;
    expect(btn.disabled).toBe(false);
    w.unmount();
  });

  it('emits submit with correct payload shape on Create click', async () => {
    const w = mountForm();
    await flushPromises();

    const scansInput = document.querySelector('[data-test="input-scans"]') as HTMLInputElement;
    scansInput.value = '1000';
    scansInput.dispatchEvent(new Event('input'));
    await flushPromises();

    const btn = document.querySelector('[data-test="submit-create"]') as HTMLButtonElement;
    btn.click();
    await flushPromises();

    const emitted = w.emitted('submit');
    expect(emitted).toBeTruthy();
    const payload = emitted![0][0] as Record<string, unknown>;
    expect(payload.orgID).toBe('O1');
    expect(payload.tier).toBe('pro');
    expect(payload.seats).toBe(0);
    expect(payload.days).toBe(365);
    const limits = payload.limits as Array<{ metric: string; cap: number }>;
    expect(limits).toHaveLength(1);
    expect(limits[0].metric).toBe('scans');
    expect(limits[0].cap).toBe(1000);
    w.unmount();
  });
});
