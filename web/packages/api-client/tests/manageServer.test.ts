import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createHttp } from '../src/http';
import { createManageApi } from '../src/manageServer';

type Call = { method: string; path: string; body?: unknown };

function mockHttpCapture(): { http: ReturnType<typeof createHttp>; calls: Call[] } {
  const calls: Call[] = [];
  // @ts-expect-error we're building a minimal Http fake
  const http: ReturnType<typeof createHttp> = {
    get:  <T>(path: string)           => { calls.push({ method: 'GET', path });        return Promise.resolve({} as T); },
    post: <T>(path: string, body?: unknown) => { calls.push({ method: 'POST', path, body });  return Promise.resolve({} as T); },
    put:  <T>(path: string, body?: unknown) => { calls.push({ method: 'PUT', path, body });   return Promise.resolve({} as T); },
    del:  <T>(path: string)           => { calls.push({ method: 'DELETE', path });    return Promise.resolve({} as T); },
  };
  return { http, calls };
}

describe('createManageApi', () => {
  let fake: ReturnType<typeof mockHttpCapture>;
  let api: ReturnType<typeof createManageApi>;
  beforeEach(() => {
    fake = mockHttpCapture();
    api = createManageApi(fake.http);
  });

  it('getSetupStatus → GET /v1/setup/status', async () => {
    await api.getSetupStatus();
    expect(fake.calls).toEqual([{ method: 'GET', path: '/v1/setup/status' }]);
  });

  it('listHosts(zoneID) encodes query string', async () => {
    await api.listHosts('abc-123');
    expect(fake.calls[0]?.path).toBe('/v1/admin/hosts/?zone_id=abc-123');
  });

  it('listScanJobs with filters builds qs', async () => {
    await api.listScanJobs({ status: 'running', limit: 50 });
    expect(fake.calls[0]?.path).toBe('/v1/admin/scan-jobs/?status=running&limit=50');
  });

  it('createZone POSTs body', async () => {
    await api.createZone({ name: 'dmz', description: 'perimeter' });
    expect(fake.calls[0]).toEqual({
      method: 'POST',
      path: '/v1/admin/zones/',
      body: { name: 'dmz', description: 'perimeter' },
    });
  });

  it('cancelScanJob POSTs empty body to /cancel', async () => {
    await api.cancelScanJob('job-1');
    expect(fake.calls[0]).toEqual({ method: 'POST', path: '/v1/admin/scan-jobs/job-1/cancel', body: {} });
  });

  it('changePassword POSTs body to /v1/auth/change-password', async () => {
    await api.changePassword({ current: 'old', next: 'new' });
    expect(fake.calls[0]).toEqual({
      method: 'POST',
      path: '/v1/auth/change-password',
      body: { current: 'old', next: 'new' },
    });
  });

  it('getLicence GETs /v1/admin/licence', async () => {
    await api.getLicence();
    expect(fake.calls[0]).toEqual({ method: 'GET', path: '/v1/admin/licence' });
  });

  it('getSettings GETs /v1/admin/settings', async () => {
    await api.getSettings();
    expect(fake.calls[0]).toEqual({ method: 'GET', path: '/v1/admin/settings' });
  });
});

describe('enrolAgent (direct fetch)', () => {
  beforeEach(() => { vi.restoreAllMocks(); });

  it('POSTs JSON and returns the Blob', async () => {
    const blob = new Blob(['tar-gz-bytes'], { type: 'application/x-gzip' });
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      blob: () => Promise.resolve(blob),
    } as unknown as Response);

    const { http } = mockHttpCapture();
    const api = createManageApi(http);
    const out = await api.enrolAgent({ name: 'agent-01', zone_id: 'z1' });
    expect(out).toBe(blob);
    const [url, init] = fetchSpy.mock.calls[0]!;
    expect(url).toBe('/api/v1/admin/enrol/agent');
    expect((init as RequestInit).method).toBe('POST');
    expect((init as RequestInit).body).toBe(JSON.stringify({ name: 'agent-01', zone_id: 'z1' }));
  });

  it('throws on non-ok response', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: false, status: 403, statusText: 'Forbidden',
      text: () => Promise.resolve('license cap'),
    } as unknown as Response);
    const { http } = mockHttpCapture();
    const api = createManageApi(http);
    await expect(api.enrolAgent({ name: 'x' })).rejects.toThrow(/403/);
  });
});
