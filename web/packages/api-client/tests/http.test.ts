import { describe, it, expect, beforeEach, vi } from 'vitest';
import { createHttp } from '../src/http';

describe('createHttp', () => {
  beforeEach(() => vi.restoreAllMocks());

  it('injects auth headers from provided getter', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response('{}', { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);
    const http = createHttp({
      baseUrl: '/api',
      authHeader: () => ({ 'X-Triton-Admin-Key': 'abc' }),
    });
    await http.get('/v1/stats');
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/stats',
      expect.objectContaining({
        headers: expect.objectContaining({ 'X-Triton-Admin-Key': 'abc' }),
      })
    );
  });

  it('parses JSON on 2xx', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ hello: 'world' }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        })
      )
    );
    const http = createHttp({ baseUrl: '/api', authHeader: () => ({}) });
    const body = await http.get<{ hello: string }>('/v1/ping');
    expect(body.hello).toBe('world');
  });

  it('calls onUnauthorized on 401 and throws', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('no', { status: 401 })));
    const onUnauthorized = vi.fn();
    const http = createHttp({
      baseUrl: '/api',
      authHeader: () => ({}),
      onUnauthorized,
    });
    await expect(http.get('/v1/stats')).rejects.toThrow();
    expect(onUnauthorized).toHaveBeenCalled();
  });

  it('throws with body text on non-2xx', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('boom', { status: 500 })));
    const http = createHttp({ baseUrl: '/api', authHeader: () => ({}) });
    await expect(http.get('/v1/stats')).rejects.toThrow(/500/);
  });
});
