import { describe, it, expect, vi } from 'vitest';
import { createReportApi } from '../src/reportServer';

function fakeHttp() {
  return {
    get: vi.fn().mockResolvedValue({}),
    post: vi.fn().mockResolvedValue({}),
    put: vi.fn().mockResolvedValue({}),
    del: vi.fn().mockResolvedValue({}),
  };
}

describe('reportApi', () => {
  it('login POSTs to /v1/auth/login with credentials', () => {
    const http = fakeHttp();
    createReportApi(http).login({ email: 'a@b.com', password: 'pw' });
    expect(http.post).toHaveBeenCalledWith('/v1/auth/login', {
      email: 'a@b.com',
      password: 'pw',
    });
  });

  it('logout POSTs to /v1/auth/logout', () => {
    const http = fakeHttp();
    createReportApi(http).logout();
    expect(http.post).toHaveBeenCalledWith('/v1/auth/logout', {});
  });

  it('refresh POSTs to /v1/auth/refresh', () => {
    const http = fakeHttp();
    createReportApi(http).refresh();
    expect(http.post).toHaveBeenCalledWith('/v1/auth/refresh', {});
  });

  it('changePassword POSTs to /v1/auth/change-password', () => {
    const http = fakeHttp();
    createReportApi(http).changePassword({ current: 'old', next: 'newpw' });
    expect(http.post).toHaveBeenCalledWith('/v1/auth/change-password', {
      current: 'old',
      next: 'newpw',
    });
  });
});
