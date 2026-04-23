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

describe('reportApi — data methods', () => {
  it('listScans GETs /v1/scans with no query string by default', () => {
    const http = fakeHttp();
    createReportApi(http).listScans();
    expect(http.get).toHaveBeenCalledWith('/v1/scans');
  });

  it('listScans GETs /v1/scans with query string when filter is provided', () => {
    const http = fakeHttp();
    createReportApi(http).listScans({ hostname: 'app01', limit: 50 });
    expect(http.get).toHaveBeenCalledWith('/v1/scans?hostname=app01&limit=50');
  });

  it('getScan GETs /v1/scans/:id', () => {
    const http = fakeHttp();
    createReportApi(http).getScan('scan-123');
    expect(http.get).toHaveBeenCalledWith('/v1/scans/scan-123');
  });

  it('getFindings GETs /v1/scans/:id/findings', () => {
    const http = fakeHttp();
    createReportApi(http).getFindings('scan-123');
    expect(http.get).toHaveBeenCalledWith('/v1/scans/scan-123/findings');
  });

  it('listMachines GETs /v1/systems', () => {
    const http = fakeHttp();
    createReportApi(http).listMachines();
    expect(http.get).toHaveBeenCalledWith('/v1/systems');
  });

  it('getMachineHistory GETs /v1/machines/:hostname (URL-encoded)', () => {
    const http = fakeHttp();
    createReportApi(http).getMachineHistory('app 01');
    expect(http.get).toHaveBeenCalledWith('/v1/machines/app%2001');
  });

  it('executive GETs /v1/executive', () => {
    const http = fakeHttp();
    createReportApi(http).executive();
    expect(http.get).toHaveBeenCalledWith('/v1/executive');
  });

  it('aggregate GETs /v1/aggregate', () => {
    const http = fakeHttp();
    createReportApi(http).aggregate();
    expect(http.get).toHaveBeenCalledWith('/v1/aggregate');
  });

  it('inventory GETs /v1/inventory with no query string by default', () => {
    const http = fakeHttp();
    createReportApi(http).inventory();
    expect(http.get).toHaveBeenCalledWith('/v1/inventory');
  });

  it('inventory GETs /v1/inventory with query string when filter provided', () => {
    const http = fakeHttp();
    createReportApi(http).inventory({ hostname: 'db01', pqc_status: 'UNSAFE' });
    expect(http.get).toHaveBeenCalledWith('/v1/inventory?hostname=db01&pqc_status=UNSAFE');
  });

  it('expiringCerts GETs /v1/certificates/expiring with within=all', () => {
    const http = fakeHttp();
    createReportApi(http).expiringCerts({ within: 'all' });
    expect(http.get).toHaveBeenCalledWith('/v1/certificates/expiring?within=all');
  });

  it('priority GETs /v1/priority with limit', () => {
    const http = fakeHttp();
    createReportApi(http).priority({ limit: 50 });
    expect(http.get).toHaveBeenCalledWith('/v1/priority?limit=50');
  });

  it('filters GETs /v1/filters', () => {
    const http = fakeHttp();
    createReportApi(http).filters();
    expect(http.get).toHaveBeenCalledWith('/v1/filters');
  });

  it('orgTrend GETs /v1/trends with no query when hostname omitted', () => {
    const http = fakeHttp();
    createReportApi(http).orgTrend();
    expect(http.get).toHaveBeenCalledWith('/v1/trends');
  });

  it('orgTrend GETs /v1/trends?hostname= when provided', () => {
    const http = fakeHttp();
    createReportApi(http).orgTrend('web01');
    expect(http.get).toHaveBeenCalledWith('/v1/trends?hostname=web01');
  });

  it('diff GETs /v1/diff?base=&compare=', () => {
    const http = fakeHttp();
    createReportApi(http).diff('scan-a', 'scan-b');
    expect(http.get).toHaveBeenCalledWith('/v1/diff?base=scan-a&compare=scan-b');
  });

  it('listAdminUsers GETs /v1/admin/users/', () => {
    const http = fakeHttp();
    createReportApi(http).listAdminUsers();
    expect(http.get).toHaveBeenCalledWith('/v1/admin/users/');
  });

  it('createAdminUser POSTs to /v1/admin/users/ with body', () => {
    const http = fakeHttp();
    const req = { email: 'a@b.com', name: 'Alice', role: 'viewer' as const, temp_password: 'pw1' };
    createReportApi(http).createAdminUser(req);
    expect(http.post).toHaveBeenCalledWith('/v1/admin/users/', req);
  });

  it('updateAdminUser PUTs to /v1/admin/users/:id with body', () => {
    const http = fakeHttp();
    const req = { name: 'Alice Renamed' };
    createReportApi(http).updateAdminUser('user-1', req);
    expect(http.put).toHaveBeenCalledWith('/v1/admin/users/user-1', req);
  });

  it('deleteAdminUser DELs /v1/admin/users/:id', () => {
    const http = fakeHttp();
    createReportApi(http).deleteAdminUser('user-1');
    expect(http.del).toHaveBeenCalledWith('/v1/admin/users/user-1');
  });

  it('resendInvite POSTs to /v1/admin/users/:id/resend-invite', () => {
    const http = fakeHttp();
    createReportApi(http).resendInvite('user-1');
    expect(http.post).toHaveBeenCalledWith('/v1/admin/users/user-1/resend-invite', {});
  });

  it('listAudit GETs /v1/admin/audit/ with no query by default', () => {
    const http = fakeHttp();
    createReportApi(http).listAudit();
    expect(http.get).toHaveBeenCalledWith('/v1/admin/audit/');
  });

  it('listAudit GETs /v1/admin/audit/ with query when filter provided', () => {
    const http = fakeHttp();
    createReportApi(http).listAudit({ limit: 100, actor_id: 'u-1' });
    expect(http.get).toHaveBeenCalledWith('/v1/admin/audit/?limit=100&actor_id=u-1');
  });
});
