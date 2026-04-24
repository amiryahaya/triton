import { describe, it, expect, vi } from 'vitest';
import { createLicenseApi } from '../src/licenseServer';

// These tests verify that the api-client hits the actual backend routes
// declared in pkg/licenseserver/server.go — all admin endpoints live
// under /api/v1/admin/*. The previous tests asserted the paths the
// frontend happened to use, which is why the whole admin UI shipped
// broken (every endpoint 404'd against the real backend).

function fakeHttp() {
  return {
    get:  vi.fn().mockResolvedValue({}),
    post: vi.fn().mockResolvedValue({}),
    put:  vi.fn().mockResolvedValue({}),
    del:  vi.fn().mockResolvedValue({}),
  };
}

describe('licenseApi', () => {
  it('dashboard hits /v1/admin/stats', () => {
    const http = fakeHttp();
    createLicenseApi(http).dashboard();
    expect(http.get).toHaveBeenCalledWith('/v1/admin/stats');
  });

  it('orgs() hits /v1/admin/orgs', () => {
    const http = fakeHttp();
    createLicenseApi(http).orgs();
    expect(http.get).toHaveBeenCalledWith('/v1/admin/orgs');
  });

  it('org(id) hits /v1/admin/orgs/:id', () => {
    const http = fakeHttp();
    createLicenseApi(http).org('O1');
    expect(http.get).toHaveBeenCalledWith('/v1/admin/orgs/O1');
  });

  it('createOrg POSTs to /v1/admin/orgs', () => {
    const http = fakeHttp();
    createLicenseApi(http).createOrg({ name: 'Acme', contact: 'admin@acme.com' });
    expect(http.post).toHaveBeenCalledWith('/v1/admin/orgs', { name: 'Acme', contact: 'admin@acme.com' });
  });

  it('deleteOrg DELETEs /v1/admin/orgs/:id', () => {
    const http = fakeHttp();
    createLicenseApi(http).deleteOrg('O1');
    expect(http.del).toHaveBeenCalledWith('/v1/admin/orgs/O1');
  });

  it('licences() hits /v1/admin/licenses (no filter)', () => {
    const http = fakeHttp();
    createLicenseApi(http).licences();
    expect(http.get).toHaveBeenCalledWith('/v1/admin/licenses');
  });

  it('licences({ org }) appends ?org=<id> query param', () => {
    const http = fakeHttp();
    createLicenseApi(http).licences({ org: 'O1' });
    expect(http.get).toHaveBeenCalledWith('/v1/admin/licenses?org=O1');
  });

  it('licence(id) hits /v1/admin/licenses/:id', () => {
    const http = fakeHttp();
    createLicenseApi(http).licence('L1');
    expect(http.get).toHaveBeenCalledWith('/v1/admin/licenses/L1');
  });

  it('revokeLicence POSTs to /v1/admin/licenses/:id/revoke', () => {
    const http = fakeHttp();
    createLicenseApi(http).revokeLicence('L1');
    expect(http.post).toHaveBeenCalledWith('/v1/admin/licenses/L1/revoke', {});
  });

  it('createLicence POSTs to /v1/admin/licenses', () => {
    const http = fakeHttp();
    const req = {
      orgID: 'O1',
      tier: 'pro' as const,
      seats: 10,
      days: 365,
      features: {
        report: true,
        manage: false,
        comprehensive_profile: true,
        diff_trend: true,
        custom_policy: false,
        sso: false,
      },
      limits: [],
      product_scope: 'report' as const,
    };
    createLicenseApi(http).createLicence(req);
    expect(http.post).toHaveBeenCalledWith('/v1/admin/licenses', req);
  });

  it('downloadAgentYaml POSTs to /v1/admin/licenses/:id/agent-yaml', () => {
    const http = fakeHttp();
    createLicenseApi(http).downloadAgentYaml('L1');
    expect(http.post).toHaveBeenCalledWith('/v1/admin/licenses/L1/agent-yaml', {});
  });

  it('activations(licenceId) builds /v1/admin/activations?license=:id', () => {
    const http = fakeHttp();
    createLicenseApi(http).activations('L1');
    expect(http.get).toHaveBeenCalledWith('/v1/admin/activations?license=L1');
  });

  it('audit(p) builds /v1/admin/audit?page=N', () => {
    const http = fakeHttp();
    createLicenseApi(http).audit(5);
    expect(http.get).toHaveBeenCalledWith('/v1/admin/audit?page=5');
  });
});
