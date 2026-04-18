import { describe, it, expect, vi } from 'vitest';
import { createLicenseApi } from '../src/licenseServer';

function fakeHttp() {
  return {
    get:  vi.fn().mockResolvedValue({}),
    post: vi.fn().mockResolvedValue({}),
    put:  vi.fn().mockResolvedValue({}),
    del:  vi.fn().mockResolvedValue({}),
  };
}

describe('licenseApi', () => {
  it('dashboard hits /v1/dashboard/stats', () => {
    const http = fakeHttp();
    createLicenseApi(http).dashboard();
    expect(http.get).toHaveBeenCalledWith('/v1/dashboard/stats');
  });

  it('orgs(p) builds correct path', () => {
    const http = fakeHttp();
    createLicenseApi(http).orgs(3);
    expect(http.get).toHaveBeenCalledWith('/v1/orgs?page=3');
  });

  it('revokeLicence POSTs to revoke path', () => {
    const http = fakeHttp();
    createLicenseApi(http).revokeLicence('L1');
    expect(http.post).toHaveBeenCalledWith('/v1/licenses/L1/revoke', {});
  });

  it('activations(licenceId) builds correct path', () => {
    const http = fakeHttp();
    createLicenseApi(http).activations('L1');
    expect(http.get).toHaveBeenCalledWith('/v1/licenses/L1/activations');
  });
});
