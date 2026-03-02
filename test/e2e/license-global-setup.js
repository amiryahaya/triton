// license-global-setup.js — Seeds the license server test database with orgs, licenses, and activations.
const { request } = require('@playwright/test');

const BASE_URL = 'http://localhost:8081';
const ADMIN_KEY = 'e2e-test-key';

async function globalSetup() {
  const ctx = await request.newContext({
    baseURL: BASE_URL,
    extraHTTPHeaders: {
      'X-Triton-Admin-Key': ADMIN_KEY,
      'Content-Type': 'application/json',
    },
  });

  // Create two organizations
  const org1Resp = await ctx.post('/api/v1/admin/orgs', {
    data: { name: 'Acme Corp', contact: 'admin@acme.com', notes: 'E2E test org' },
  });
  if (org1Resp.status() !== 201) {
    throw new Error(`Failed to create org1: ${org1Resp.status()} ${await org1Resp.text()}`);
  }
  const org1 = await org1Resp.json();

  const org2Resp = await ctx.post('/api/v1/admin/orgs', {
    data: { name: 'Globex Inc', contact: 'admin@globex.com' },
  });
  if (org2Resp.status() !== 201) {
    throw new Error(`Failed to create org2: ${org2Resp.status()} ${await org2Resp.text()}`);
  }
  const org2 = await org2Resp.json();

  // Empty org for delete test (no licenses)
  const org3Resp = await ctx.post('/api/v1/admin/orgs', {
    data: { name: 'EmptyOrg Ltd', contact: 'admin@empty.com' },
  });
  if (org3Resp.status() !== 201) {
    throw new Error(`Failed to create org3: ${org3Resp.status()} ${await org3Resp.text()}`);
  }

  // Create licenses
  const lic1Resp = await ctx.post('/api/v1/admin/licenses', {
    data: { orgID: org1.id, tier: 'pro', seats: 5, days: 365 },
  });
  if (lic1Resp.status() !== 201) {
    throw new Error(`Failed to create lic1: ${lic1Resp.status()} ${await lic1Resp.text()}`);
  }
  const lic1 = await lic1Resp.json();

  const lic2Resp = await ctx.post('/api/v1/admin/licenses', {
    data: { orgID: org2.id, tier: 'enterprise', seats: 10, days: 180 },
  });
  if (lic2Resp.status() !== 201) {
    throw new Error(`Failed to create lic2: ${lic2Resp.status()} ${await lic2Resp.text()}`);
  }

  // Activate a machine on lic1
  const actResp = await ctx.post('/api/v1/license/activate', {
    headers: { 'Content-Type': 'application/json' },
    data: {
      licenseID: lic1.id,
      machineID: 'e2e-machine-001',
      hostname: 'e2e-host-01',
      os: 'linux',
      arch: 'amd64',
    },
  });
  if (actResp.status() !== 201) {
    throw new Error(`Failed to activate: ${actResp.status()} ${await actResp.text()}`);
  }

  await ctx.dispose();
}

module.exports = globalSetup;
