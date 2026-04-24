// license-global-setup.js — Seeds the license server test database with orgs, licenses, and activations.
// Auth flow: setup first-admin → login → change password → use JWT for all admin calls.
const { request } = require('@playwright/test');

const BASE_URL = 'http://localhost:8081';

// These must match the constants in license-admin.spec.js
const TEST_ADMIN_EMAIL = 'admin@triton.e2e';
const TEST_ADMIN_NAME = 'E2E Admin';
const TEST_ADMIN_PASSWORD = 'E2eAdminPass123!';

async function globalSetup() {
  const ctx = await request.newContext({ baseURL: BASE_URL });

  // Step 1: Bootstrap the first admin (DB is empty after TruncateAll in testlicenseserver)
  const setupResp = await ctx.post('/api/v1/setup/first-admin', {
    data: { name: TEST_ADMIN_NAME, email: TEST_ADMIN_EMAIL },
  });
  if (setupResp.status() !== 201) {
    throw new Error(`Setup first-admin failed: ${setupResp.status()} ${await setupResp.text()}`);
  }
  const { tempPassword } = await setupResp.json();

  // Step 2: Login with temp password
  const loginResp = await ctx.post('/api/v1/auth/login', {
    data: { email: TEST_ADMIN_EMAIL, password: tempPassword },
  });
  if (loginResp.status() !== 200) {
    throw new Error(`Login failed: ${loginResp.status()} ${await loginResp.text()}`);
  }
  const { token: tempToken } = await loginResp.json();

  // Step 3: Change to permanent password so tests can log in with a known credential
  const changePwResp = await ctx.post('/api/v1/auth/change-password', {
    headers: { Authorization: `Bearer ${tempToken}` },
    data: { current: tempPassword, next: TEST_ADMIN_PASSWORD },
  });
  if (changePwResp.status() !== 200) {
    throw new Error(`Change password failed: ${changePwResp.status()} ${await changePwResp.text()}`);
  }
  const { token } = await changePwResp.json();

  const authHeaders = { Authorization: `Bearer ${token}` };

  // Create two organizations
  const org1Resp = await ctx.post('/api/v1/admin/orgs', {
    headers: authHeaders,
    data: { name: 'Acme Corp', contact: 'admin@acme.com', notes: 'E2E test org' },
  });
  if (org1Resp.status() !== 201) {
    throw new Error(`Failed to create org1: ${org1Resp.status()} ${await org1Resp.text()}`);
  }
  const org1 = await org1Resp.json();

  const org2Resp = await ctx.post('/api/v1/admin/orgs', {
    headers: authHeaders,
    data: { name: 'Globex Inc', contact: 'admin@globex.com' },
  });
  if (org2Resp.status() !== 201) {
    throw new Error(`Failed to create org2: ${org2Resp.status()} ${await org2Resp.text()}`);
  }
  const org2 = await org2Resp.json();

  // Empty org for delete test (no licenses)
  const org3Resp = await ctx.post('/api/v1/admin/orgs', {
    headers: authHeaders,
    data: { name: 'EmptyOrg Ltd', contact: 'admin@empty.com' },
  });
  if (org3Resp.status() !== 201) {
    throw new Error(`Failed to create org3: ${org3Resp.status()} ${await org3Resp.text()}`);
  }

  // Create licenses
  const lic1Resp = await ctx.post('/api/v1/admin/licenses', {
    headers: authHeaders,
    data: { orgID: org1.id, tier: 'pro', seats: 5, days: 365 },
  });
  if (lic1Resp.status() !== 201) {
    throw new Error(`Failed to create lic1: ${lic1Resp.status()} ${await lic1Resp.text()}`);
  }
  const lic1 = await lic1Resp.json();

  const lic2Resp = await ctx.post('/api/v1/admin/licenses', {
    headers: authHeaders,
    data: { orgID: org2.id, tier: 'enterprise', seats: 10, days: 180 },
  });
  if (lic2Resp.status() !== 201) {
    throw new Error(`Failed to create lic2: ${lic2Resp.status()} ${await lic2Resp.text()}`);
  }

  // Activate a machine on lic1
  const actResp = await ctx.post('/api/v1/license/activate', {
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
