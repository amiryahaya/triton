// @ts-check
// manage-global-setup.js — logs into the manage test server and stores the
// JWT in Playwright's storageState so every test starts already authenticated.
const { chromium, request } = require('@playwright/test');
const path = require('path');
const fs = require('fs');

const BASE_URL = 'http://localhost:8082';
const CREDENTIALS = {
  email: 'e2e-manage@triton.test',
  password: 'Manage123!',
};

// Path where we store the authenticated browser state (cookies + localStorage).
const AUTH_FILE = path.join(__dirname, '.manage-auth.json');

async function globalSetup() {
  // Login via the REST API to get the JWT.
  const ctx = await request.newContext({ baseURL: BASE_URL });
  const resp = await ctx.post('/api/v1/auth/login', { data: CREDENTIALS });
  if (resp.status() !== 200) {
    throw new Error(`Login failed: ${resp.status()} ${await resp.text()}`);
  }
  const { token } = await resp.json();
  if (!token) throw new Error('Login response missing token');

  // ── Seed hosts for scan-enqueue wizard E2E tests ───────────────────────────
  // Use an authenticated context so /api/v1/admin/* routes accept the request.
  const api = await request.newContext({
    baseURL: BASE_URL,
    extraHTTPHeaders: { Authorization: `Bearer ${token}` },
  });

  // Seed a credential so one host can show the 🟢 icon in Step 2.
  // The credentials endpoint requires Vault (started by the test server).
  // If Vault is unavailable the seed is skipped gracefully so the other
  // wizard tests that don't need credentials can still run.
  let credID = null;
  try {
    const credResp = await api.post('/api/v1/admin/credentials', {
      data: {
        name:        'e2e-ssh-key',
        auth_type:   'ssh-password',   // ssh-password avoids PEM validation overhead
        username:    'e2e',
        password:    'e2e-password-123',
      },
    });
    if (credResp.status() === 201) {
      const cred = await credResp.json();
      credID = cred.id;
    } else if (credResp.status() === 409) {
      // Already exists from a previous run — fetch the list to get the ID.
      const listResp = await api.get('/api/v1/admin/credentials');
      if (listResp.status() === 200) {
        const list = await listResp.json();
        const found = Array.isArray(list) && list.find(c => c.name === 'e2e-ssh-key');
        if (found) credID = found.id;
      }
    }
  } catch (_) {
    // Vault not available — proceed without the SSH-credentialed host.
  }

  // Seed e2e-ssh-01: SSH host with credential (shows 🟢 in Step 2).
  await api.post('/api/v1/admin/hosts', {
    data: {
      hostname:        'e2e-ssh-01',
      ip:              '10.100.0.1',
      connection_type: 'ssh',
      ssh_port:        22,
      ...(credID ? { credentials_ref: credID } : {}),
    },
  }).catch(() => {});  // ignore 409 Conflict on repeated seeding

  // Seed e2e-agent-01: agent-connected host (shows 🔵 — enrolled agent).
  await api.post('/api/v1/admin/hosts', {
    data: {
      hostname:        'e2e-agent-01',
      ip:              '10.100.0.2',
      connection_type: 'agent',
    },
  }).catch(() => {});

  // Seed e2e-none-01: plain SSH host without credential (shows 🟡, triggers
  // the amber warning in Step 5 when filesystem job type is selected).
  await api.post('/api/v1/admin/hosts', {
    data: {
      hostname:        'e2e-none-01',
      ip:              '10.100.0.3',
      connection_type: 'ssh',
    },
  }).catch(() => {});

  await api.dispose();
  // ── End seed ────────────────────────────────────────────────────────────────

  await ctx.dispose();

  // Open a browser, navigate to the SPA root so the origin is established,
  // then inject the JWT into localStorage under the key the auth store uses.
  const browser = await chromium.launch();
  const page = await browser.newPage();
  await page.goto(`${BASE_URL}/ui/`);
  await page.evaluate((t) => {
    localStorage.setItem('tritonJWT', t);
  }, token);

  // Persist the storage state so every test in this run inherits it.
  await page.context().storageState({ path: AUTH_FILE });
  await browser.close();
}

module.exports = globalSetup;
