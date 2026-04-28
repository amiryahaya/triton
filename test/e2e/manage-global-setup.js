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
