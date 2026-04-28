// @ts-check
// Credentials — E2E tests for the Credentials page in the manage portal.
//
// To enable: wire up a manage-portal E2E test server (similar to
// test/e2e/cmd/testserver/main.go for the report portal) that:
//   1. Starts a fake Vault KV v2 stub.
//   2. Creates a manageserver.Server with VaultAddr pointing to the stub.
//   3. Completes setup (admin + license) programmatically.
//   4. Listens on a fixed port (e.g. :8083) for Playwright.
//   5. Seeds an admin session token stored in localStorage so tests
//      start directly on protected pages without the login flow.
//
// Then add a 'test-e2e-manage' Makefile target:
//   test-e2e-manage: db-up build-manageserver
//       cd test/e2e && npx playwright test --config=playwright.manage.config.js

const { test, expect } = require('@playwright/test');

test.describe.configure({ mode: 'skip' });

// ---------------------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------------------

test.describe('Credentials — navigation', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/ui/#/');
  });

  test('sidebar shows Credentials link under Inventory', async ({ page }) => {
    await expect(page.locator('a[href="#/inventory/credentials"]')).toBeVisible();
  });

  test('Credentials link is between Hosts and Agents in the sidebar', async ({ page }) => {
    const navItems = page.locator('nav a');
    const labels = await navItems.allTextContents();
    const hostsIdx = labels.findIndex(l => l.trim() === 'Hosts');
    const credsIdx = labels.findIndex(l => l.trim() === 'Credentials');
    const agentsIdx = labels.findIndex(l => l.trim() === 'Agents');
    expect(hostsIdx).toBeGreaterThanOrEqual(0);
    expect(credsIdx).toBeGreaterThan(hostsIdx);
    expect(agentsIdx).toBeGreaterThan(credsIdx);
  });
});

// ---------------------------------------------------------------------------
// Credentials list page
// ---------------------------------------------------------------------------

test.describe('Credentials — list page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/ui/#/inventory/credentials');
  });

  test('renders page heading and Add Credential button', async ({ page }) => {
    await expect(page.getByRole('heading', { name: /credentials/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /add credential/i })).toBeVisible();
  });

  test('empty state shows no rows', async ({ page }) => {
    const rows = page.locator('tbody tr');
    await expect(rows).toHaveCount(0);
  });
});

// ---------------------------------------------------------------------------
// Create credential
// ---------------------------------------------------------------------------

test.describe('Credentials — create', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/ui/#/inventory/credentials');
  });

  test('Add Credential opens the form modal', async ({ page }) => {
    await page.getByRole('button', { name: /add credential/i }).click();
    await expect(page.getByRole('dialog')).toBeVisible();
    await expect(page.getByLabel(/name/i)).toBeVisible();
    await expect(page.getByLabel(/type/i)).toBeVisible();
  });

  test('SSH Key type shows private key textarea and optional passphrase', async ({ page }) => {
    await page.getByRole('button', { name: /add credential/i }).click();
    await page.getByLabel(/type/i).selectOption('ssh-key');
    await expect(page.getByLabel(/private key/i)).toBeVisible();
    await expect(page.getByLabel(/passphrase/i)).toBeVisible();
    await expect(page.getByLabel(/password/i)).not.toBeVisible();
  });

  test('SSH Password type shows password field, hides private key', async ({ page }) => {
    await page.getByRole('button', { name: /add credential/i }).click();
    await page.getByLabel(/type/i).selectOption('ssh-password');
    await expect(page.getByLabel(/password/i)).toBeVisible();
    await expect(page.getByLabel(/private key/i)).not.toBeVisible();
  });

  test('WinRM type shows password and Use HTTPS toggle', async ({ page }) => {
    await page.getByRole('button', { name: /add credential/i }).click();
    await page.getByLabel(/type/i).selectOption('winrm-password');
    await expect(page.getByLabel(/password/i)).toBeVisible();
    await expect(page.getByLabel(/use https/i)).toBeVisible();
  });

  test('submitting SSH password credential adds row to list', async ({ page }) => {
    await page.getByRole('button', { name: /add credential/i }).click();
    await page.getByLabel(/name/i).fill('test-ssh-pw');
    await page.getByLabel(/type/i).selectOption('ssh-password');
    await page.getByLabel(/username/i).fill('ubuntu');
    await page.getByLabel(/password/i).fill('hunter2');
    await page.getByRole('button', { name: /save/i }).click();

    // Modal closes on success.
    await expect(page.getByRole('dialog')).not.toBeVisible();

    // New row appears in the table.
    await expect(page.getByText('test-ssh-pw')).toBeVisible();
    await expect(page.getByText('ssh-password')).toBeVisible();
  });

  test('submitting SSH key without private key shows inline error', async ({ page }) => {
    await page.getByRole('button', { name: /add credential/i }).click();
    await page.getByLabel(/name/i).fill('bad-key-cred');
    await page.getByLabel(/type/i).selectOption('ssh-key');
    await page.getByLabel(/username/i).fill('ops');
    // Leave private_key empty.
    await page.getByRole('button', { name: /save/i }).click();

    // Error message appears, modal stays open.
    await expect(page.getByRole('dialog')).toBeVisible();
    await expect(page.getByText(/private key/i)).toBeVisible();
  });

  test('submitting SSH key with non-PEM content shows PEM format error', async ({ page }) => {
    await page.getByRole('button', { name: /add credential/i }).click();
    await page.getByLabel(/name/i).fill('bad-pem-cred');
    await page.getByLabel(/type/i).selectOption('ssh-key');
    await page.getByLabel(/username/i).fill('ops');
    await page.getByLabel(/private key/i).fill('not a pem key');
    await page.getByRole('button', { name: /save/i }).click();

    await expect(page.getByRole('dialog')).toBeVisible();
    await expect(page.getByText(/pem/i)).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Delete credential
// ---------------------------------------------------------------------------

test.describe('Credentials — delete', () => {
  test('can delete a credential that is not assigned to any host', async ({ page }) => {
    // Pre-condition: seed a credential via API before navigating.
    // (Requires the manage-portal testserver to expose a seed endpoint,
    //  or the test to create it via the UI flow first.)
    await page.goto('/ui/#/inventory/credentials');
    const rows = page.locator('tbody tr');
    const initialCount = await rows.count();

    // Create one via UI.
    await page.getByRole('button', { name: /add credential/i }).click();
    await page.getByLabel(/name/i).fill('delete-me');
    await page.getByLabel(/type/i).selectOption('ssh-password');
    await page.getByLabel(/username/i).fill('tmp');
    await page.getByLabel(/password/i).fill('tmp123456');
    await page.getByRole('button', { name: /save/i }).click();
    await expect(page.getByRole('dialog')).not.toBeVisible();

    await expect(rows).toHaveCount(initialCount + 1);

    // Click the delete icon on the new row.
    await page.getByText('delete-me').locator('..').getByRole('button', { name: /delete/i }).click();

    // Confirm dialog appears.
    await page.getByRole('button', { name: /confirm|yes|delete/i }).click();

    await expect(rows).toHaveCount(initialCount);
  });

  test('deleting a credential assigned to a host shows in-use error', async ({ page }) => {
    // This test requires the credential to be assigned to a host first.
    // Full flow: create credential → navigate to Hosts → assign → come back → try delete.
    await page.goto('/ui/#/inventory/credentials');

    await page.getByRole('button', { name: /add credential/i }).click();
    await page.getByLabel(/name/i).fill('in-use-cred');
    await page.getByLabel(/type/i).selectOption('ssh-password');
    await page.getByLabel(/username/i).fill('ops');
    await page.getByLabel(/password/i).fill('pass1234567');
    await page.getByRole('button', { name: /save/i }).click();
    await expect(page.getByRole('dialog')).not.toBeVisible();

    // Assign to a host via Hosts page.
    await page.goto('/ui/#/inventory/hosts');
    await page.getByRole('button', { name: /add host/i }).click();
    await page.getByLabel(/hostname/i).fill('web-01');
    await page.getByLabel(/ip/i).fill('10.0.0.1');
    // Select the credential in the picker.
    await page.getByLabel(/credential/i).selectOption({ label: 'in-use-cred' });
    await page.getByRole('button', { name: /save/i }).click();
    await expect(page.getByRole('dialog')).not.toBeVisible();

    // Try to delete the credential — should be blocked.
    // Credentials.vue:remove() returns early with a toast when inUseCount > 0;
    // it never sets confirmOpen = true, so the confirm dialog does NOT appear.
    await page.goto('/ui/#/inventory/credentials');
    await page.getByText('in-use-cred').locator('..').getByRole('button', { name: /delete/i }).click();

    // Toast error appears immediately; row remains visible.
    await expect(page.getByText(/in use/i)).toBeVisible();
    await expect(page.getByText('in-use-cred')).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Host form — credential picker
// ---------------------------------------------------------------------------

test.describe('Credentials — host form integration', () => {
  test('Hosts form shows Credential dropdown populated from credentials list', async ({ page }) => {
    // Seed a credential first.
    await page.goto('/ui/#/inventory/credentials');
    await page.getByRole('button', { name: /add credential/i }).click();
    await page.getByLabel(/name/i).fill('picker-cred');
    await page.getByLabel(/type/i).selectOption('ssh-password');
    await page.getByLabel(/username/i).fill('u');
    await page.getByLabel(/password/i).fill('pass123456789');
    await page.getByRole('button', { name: /save/i }).click();
    await expect(page.getByRole('dialog')).not.toBeVisible();

    // Open host form and check credential picker.
    await page.goto('/ui/#/inventory/hosts');
    await page.getByRole('button', { name: /add host/i }).click();
    const credPicker = page.getByLabel(/credential/i);
    await expect(credPicker).toBeVisible();
    await expect(credPicker.getByRole('option', { name: 'picker-cred' })).toBeVisible();
  });

  test('selecting WinRM credential pre-fills access port to 5985', async ({ page }) => {
    // Seed a WinRM credential.
    await page.goto('/ui/#/inventory/credentials');
    await page.getByRole('button', { name: /add credential/i }).click();
    await page.getByLabel(/name/i).fill('winrm-cred');
    await page.getByLabel(/type/i).selectOption('winrm-password');
    await page.getByLabel(/username/i).fill('Administrator');
    await page.getByLabel(/password/i).fill('W1nRM_Pass!');
    await page.getByRole('button', { name: /save/i }).click();
    await expect(page.getByRole('dialog')).not.toBeVisible();

    await page.goto('/ui/#/inventory/hosts');
    await page.getByRole('button', { name: /add host/i }).click();
    await page.getByLabel(/credential/i).selectOption({ label: 'winrm-cred' });

    // Access port should auto-fill to 5985.
    const portInput = page.getByLabel(/access port/i);
    await expect(portInput).toHaveValue('5985');
  });

  test('selecting SSH credential resets access port to 22', async ({ page }) => {
    // Seed both credential types.
    await page.goto('/ui/#/inventory/credentials');
    for (const [name, type] of [['ssh-cred', 'ssh-password'], ['winrm-cred2', 'winrm-password']]) {
      await page.getByRole('button', { name: /add credential/i }).click();
      await page.getByLabel(/name/i).fill(name);
      await page.getByLabel(/type/i).selectOption(type);
      await page.getByLabel(/username/i).fill('u');
      await page.getByLabel(/password/i).fill('pass12345678');
      await page.getByRole('button', { name: /save/i }).click();
      await expect(page.getByRole('dialog')).not.toBeVisible();
    }

    await page.goto('/ui/#/inventory/hosts');
    await page.getByRole('button', { name: /add host/i }).click();

    // Pick WinRM → port 5985, then switch to SSH → port should reset to 22.
    await page.getByLabel(/credential/i).selectOption({ label: 'winrm-cred2' });
    await expect(page.getByLabel(/access port/i)).toHaveValue('5985');

    await page.getByLabel(/credential/i).selectOption({ label: 'ssh-cred' });
    await expect(page.getByLabel(/access port/i)).toHaveValue('22');
  });
});
