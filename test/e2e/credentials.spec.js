// @ts-check
// Credentials — E2E tests for the Credentials page in the manage portal.

const { test, expect } = require('@playwright/test');

// ---------------------------------------------------------------------------
// Helpers — TFormField does not use for= attributes, so getByLabel() doesn't
// work. Use the same pattern as manage-hosts.spec.js.
// ---------------------------------------------------------------------------

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function fieldInput(page, labelText) {
  const exact = new RegExp(`^${escapeRegex(labelText)}\\*?$`);
  return page
    .locator('.t-modal .t-field')
    .filter({ has: page.locator('.t-field-label').filter({ hasText: exact }) })
    .locator('input');
}

function fieldSelect(page, labelText) {
  const exact = new RegExp(`^${escapeRegex(labelText)}\\*?$`);
  return page
    .locator('.t-modal .t-field')
    .filter({ has: page.locator('.t-field-label').filter({ hasText: exact }) })
    .locator('select');
}

function fieldTextarea(page, labelText) {
  const exact = new RegExp(`^${escapeRegex(labelText)}\\*?$`);
  return page
    .locator('.t-modal .t-field')
    .filter({ has: page.locator('.t-field-label').filter({ hasText: exact }) })
    .locator('textarea');
}

// Same helpers scoped to the whole page (for host form that also lives in a modal).
function pageFieldInput(page, labelText) {
  const exact = new RegExp(`^${escapeRegex(labelText)}\\*?$`);
  return page
    .locator('.t-modal .t-field')
    .filter({ has: page.locator('.t-field-label').filter({ hasText: exact }) })
    .locator('input');
}

function pageFieldSelect(page, labelText) {
  const exact = new RegExp(`^${escapeRegex(labelText)}\\*?$`);
  return page
    .locator('.t-modal .t-field')
    .filter({ has: page.locator('.t-field-label').filter({ hasText: exact }) })
    .locator('select');
}

/**
 * Select a <select> option whose label text includes partialText.
 * Playwright selectOption({ label }) only accepts strings, not regexes,
 * so we locate the matching <option> and select by value.
 */
async function selectByPartialLabel(selectLocator, partialText) {
  const option = selectLocator.locator('option').filter({ hasText: partialText }).first();
  const value = await option.getAttribute('value');
  await selectLocator.selectOption(value ?? '');
}

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
    await page.waitForLoadState('networkidle');
  });

  test('renders page heading and Add Credential button', async ({ page }) => {
    await expect(page.getByRole('heading', { name: /credentials/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /add credential/i })).toBeVisible();
  });

  test('empty state shows no rows', async ({ page }) => {
    const rows = page.locator('.t-tbl-row');
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
    await expect(fieldInput(page, 'Name')).toBeVisible();
    await expect(fieldSelect(page, 'Type')).toBeVisible();
  });

  test('SSH Key type shows private key textarea and optional passphrase', async ({ page }) => {
    await page.getByRole('button', { name: /add credential/i }).click();
    await fieldSelect(page, 'Type').selectOption('ssh-key');
    await expect(fieldTextarea(page, 'Private Key (PEM)')).toBeVisible();
    await expect(fieldInput(page, 'Passphrase (optional)')).toBeVisible();
    await expect(fieldInput(page, 'Password')).not.toBeVisible();
  });

  test('SSH Password type shows password field, hides private key', async ({ page }) => {
    await page.getByRole('button', { name: /add credential/i }).click();
    await fieldSelect(page, 'Type').selectOption('ssh-password');
    await expect(fieldInput(page, 'Password')).toBeVisible();
    await expect(fieldTextarea(page, 'Private Key (PEM)')).not.toBeVisible();
  });

  test('WinRM type shows password and Use HTTPS toggle', async ({ page }) => {
    await page.getByRole('button', { name: /add credential/i }).click();
    await fieldSelect(page, 'Type').selectOption('winrm-password');
    await expect(fieldInput(page, 'Password')).toBeVisible();
    // The HTTPS checkbox is inside a <label> that wraps it — getByLabel works here.
    await expect(page.getByLabel(/use https/i)).toBeVisible();
  });

  test('submitting SSH password credential adds row to list', async ({ page }) => {
    await page.getByRole('button', { name: /add credential/i }).click();
    await fieldInput(page, 'Name').fill('test-ssh-pw');
    await fieldSelect(page, 'Type').selectOption('ssh-password');
    await fieldInput(page, 'Username').fill('ubuntu');
    await fieldInput(page, 'Password').fill('hunter2');
    await page.getByRole('button', { name: /save/i }).click();

    // Modal closes on success.
    await expect(page.getByRole('dialog')).not.toBeVisible();

    // New row appears in the table.
    await expect(page.getByText('test-ssh-pw')).toBeVisible();
    await expect(page.getByText('SSH Password')).toBeVisible();
  });

  test('submitting SSH key without private key shows inline error', async ({ page }) => {
    await page.getByRole('button', { name: /add credential/i }).click();
    await fieldInput(page, 'Name').fill('bad-key-cred');
    await fieldSelect(page, 'Type').selectOption('ssh-key');
    await fieldInput(page, 'Username').fill('ops');
    // Leave private_key empty.
    await page.getByRole('button', { name: /save/i }).click();

    // Error message appears, modal stays open.
    await expect(page.getByRole('dialog')).toBeVisible();
    await expect(page.locator('.field-error', { hasText: /private key/i })).toBeVisible();
  });

  test('submitting SSH key with non-PEM content shows PEM format error', async ({ page }) => {
    await page.getByRole('button', { name: /add credential/i }).click();
    await fieldInput(page, 'Name').fill('bad-pem-cred');
    await fieldSelect(page, 'Type').selectOption('ssh-key');
    await fieldInput(page, 'Username').fill('ops');
    await fieldTextarea(page, 'Private Key (PEM)').fill('not a pem key');
    await page.getByRole('button', { name: /save/i }).click();

    await expect(page.getByRole('dialog')).toBeVisible();
    // Use first() because the inline "Must be PEM format" and the submit-path error
    // are both visible at the same time — either one is sufficient proof.
    await expect(page.locator('.field-error', { hasText: /pem/i }).first()).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Delete credential
// ---------------------------------------------------------------------------

test.describe('Credentials — delete', () => {
  test('can delete a credential that is not assigned to any host', async ({ page }) => {
    await page.goto('/ui/#/inventory/credentials');
    // Wait for async fetch to complete before reading the baseline count.
    await page.waitForLoadState('networkidle');
    const rows = page.locator('.t-tbl-row');
    const initialCount = await rows.count();

    // Use a unique name so retries don't collide with a previous attempt.
    const credName = `delete-me-${Date.now()}`;
    // Create one via UI.
    await page.getByRole('button', { name: /add credential/i }).click();
    await fieldInput(page, 'Name').fill(credName);
    await fieldSelect(page, 'Type').selectOption('ssh-password');
    await fieldInput(page, 'Username').fill('tmp');
    await fieldInput(page, 'Password').fill('tmp123456');
    await page.getByRole('button', { name: /save/i }).click();
    await expect(page.getByRole('dialog')).not.toBeVisible();

    await expect(rows).toHaveCount(initialCount + 1);

    // Click the delete icon on the new row.
    await page.getByText(credName).locator('..').getByRole('button', { name: /delete/i }).click();

    // Confirm dialog appears — scope to the t-confirm-ok button inside the dialog.
    await page.locator('.t-confirm-ok').click();

    await expect(rows).toHaveCount(initialCount);
  });

  test('deleting a credential assigned to a host shows in-use error', async ({ page }) => {
    await page.goto('/ui/#/inventory/credentials');
    await page.waitForLoadState('networkidle');

    const credName = `in-use-cred-${Date.now()}`;
    await page.getByRole('button', { name: /add credential/i }).click();
    await fieldInput(page, 'Name').fill(credName);
    await fieldSelect(page, 'Type').selectOption('ssh-password');
    await fieldInput(page, 'Username').fill('ops');
    await fieldInput(page, 'Password').fill('pass1234567');
    await page.getByRole('button', { name: /save/i }).click();
    await expect(page.getByRole('dialog')).not.toBeVisible();

    // Assign to a host via Hosts page.
    await page.goto('/ui/#/inventory/hosts');
    await page.getByRole('button', { name: 'New host' }).click();
    await pageFieldInput(page, 'Hostname').fill(`web-${Date.now()}`);
    await pageFieldInput(page, 'IP address').fill('10.0.0.1');
    // Select the credential in the picker.
    await selectByPartialLabel(pageFieldSelect(page, 'Credential'), credName);
    await page.getByRole('button', { name: /save|create/i }).click();
    await expect(page.getByRole('dialog')).not.toBeVisible();

    // Try to delete the credential — should be blocked.
    await page.goto('/ui/#/inventory/credentials');
    await page.getByText(credName).locator('..').getByRole('button', { name: /delete/i }).click();

    // Toast error appears immediately; row remains visible.
    await expect(page.getByText(/in use/i)).toBeVisible();
    await expect(page.getByText(credName)).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Host form — credential picker
// ---------------------------------------------------------------------------

test.describe('Credentials — host form integration', () => {
  test('Hosts form shows Credential dropdown populated from credentials list', async ({ page }) => {
    // Seed a credential first — unique name avoids retry collisions.
    const credName = `picker-cred-${Date.now()}`;
    await page.goto('/ui/#/inventory/credentials');
    await page.getByRole('button', { name: /add credential/i }).click();
    await fieldInput(page, 'Name').fill(credName);
    await fieldSelect(page, 'Type').selectOption('ssh-password');
    await fieldInput(page, 'Username').fill('u');
    await fieldInput(page, 'Password').fill('pass123456789');
    await page.getByRole('button', { name: /save/i }).click();
    await expect(page.getByRole('dialog')).not.toBeVisible();

    // Open host form and check credential picker.
    await page.goto('/ui/#/inventory/hosts');
    await page.getByRole('button', { name: 'New host' }).click();
    const credPicker = pageFieldSelect(page, 'Credential');
    await expect(credPicker).toBeVisible();
    // <option> elements are always "hidden" until the dropdown opens; use toBeAttached().
    await expect(credPicker.locator('option').filter({ hasText: credName })).toBeAttached();
  });

  test('selecting WinRM credential pre-fills access port to 5985', async ({ page }) => {
    // Seed a WinRM credential.
    await page.goto('/ui/#/inventory/credentials');
    await page.getByRole('button', { name: /add credential/i }).click();
    await fieldInput(page, 'Name').fill('winrm-cred');
    await fieldSelect(page, 'Type').selectOption('winrm-password');
    await fieldInput(page, 'Username').fill('Administrator');
    await fieldInput(page, 'Password').fill('W1nRM_Pass!');
    await page.getByRole('button', { name: /save/i }).click();
    await expect(page.getByRole('dialog')).not.toBeVisible();

    await page.goto('/ui/#/inventory/hosts');
    await page.getByRole('button', { name: 'New host' }).click();
    await selectByPartialLabel(pageFieldSelect(page, 'Credential'), 'winrm-cred');

    // SSH Port should auto-fill to 5985.
    const portInput = pageFieldInput(page, 'SSH Port');
    await expect(portInput).toHaveValue('5985');
  });

  test('selecting SSH credential resets access port to 22', async ({ page }) => {
    // Seed both credential types.
    await page.goto('/ui/#/inventory/credentials');
    for (const [name, type] of [['ssh-cred', 'ssh-password'], ['winrm-cred2', 'winrm-password']]) {
      await page.getByRole('button', { name: /add credential/i }).click();
      await fieldInput(page, 'Name').fill(name);
      await fieldSelect(page, 'Type').selectOption(type);
      await fieldInput(page, 'Username').fill('u');
      await fieldInput(page, 'Password').fill('pass12345678');
      await page.getByRole('button', { name: /save/i }).click();
      await expect(page.getByRole('dialog')).not.toBeVisible();
    }

    await page.goto('/ui/#/inventory/hosts');
    await page.getByRole('button', { name: 'New host' }).click();

    // Pick WinRM → port 5985, then switch to SSH → port should reset to 22.
    await selectByPartialLabel(pageFieldSelect(page, 'Credential'), 'winrm-cred2');
    await expect(pageFieldInput(page, 'SSH Port')).toHaveValue('5985');

    await selectByPartialLabel(pageFieldSelect(page, 'Credential'), 'ssh-cred');
    await expect(pageFieldInput(page, 'SSH Port')).toHaveValue('22');
  });
});
