// @ts-check
// manage-hosts.spec.js — E2E tests for the Hosts page of the Manage Portal.
//
// Covers three flows:
//   1. Create a new host via the manual form (New host button)
//   2. Bulk import via CSV paste
//   3. Import from a pre-seeded discovery scan

const { test, expect } = require('@playwright/test');

const HOSTS_URL = '/ui/#/inventory/hosts';
const DISCOVER_URL = '/ui/#/inventory/discover';

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/** Navigate to the Hosts page and wait for the page heading. */
async function gotoHosts(page) {
  await page.goto(HOSTS_URL);
  await expect(page.locator('h1', { hasText: 'Hosts' })).toBeVisible({ timeout: 8_000 });
}

/** Navigate to the Discovery page and wait for the page heading. */
async function gotoDiscover(page) {
  await page.goto(DISCOVER_URL);
  await expect(page.locator('h1', { hasText: 'Network Discovery' })).toBeVisible({ timeout: 8_000 });
}

/**
 * Find the input inside a TFormField by matching the label text, scoped
 * to the open modal so table cells with the same text don't collide.
 * TFormField renders: <div class="t-field"><label class="t-field-label">…</label><input></div>
 */
function fieldInput(page, labelText) {
  // Use a word-boundary regex so "OS" doesn't match "Hostname" (contains "os").
  const exact = new RegExp(`^${labelText}\\*?$`);
  return page
    .locator('.t-modal .t-field')
    .filter({ has: page.locator('.t-field-label').filter({ hasText: exact }) })
    .locator('input');
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Manual host creation
// ─────────────────────────────────────────────────────────────────────────────

test.describe('Hosts — manual form', () => {
  test('New host button opens modal and creates a host', async ({ page }) => {
    await gotoHosts(page);

    // Open the modal.
    await page.getByRole('button', { name: 'New host' }).click();
    await expect(page.locator('.t-modal')).toBeVisible();
    await expect(page.locator('.t-modal-title', { hasText: 'New host' })).toBeVisible();

    // Fill in the form fields.
    await fieldInput(page, 'Hostname').fill('form-host-01');
    await fieldInput(page, 'IP address').fill('10.42.0.1');
    await fieldInput(page, 'OS').fill('linux');

    // Submit.
    await page.locator('.t-modal').getByRole('button', { name: 'Create' }).click();

    // Modal closes and success toast appears.
    await expect(page.locator('.t-modal')).not.toBeVisible({ timeout: 5_000 });
    await expect(page.locator('text=Host created')).toBeVisible({ timeout: 5_000 });

    // The new host appears in the table (TDataTable renders cells as .t-tbl-c spans).
    await expect(page.locator('.t-tbl-c', { hasText: 'form-host-01' })).toBeVisible({ timeout: 5_000 });
    await expect(page.locator('.t-tbl-c', { hasText: '10.42.0.1' })).toBeVisible();
  });

  test('IP field is required — form shows error without closing modal', async ({ page }) => {
    await gotoHosts(page);
    await page.getByRole('button', { name: 'New host' }).click();
    await expect(page.locator('.t-modal')).toBeVisible();

    // Click Create without filling in any IP.
    await page.locator('.t-modal').getByRole('button', { name: 'Create' }).click();

    // Modal stays open; inline error text is shown inside the form field.
    await expect(page.locator('.t-modal')).toBeVisible();
    await expect(page.locator('.t-field-error', { hasText: 'required' })).toBeVisible({ timeout: 3_000 });
  });

  test('Cancel closes modal without creating a host', async ({ page }) => {
    await gotoHosts(page);

    const hostsBefore = page.locator('table tbody tr');
    const countBefore = await hostsBefore.count();

    await page.getByRole('button', { name: 'New host' }).click();
    await expect(page.locator('.t-modal')).toBeVisible();

    // Fill a value but then cancel.
    await fieldInput(page, 'IP address').fill('10.42.0.99');
    await page.locator('.t-modal').getByRole('button', { name: 'Cancel' }).click();

    await expect(page.locator('.t-modal')).not.toBeVisible({ timeout: 3_000 });

    // Row count is unchanged.
    await expect(hostsBefore).toHaveCount(countBefore, { timeout: 3_000 });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. CSV bulk import
// ─────────────────────────────────────────────────────────────────────────────

test.describe('Hosts — CSV bulk import', () => {
  test('Bulk import modal opens on CSV tab by default', async ({ page }) => {
    await gotoHosts(page);
    await page.getByRole('button', { name: 'Bulk import' }).click();

    await expect(page.locator('.t-modal-title', { hasText: 'Bulk import hosts' })).toBeVisible();
    await expect(page.locator('button.bulk-tab.active', { hasText: 'CSV' })).toBeVisible();
  });

  test('valid CSV shows preview and imports hosts', async ({ page }) => {
    await gotoHosts(page);
    await page.getByRole('button', { name: 'Bulk import' }).click();
    await expect(page.locator('.t-modal-title', { hasText: 'Bulk import hosts' })).toBeVisible();

    // Paste CSV into the textarea.
    const csv = 'ip,hostname,os\n10.42.1.10,csv-host-01,linux\n10.42.1.11,csv-host-02,windows';
    await page.locator('.bulk-text').fill(csv);

    // Preview renders with 2 valid rows.
    await expect(page.locator('text=csv-host-01')).toBeVisible({ timeout: 3_000 });
    await expect(page.locator('.preview-summary', { hasText: '2 valid' })).toBeVisible();

    // Import button shows the count.
    const importBtn = page.locator('.t-modal').getByRole('button', { name: /Import 2/ });
    await expect(importBtn).toBeVisible();
    await importBtn.click();

    // Modal closes; success toast fires.
    await expect(page.locator('.t-modal')).not.toBeVisible({ timeout: 8_000 });
    await expect(page.locator('text=Bulk import complete')).toBeVisible({ timeout: 8_000 });

    // Both new hosts appear in the table.
    await expect(page.locator('text=csv-host-01')).toBeVisible({ timeout: 5_000 });
    await expect(page.locator('text=csv-host-02')).toBeVisible();
  });

  test('CSV without ip column shows parse error', async ({ page }) => {
    await gotoHosts(page);
    await page.getByRole('button', { name: 'Bulk import' }).click();
    await expect(page.locator('.t-modal-title', { hasText: 'Bulk import hosts' })).toBeVisible();

    await page.locator('.bulk-text').fill('hostname,os\nweb-01,linux');
    await expect(page.locator('text=must have an "ip" column')).toBeVisible({ timeout: 3_000 });
  });

  test('JSON tab accepts a valid array and imports hosts', async ({ page }) => {
    await gotoHosts(page);
    await page.getByRole('button', { name: 'Bulk import' }).click();
    await expect(page.locator('.t-modal-title', { hasText: 'Bulk import hosts' })).toBeVisible();

    // Switch to the JSON tab.
    await page.locator('button.bulk-tab', { hasText: 'JSON' }).click();
    await expect(page.locator('button.bulk-tab.active', { hasText: 'JSON' })).toBeVisible();

    const json = JSON.stringify([{ ip: '10.42.2.10', hostname: 'json-host-01', os: 'linux' }]);
    await page.locator('.bulk-text').fill(json);

    // Import.
    await page.locator('.t-modal').getByRole('button', { name: /Import/ }).click();

    await expect(page.locator('.t-modal')).not.toBeVisible({ timeout: 8_000 });
    await expect(page.locator('text=Bulk import complete')).toBeVisible({ timeout: 8_000 });
    await expect(page.locator('text=json-host-01')).toBeVisible({ timeout: 5_000 });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. Discovery scan import
// ─────────────────────────────────────────────────────────────────────────────

test.describe('Hosts — discovery scan import', () => {
  test('Discovery button navigates to the Discovery page', async ({ page }) => {
    await gotoHosts(page);
    await page.getByRole('button', { name: 'Discovery' }).click();
    await expect(page).toHaveURL(/inventory\/discover/);
    await expect(page.locator('h1', { hasText: 'Network Discovery' })).toBeVisible({ timeout: 5_000 });
  });

  test('pre-seeded completed scan shows results table with 2 candidates', async ({ page }) => {
    await gotoDiscover(page);

    // The test server seeds a completed job — load() picks it up on mount.
    const table = page.locator('table.results-table');
    await expect(table).toBeVisible({ timeout: 10_000 });

    const rows = table.locator('tbody tr');
    await expect(rows).toHaveCount(2);

    await expect(rows.nth(0).locator('td.col-ip')).toHaveText('10.99.0.1');
    await expect(rows.nth(1).locator('td.col-ip')).toHaveText('10.99.0.2');
  });

  test('both candidates show "New" badge (not in inventory yet)', async ({ page }) => {
    await gotoDiscover(page);
    await expect(page.locator('table.results-table')).toBeVisible({ timeout: 10_000 });

    await expect(page.locator('.badge.badge-blue', { hasText: 'New' })).toHaveCount(2);
  });

  test('selecting candidate with hostname and importing redirects to Hosts', async ({ page }) => {
    await gotoDiscover(page);
    const table = page.locator('table.results-table');
    await expect(table).toBeVisible({ timeout: 10_000 });

    // Select the first candidate (has hostname e2e-host-01).
    const firstRow = table.locator('tbody tr').nth(0);
    await firstRow.locator('input[type="checkbox"]').check();

    // Import button should be enabled.
    const importBtn = page.locator('button', { hasText: 'Import Selected' });
    await expect(importBtn).toBeEnabled({ timeout: 3_000 });
    await importBtn.click();

    // After import, navigates to Hosts.
    await expect(page).toHaveURL(/inventory\/hosts/, { timeout: 10_000 });
    await expect(page.locator('h1', { hasText: 'Hosts' })).toBeVisible({ timeout: 5_000 });
    await expect(page.locator('text=e2e-host-01')).toBeVisible({ timeout: 5_000 });
  });

  test('candidate without hostname requires inline edit before import', async ({ page }) => {
    await gotoDiscover(page);
    const table = page.locator('table.results-table');
    await expect(table).toBeVisible({ timeout: 10_000 });

    // Second row (10.99.0.2) has no DNS hostname.
    const secondRow = table.locator('tbody tr').nth(1);
    const hostnameInput = secondRow.locator('td.col-hostname input[type="text"]');
    await expect(hostnameInput).toBeVisible();

    // Clear and type a hostname.
    await hostnameInput.fill('typed-hostname-02');

    // Select and import.
    await secondRow.locator('input[type="checkbox"]').check();
    const importBtn = page.locator('button', { hasText: 'Import Selected' });
    await expect(importBtn).toBeEnabled({ timeout: 3_000 });
    await importBtn.click();

    // Redirects to Hosts and shows the imported hostname.
    await expect(page).toHaveURL(/inventory\/hosts/, { timeout: 10_000 });
    await expect(page.locator('text=typed-hostname-02')).toBeVisible({ timeout: 5_000 });
  });
});
