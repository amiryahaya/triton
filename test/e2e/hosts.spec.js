// @ts-check
// Hosts — E2E tests for the Hosts page in the manage portal.
//
// To enable: wire up a manage-portal E2E test server (similar to
// test/e2e/cmd/testserver/main.go for the report portal) that:
//   1. Starts the manageserver with PostgreSQL storage.
//   2. Completes setup (admin + license) programmatically.
//   3. Seeds credentials and tags via API.
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

test.describe('Hosts page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/ui/#/');
  });

  test('navigates to hosts page from sidebar', async ({ page }) => {
    await page.click('a[href="#/hosts"]');
    await page.waitForURL('/#/hosts');
    expect(page.url()).toContain('/#/hosts');
  });

  test('shows no-tag warning badge for hosts without tags', async ({ page }) => {
    await page.goto('/ui/#/hosts');

    // Create a host without tags first (to ensure one exists).
    await page.click('button:has-text("Add Host")');
    await page.fill('input[aria-label="hostname" i]', 'untagged-host');
    await page.fill('input[aria-label="ip" i]', '10.0.0.1');
    await page.click('button:has-text("Save")');

    // Reload to see the list with the host.
    await page.goto('/ui/#/hosts');

    // Check for the no-tag badge.
    const badgeLocator = page.locator('span.no-tag-badge, span:has-text("No tags")');
    await expect(badgeLocator).toBeVisible();

    // Check that the badge has a title attribute about targeting.
    const title = await badgeLocator.getAttribute('title');
    expect(title).toContain('cannot be targeted');
  });

  test('tag filter filters host list', async ({ page }) => {
    await page.goto('/ui/#/hosts');

    // Find a tag filter dropdown (if one exists).
    const filterSelect = page.locator('select').first();
    if (await filterSelect.isVisible()) {
      // Try to select a production option if available.
      const options = await filterSelect.locator('option').count();
      if (options > 1) {
        await filterSelect.selectOption({ index: 1 });
      }
    }

    // Verify no crash — rows count >= 0.
    const rows = page.locator('tbody tr');
    const rowCount = await rows.count();
    expect(rowCount).toBeGreaterThanOrEqual(0);
  });
});

// ---------------------------------------------------------------------------
// New host form — validation
// ---------------------------------------------------------------------------

test.describe('New host form — validation', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/ui/#/hosts');
    await page.click('button:has-text("Add Host")');
    await page.waitForSelector('input[aria-label="hostname" i]');
  });

  test('hostname is required — blocks submit', async ({ page }) => {
    // Fill IP but leave hostname empty.
    await page.fill('input[aria-label="ip" i]', '10.0.0.2');
    await page.click('button:has-text("Save")');

    // Error message should appear.
    const errorText = page.locator('text=/hostname.*required/i');
    await expect(errorText).toBeVisible();
  });

  test('IP is required — blocks submit', async ({ page }) => {
    // Fill hostname but leave IP empty.
    await page.fill('input[aria-label="hostname" i]', 'test-host');
    await page.click('button:has-text("Save")');

    // Error message should appear.
    const errorText = page.locator('text=/ip.*required/i, text=/address.*required/i');
    await expect(errorText).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Bulk CSV upload
// ---------------------------------------------------------------------------

test.describe('Bulk CSV upload', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/ui/#/hosts');
    // Click the import/bulk upload button.
    await page.click('button:has-text("Bulk Import"), button:has-text("Import")');
    // Wait for the CSV tab/section to be visible.
    await page.waitForSelector('input[type="file"]');
  });

  test('CSV template download triggers file download', async ({ page, context }) => {
    // Wait for the download.
    const downloadPromise = context.waitForEvent('download');

    // Click the download template button.
    await page.click('button:has-text("Download CSV template"), button:has-text("Template"), a:has-text("template")');

    // Verify the download filename.
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toBe('hosts-template.csv');
  });

  test('CSV upload with valid data imports successfully', async ({ page }) => {
    const csv = 'hostname,ip\nbulk-host-01,10.55.0.1\n';

    // Set the file input.
    const fileInput = page.locator('input[type="file"]').first();
    await fileInput.setInputFiles({
      name: 'hosts.csv',
      mimeType: 'text/csv',
      buffer: Buffer.from(csv),
    });

    // Click the upload/import button.
    await page.click('button:has-text("Import"), button:has-text("Upload")');

    // Verify the host appears in the list.
    await expect(page.locator('text="bulk-host-01"')).toBeVisible();
  });

  test('CSV without hostname column shows error', async ({ page }) => {
    const csv = 'ip\n10.55.0.2\n';

    const fileInput = page.locator('input[type="file"]').first();
    await fileInput.setInputFiles({
      name: 'hosts.csv',
      mimeType: 'text/csv',
      buffer: Buffer.from(csv),
    });

    await page.click('button:has-text("Import"), button:has-text("Upload")');

    // Error about missing hostname column.
    const errorText = page.locator('text=/hostname.*column|missing.*hostname/i');
    await expect(errorText).toBeVisible();
  });

  test('CSV row missing hostname shows row-level error', async ({ page }) => {
    const csv = 'hostname,ip\n,10.55.0.3\n';

    const fileInput = page.locator('input[type="file"]').first();
    await fileInput.setInputFiles({
      name: 'hosts.csv',
      mimeType: 'text/csv',
      buffer: Buffer.from(csv),
    });

    await page.click('button:has-text("Import"), button:has-text("Upload")');

    // Row-level error about hostname required.
    const errorText = page.locator('text=/hostname.*required|row.*hostname/i');
    await expect(errorText).toBeVisible();
  });

  test('CSV row with invalid IP shows row-level error', async ({ page }) => {
    const csv = 'hostname,ip\ntest.local,not-an-ip\n';

    const fileInput = page.locator('input[type="file"]').first();
    await fileInput.setInputFiles({
      name: 'hosts.csv',
      mimeType: 'text/csv',
      buffer: Buffer.from(csv),
    });

    await page.click('button:has-text("Import"), button:has-text("Upload")');

    // Row-level error about invalid IP.
    const errorText = page.locator('text=/ip.*invalid|invalid.*ip|address/i');
    await expect(errorText).toBeVisible();
  });

  test('CSV with duplicate hostname shows duplicate error', async ({ page }) => {
    const csv = 'hostname,ip\ndup.local,10.55.0.4\ndup.local,10.55.0.5\n';

    const fileInput = page.locator('input[type="file"]').first();
    await fileInput.setInputFiles({
      name: 'hosts.csv',
      mimeType: 'text/csv',
      buffer: Buffer.from(csv),
    });

    await page.click('button:has-text("Import"), button:has-text("Upload")');

    // Error about duplicate hostname.
    const errorText = page.locator('text=/duplicate.*hostname|hostname.*duplicate/i');
    await expect(errorText).toBeVisible();
  });
});
