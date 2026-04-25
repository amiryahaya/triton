// @ts-check
// Network Discovery — E2E tests for the Discovery view.
//
// Requires a running manage-portal at the playwright baseURL with discovery
// endpoints available. Tests are currently skipped; remove the skip when
// an E2E discovery stub server is wired up.

const { test, expect } = require('@playwright/test');

test.describe.configure({ mode: 'skip' });

test.describe('Discovery — navigation', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/ui/#/');
  });

  test('sidebar shows Discover link under Inventory', async ({ page }) => {
    await expect(page.locator('a[href="#/inventory/discover"]')).toBeVisible();
  });
});

test.describe('Discovery — scan form', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/ui/#/inventory/discover');
  });

  test('shows scan form with CIDR input and Start Scan button', async ({ page }) => {
    await expect(page.locator('input[placeholder="192.168.1.0/24"]')).toBeVisible();
    await expect(page.locator('button', { hasText: 'Start Scan' })).toBeVisible();
  });

  test('Start Scan button replaces with Stop Scan when running', async ({ page }) => {
    // Would require a mock server endpoint; skipped until stub wired
  });

  test('results table renders with New and Exists badges', async ({ page }) => {
    // Requires stubbed discovery response
  });

  test('inline hostname edit on null-hostname row unblocks Import', async ({ page }) => {
    // Requires stubbed discovery response
  });

  test('import flow redirects to hosts page', async ({ page }) => {
    // Requires stubbed import endpoint
  });

  test('stop mid-scan flips status to Cancelled', async ({ page }) => {
    // Requires stubbed cancel endpoint
  });
});
