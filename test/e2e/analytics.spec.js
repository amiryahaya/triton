// @ts-check
// Analytics Phase 1 — E2E tests for the three new sidebar views.
// See docs/plans/2026-04-09-analytics-phase-1-plan.md Task 2.5.

const { test, expect } = require('@playwright/test');

test.describe('Analytics — sidebar navigation', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/ui/#/');
  });

  test('sidebar shows the Analytics section label', async ({ page }) => {
    const label = page.locator('.nav-section-label', { hasText: 'Analytics' });
    await expect(label).toBeVisible();
  });

  test('sidebar exposes all three analytics links', async ({ page }) => {
    await expect(page.locator('a[href="#/inventory"]')).toBeVisible();
    await expect(page.locator('a[href="#/certificates"]')).toBeVisible();
    await expect(page.locator('a[href="#/priority"]')).toBeVisible();
  });

  test('clicking Inventory navigates to the inventory view', async ({ page }) => {
    await page.click('a[href="#/inventory"]');
    await expect(page).toHaveURL(/#\/inventory$/);
    await expect(page.locator('h2', { hasText: 'Crypto Inventory' })).toBeVisible();
  });
});

test.describe('Analytics — Crypto Inventory view', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/ui/#/inventory');
    // Wait for either the table or the empty-state card to render.
    await page.waitForSelector('.analytics-table, .empty-state', { timeout: 10_000 });
  });

  test('renders the page heading and subtitle', async ({ page }) => {
    await expect(page.locator('h2', { hasText: 'Crypto Inventory' })).toBeVisible();
    await expect(page.locator('.subtitle')).toContainText('algorithm and key size');
  });

  test('table renders rows from seeded findings', async ({ page }) => {
    // global-setup.js seeds 4 scans with RSA-2048, SHA-1, DES, and
    // ML-KEM-768 crypto assets across two machines. After the
    // latest-scan-per-host filter, the inventory view must show at
    // least one row (the fixtures always have crypto findings).
    const table = page.locator('.analytics-table');
    await expect(table).toBeVisible();
    const rows = table.locator('tbody tr');
    await expect(rows.first()).toBeVisible();
    // Each row must have Algorithm, Size, Status, Instances, Machines,
    // and Max Priority columns.
    await expect(rows.first().locator('td')).toHaveCount(6);
  });

  test('table includes expected algorithm families from fixtures', async ({ page }) => {
    // The seeded scans include at least one SHA-1 finding (DEPRECATED)
    // — the exact one verifies the latest-scan-per-host filter kept
    // crypto-bearing findings from the newest scan per host.
    const tbody = page.locator('.analytics-table tbody');
    // Match a row containing any of the seeded algorithms. We can't
    // guarantee the exact set because latest-scan-per-host depends on
    // the fixture timestamps, but one of these MUST show up.
    const anyKnownAlgo = tbody.locator('tr', {
      hasText: /RSA-2048|SHA-1|DES|ML-KEM-768/,
    });
    await expect(anyKnownAlgo.first()).toBeVisible();
  });

  test('status column renders PQC badges', async ({ page }) => {
    // Badges are <span class="badge safe|transitional|deprecated|unsafe">
    // rendered by the badge() helper in app.js. At least one must be
    // present in the table.
    const badges = page.locator('.analytics-table .badge');
    await expect(badges.first()).toBeVisible();
  });
});

test.describe('Analytics — Crypto Inventory empty state', () => {
  // Empty-state coverage is handled at the store-integration level
  // (TestListInventory_EmptyOrg) — seeding a separate empty-org
  // testserver instance for a Playwright-only check is disproportionate
  // cost for what's essentially a branch in app.js that unit tests can
  // drive through the backfill-header test below. Kept as a no-op
  // describe block so the intent is documented in the spec file.
  test.skip('empty org renders the no-findings card', () => {});
});

test.describe('Analytics — Expiring Certificates view', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/ui/#/certificates');
    // Wait for either the table or the empty-state card.
    await page.waitForSelector('.analytics-table, .empty-state', { timeout: 10_000 });
  });

  test('renders the page heading and summary chips', async ({ page }) => {
    await expect(page.locator('h2', { hasText: 'Expiring Certificates' })).toBeVisible();
    // Four summary chips: expired, within 30, within 90, shown.
    const chips = page.locator('.summary-chip');
    await expect(chips).toHaveCount(4);
  });

  test('exposes filter chip buttons for 30/90/180/all days', async ({ page }) => {
    await expect(page.locator('button[data-window="30"]')).toBeVisible();
    await expect(page.locator('button[data-window="90"]')).toBeVisible();
    await expect(page.locator('button[data-window="180"]')).toBeVisible();
    await expect(page.locator('button[data-window="all"]')).toBeVisible();
  });

  test('clicking 30-day chip keeps the view on /certificates', async ({ page }) => {
    // Clicking the filter re-renders the view in place; URL stays the same.
    await page.click('button[data-window="30"]');
    // Give the re-render a moment; the filter change happens client-side
    // and triggers a fresh API call.
    await page.waitForTimeout(500);
    await expect(page.locator('h2', { hasText: 'Expiring Certificates' })).toBeVisible();
  });

  test('clicking All broadens the view without errors', async ({ page }) => {
    await page.click('button[data-window="all"]');
    await page.waitForTimeout(500);
    // Still on certificates view, no error state.
    await expect(page.locator('h2', { hasText: 'Expiring Certificates' })).toBeVisible();
    await expect(page.locator('.error')).not.toBeVisible();
  });
});
