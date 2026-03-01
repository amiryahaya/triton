// @ts-check
const { test, expect } = require('@playwright/test');

test.describe('Scans', () => {
  test('scans list shows 4 seeded scans', async ({ page }) => {
    await page.goto('/ui/index.html#/scans');
    await page.waitForSelector('table', { timeout: 10_000 });
    // 4 data rows + 1 header row
    const rows = page.locator('table tr');
    await expect(rows).toHaveCount(5);
  });

  test('clicking scan row navigates to detail', async ({ page }) => {
    await page.goto('/ui/index.html#/scans');
    await page.waitForSelector('table', { timeout: 10_000 });

    // Click the first data row
    await page.locator('table tr').nth(1).click();
    await expect(page).toHaveURL(/.*#\/scans\/.+/);
  });

  test('scan detail shows metadata cards and findings', async ({ page }) => {
    await page.goto('/ui/index.html#/scans/scan-e2e-001');
    await page.waitForSelector('.card-grid', { timeout: 10_000 });

    // Detail view has 7 cards: hostname, profile, total, safe, trans, depr, unsafe
    const cards = page.locator('.card-grid .card');
    await expect(cards).toHaveCount(7);

    // Findings table with badge elements
    await expect(page.locator('table')).toBeVisible();
    const badges = page.locator('.badge');
    // Each finding has a badge, total = 10+5+3+2 = 20
    await expect(badges).toHaveCount(20);
  });

  test('back button returns to scans list', async ({ page }) => {
    await page.goto('/ui/index.html#/scans/scan-e2e-001');
    await page.waitForSelector('.btn-outline', { timeout: 10_000 });

    await page.click('.btn-outline');
    await expect(page).toHaveURL(/.*#\/scans$/);
  });

  test('nonexistent scan shows error', async ({ page }) => {
    await page.goto('/ui/index.html#/scans/nonexistent-id');
    await page.waitForSelector('.error', { timeout: 10_000 });
    await expect(page.locator('.error')).toContainText('Failed to load');
  });
});

test.describe('Machines', () => {
  test('machines list shows 2 unique hostnames', async ({ page }) => {
    await page.goto('/ui/index.html#/machines');
    await page.waitForSelector('table', { timeout: 10_000 });

    const table = page.locator('table');
    await expect(table.locator('text=web-server-01')).toBeVisible();
    await expect(table.locator('text=db-server-01')).toBeVisible();

    // 2 data rows + 1 header row
    const rows = table.locator('tr');
    await expect(rows).toHaveCount(3);
  });

  test('machine detail shows scan history', async ({ page }) => {
    await page.goto('/ui/index.html#/machines/web-server-01');
    await page.waitForSelector('table', { timeout: 10_000 });

    // web-server-01 has 2 scans
    const heading = page.locator('h2');
    await expect(heading).toContainText('web-server-01');
    // 2 data rows + 1 header row
    const rows = page.locator('table tr');
    await expect(rows).toHaveCount(3);
  });

  test('machine detail renders trend chart when 2+ scans', async ({ page }) => {
    await page.goto('/ui/index.html#/machines/web-server-01');
    await page.waitForSelector('#trendChart', { timeout: 10_000 });
    await expect(page.locator('#trendChart')).toBeVisible();
  });
});
