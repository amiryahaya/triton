// @ts-check
//
// Report Portal Vue migration — phase 1 skip. ScanDiff.vue and
// MigrationTrend.vue are stubs; content lands in phase 3.
const { test, expect } = require('@playwright/test');
const SCAN_IDS = require('./scan-ids');

test.describe.configure({ mode: 'skip' });

test.describe('Diff', () => {
  test('diff form renders', async ({ page }) => {
    await page.goto('/ui/index.html#/diff');
    await page.waitForSelector('#diffBase', { timeout: 10_000 });

    await expect(page.locator('#diffBase')).toBeVisible();
    await expect(page.locator('#diffCompare')).toBeVisible();
    // Compare button
    await expect(page.locator('button:has-text("Compare")')).toBeVisible();
  });

  test('comparing two scans shows diff result', async ({ page }) => {
    await page.goto('/ui/index.html#/diff');
    await page.waitForSelector('#diffBase', { timeout: 10_000 });

    await page.fill('#diffBase', SCAN_IDS.SCAN_001);
    await page.fill('#diffCompare', SCAN_IDS.SCAN_002);
    await page.click('button:has-text("Compare")');

    // Wait for diff result to load
    await page.waitForSelector('#diffResult .card-grid', { timeout: 10_000 });

    // Should show Added/Removed/Changed cards with numeric values
    const resultCards = page.locator('#diffResult .card');
    await expect(resultCards).toHaveCount(3);
    for (let i = 0; i < 3; i++) {
      const value = await resultCards.nth(i).locator('.value').textContent();
      expect(parseInt(value)).toBeGreaterThanOrEqual(0);
    }
  });

  test('empty scan IDs shows error', async ({ page }) => {
    await page.goto('/ui/index.html#/diff');
    await page.waitForSelector('#diffBase', { timeout: 10_000 });

    // Leave inputs empty and click compare
    await page.click('button:has-text("Compare")');

    await expect(page.locator('#diffResult .error')).toContainText('Enter both scan IDs');
  });

  test('invalid scan IDs shows API error', async ({ page }) => {
    await page.goto('/ui/index.html#/diff');
    await page.waitForSelector('#diffBase', { timeout: 10_000 });

    await page.fill('#diffBase', 'invalid-id-1');
    await page.fill('#diffCompare', 'invalid-id-2');
    await page.click('button:has-text("Compare")');

    await page.waitForSelector('#diffResult .error', { timeout: 10_000 });
    await expect(page.locator('#diffResult .error')).toContainText('Diff failed');
  });
});

test.describe('Trend', () => {
  test('trend form renders', async ({ page }) => {
    await page.goto('/ui/index.html#/trend');
    await page.waitForSelector('#trendHost', { timeout: 10_000 });

    await expect(page.locator('#trendHost')).toBeVisible();
    await expect(page.locator('#trendLast')).toBeVisible();
    await expect(page.locator('button:has-text("Show Trend")')).toBeVisible();
  });

  test('trend for hostname shows chart', async ({ page }) => {
    await page.goto('/ui/index.html#/trend');
    await page.waitForSelector('#trendHost', { timeout: 10_000 });

    await page.fill('#trendHost', 'web-server-01');
    await page.click('button:has-text("Show Trend")');

    // Wait for trend chart to render (points array is non-empty)
    await page.waitForSelector('#trendLineChart', { timeout: 10_000 });
    await expect(page.locator('#trendLineChart')).toBeVisible();
  });

  test('trend chart renders as canvas', async ({ page }) => {
    await page.goto('/ui/index.html#/trend');
    await page.waitForSelector('#trendHost', { timeout: 10_000 });

    await page.fill('#trendHost', 'db-server-01');
    await page.click('button:has-text("Show Trend")');

    await page.waitForSelector('#trendLineChart', { timeout: 10_000 });
    // Verify the canvas element is present, visible, and is a <canvas>
    const canvas = page.locator('#trendLineChart');
    await expect(canvas).toBeVisible();
    // Chart.js overrides the HTML width; just verify the element is a canvas
    const tagName = await canvas.evaluate((el) => el.tagName);
    expect(tagName).toBe('CANVAS');
  });

  test('all-hosts trend works without hostname', async ({ page }) => {
    await page.goto('/ui/index.html#/trend');
    await page.waitForSelector('#trendHost', { timeout: 10_000 });

    // Leave hostname empty to get all-hosts trend
    await page.fill('#trendHost', '');
    await page.click('button:has-text("Show Trend")');

    // Should still render chart with all scans across hosts
    await page.waitForSelector('#trendLineChart', { timeout: 10_000 });
    await expect(page.locator('#trendLineChart')).toBeVisible();
  });
});
