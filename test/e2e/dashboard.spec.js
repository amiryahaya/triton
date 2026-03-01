// @ts-check
const { test, expect } = require('@playwright/test');

test.describe('Dashboard Overview', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/ui/index.html#/');
    // Wait for overview to load (loading indicator disappears)
    await page.waitForSelector('.card-grid', { timeout: 10_000 });
  });

  test('shows stat cards', async ({ page }) => {
    // Overview has 6 cards: Machines, Total Findings, Safe, Transitional, Deprecated, Unsafe
    const cards = page.locator('.card-grid .card');
    await expect(cards).toHaveCount(6);

    // Verify card types exist
    await expect(page.locator('.card.info')).toHaveCount(2); // Machines + Total Findings
    await expect(page.locator('.card.safe')).toHaveCount(1);
    await expect(page.locator('.card.transitional')).toHaveCount(1);
    await expect(page.locator('.card.deprecated')).toHaveCount(1);
    await expect(page.locator('.card.unsafe')).toHaveCount(1);
  });

  test('machines table contains seeded hostnames', async ({ page }) => {
    // Overview renders a machines table below the cards
    const table = page.locator('table');
    await expect(table).toBeVisible();
    await expect(table.locator('text=web-server-01')).toBeVisible();
    await expect(table.locator('text=db-server-01')).toBeVisible();
  });

  test('charts render', async ({ page }) => {
    // Donut and bar charts render as canvas elements
    await expect(page.locator('#donutChart')).toBeVisible();
    await expect(page.locator('#barChart')).toBeVisible();
  });

  test('aggregate machine count is 2', async ({ page }) => {
    // The first info card shows machine count
    const machineCard = page.locator('.card.info').first();
    const value = machineCard.locator('.value');
    await expect(value).toHaveText('2');
  });
});
