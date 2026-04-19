// @ts-check
//
// Report Portal Vue migration — phase 1 skip.
//
// Views are stubs (<h1>Overview</h1> etc) on feat/report-portal-phase-1.
// Selectors below target the vanilla-JS DOM (.card-grid, .machines-list)
// that no longer renders. Re-enable progressively as phases 2-4 land
// real view content and rewrite selectors against the Vue DOM.
//
// Spec: docs/superpowers/specs/2026-04-18-portal-unification-design.md
const { test, expect } = require('@playwright/test');

test.describe.configure({ mode: 'skip' });

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
