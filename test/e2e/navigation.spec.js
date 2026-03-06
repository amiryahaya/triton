// @ts-check
const { test, expect } = require('@playwright/test');

test.describe('Navigation', () => {
  test('sidebar has 5 nav links', async ({ page }) => {
    await page.goto('/ui/index.html');
    const navLinks = page.locator('.sidebar nav a');
    await expect(navLinks).toHaveCount(5);

    const views = ['overview', 'machines', 'scans', 'diff', 'trend'];
    for (const view of views) {
      await expect(page.locator(`[data-view="${view}"]`)).toBeVisible();
    }
  });

  test('clicking nav links updates hash and active class', async ({ page }) => {
    await page.goto('/ui/index.html#/');
    await page.waitForSelector('.card-grid', { timeout: 10_000 });

    // Click Scans
    await page.click('[data-view="scans"]');
    await expect(page).toHaveURL(/.*#\/scans$/);
    await expect(page.locator('[data-view="scans"]')).toHaveClass(/active/);
    await expect(page.locator('[data-view="overview"]')).not.toHaveClass(/active/);

    // Click Machines
    await page.click('[data-view="machines"]');
    await expect(page).toHaveURL(/.*#\/machines$/);
    await expect(page.locator('[data-view="machines"]')).toHaveClass(/active/);
  });

  test('direct hash navigation works', async ({ page }) => {
    await page.goto('/ui/index.html#/scans');
    // Wait for the scans view to render
    await page.waitForSelector('h2', { timeout: 10_000 });
    await expect(page.locator('h2')).toContainText('All Scans');
  });

  test('unknown hash shows error', async ({ page }) => {
    await page.goto('/ui/index.html#/nonexistent');
    await expect(page.locator('.error')).toContainText('Page not found');
  });

  test('root redirects to UI', async ({ page }) => {
    // Server returns 302 redirect to /ui/index.html; goto follows automatically
    await page.goto('/');
    await expect(page).toHaveURL(/\/ui\//);
    // Verify the dashboard actually loads
    await page.waitForSelector('.card-grid', { timeout: 10_000 });
    await expect(page.locator('.card-grid')).toBeVisible();
  });
});
