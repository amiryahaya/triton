// @ts-check
const { test, expect } = require('@playwright/test');

const ADMIN_KEY = 'e2e-test-key';

// Helper: inject admin key into localStorage before each test.
test.beforeEach(async ({ page }) => {
  await page.goto('/ui/index.html');
  await page.evaluate((key) => {
    localStorage.setItem('triton_admin_key', key);
  }, ADMIN_KEY);
});

test.describe('Admin Authentication', () => {
  test('shows auth prompt without admin key', async ({ page }) => {
    // Clear the key we just set
    await page.evaluate(() => localStorage.removeItem('triton_admin_key'));
    await page.goto('/ui/index.html#/');
    await expect(page.locator('#auth-prompt')).toBeVisible();
    await expect(page.locator('#key-input')).toBeVisible();
    await expect(page.locator('#key-submit')).toBeVisible();
  });

  test('login with valid admin key shows dashboard', async ({ page }) => {
    await page.evaluate(() => localStorage.removeItem('triton_admin_key'));
    await page.goto('/ui/index.html#/');
    await page.fill('#key-input', ADMIN_KEY);
    await page.click('#key-submit');
    await expect(page.locator('.stat-cards')).toBeVisible({ timeout: 10_000 });
    await expect(page.locator('h2')).toHaveText('Dashboard');
  });
});

test.describe('Dashboard', () => {
  test('shows stat cards with seeded data', async ({ page }) => {
    await page.goto('/ui/index.html#/');
    await page.waitForSelector('.stat-cards', { timeout: 10_000 });
    const cards = page.locator('.stat-card');
    await expect(cards).toHaveCount(6);

    // Verify labels
    const labels = page.locator('.stat-card .label');
    await expect(labels.nth(0)).toHaveText('Organizations');
    await expect(labels.nth(1)).toHaveText('Total Licenses');
    await expect(labels.nth(2)).toHaveText('Active Licenses');
    await expect(labels.nth(3)).toHaveText('Active Seats');
  });

  test('organizations count is at least 2', async ({ page }) => {
    await page.goto('/ui/index.html#/');
    await page.waitForSelector('.stat-cards', { timeout: 10_000 });
    const value = page.locator('.stat-card').first().locator('.value');
    const count = parseInt(await value.textContent());
    expect(count).toBeGreaterThanOrEqual(2);
  });
});

test.describe('Organizations', () => {
  test('lists seeded organizations', async ({ page }) => {
    await page.goto('/ui/index.html#/orgs');
    await page.waitForSelector('table', { timeout: 10_000 });
    await expect(page.locator('text=Acme Corp')).toBeVisible();
    await expect(page.locator('text=Globex Inc')).toBeVisible();
  });

  test('create organization modal', async ({ page }) => {
    await page.goto('/ui/index.html#/orgs');
    await page.waitForSelector('#create-org-btn', { timeout: 10_000 });
    await page.click('#create-org-btn');
    await expect(page.locator('.modal')).toBeVisible();
    await expect(page.locator('.modal h3')).toHaveText('Create Organization');

    // Fill and submit
    await page.fill('#org-name', 'E2E-NewOrg');
    await page.fill('#org-contact', 'test@e2e.com');
    await page.click('#modal-create');

    // Modal should close and new org should appear
    await expect(page.locator('.modal')).not.toBeVisible({ timeout: 5_000 });
    await expect(page.locator('text=E2E-NewOrg')).toBeVisible();
  });
});

test.describe('Licenses', () => {
  test('lists seeded licenses', async ({ page }) => {
    await page.goto('/ui/index.html#/licenses');
    await page.waitForSelector('table', { timeout: 10_000 });
    // Should have at least 2 licenses from global setup
    const rows = page.locator('table tbody tr');
    const count = await rows.count();
    expect(count).toBeGreaterThanOrEqual(2);

    // Verify tier badges (use .first() since later tests may create additional licenses)
    await expect(page.locator('.tier-badge.tier-pro').first()).toBeVisible();
    await expect(page.locator('.tier-badge.tier-enterprise').first()).toBeVisible();
  });

  test('license detail page shows activations', async ({ page }) => {
    await page.goto('/ui/index.html#/licenses');
    await page.waitForSelector('table', { timeout: 10_000 });
    // Click first license link
    await page.locator('table tbody tr a').first().click();
    await expect(page.locator('h2')).toHaveText('License Detail');
    // Should have an activations table header
    await expect(page.locator('h3')).toHaveText('Activations');
  });
});

test.describe('Activations', () => {
  test('lists seeded activations', async ({ page }) => {
    await page.goto('/ui/index.html#/activations');
    await page.waitForSelector('table', { timeout: 10_000 });
    // Global setup activated one machine
    await expect(page.locator('text=e2e-host-01')).toBeVisible();
    // Check active badge
    await expect(page.locator('.badge-active')).toBeVisible();
  });
});

test.describe('Audit Log', () => {
  test('shows audit entries from seeded actions', async ({ page }) => {
    await page.goto('/ui/index.html#/audit');
    await page.waitForSelector('table', { timeout: 10_000 });
    const rows = page.locator('table tbody tr');
    const count = await rows.count();
    // Global setup creates 3 orgs + 2 licenses + 1 activation = at least 6 audit entries
    expect(count).toBeGreaterThanOrEqual(6);

    // Verify event types present (use .first() since multiple rows may match)
    await expect(page.locator('text=org_create').first()).toBeVisible();
    await expect(page.locator('text=license_create').first()).toBeVisible();
    await expect(page.locator('text=activate').first()).toBeVisible();
  });
});

test.describe('Navigation', () => {
  test('sidebar links navigate between pages', async ({ page }) => {
    await page.goto('/ui/index.html#/');
    await page.waitForSelector('.stat-cards', { timeout: 10_000 });

    // Navigate to Organizations
    await page.click('a[href="#/orgs"]');
    await expect(page.locator('h2')).toHaveText('Organizations');

    // Navigate to Licenses
    await page.click('a[href="#/licenses"]');
    await expect(page.locator('h2')).toHaveText('Licenses');

    // Navigate to Activations
    await page.click('a[href="#/activations"]');
    await expect(page.locator('h2')).toHaveText('Activations');

    // Navigate to Audit
    await page.click('a[href="#/audit"]');
    await expect(page.locator('h2')).toHaveText('Audit Log');

    // Back to Dashboard
    await page.click('a[href="#/"]');
    await expect(page.locator('h2')).toHaveText('Dashboard');
  });
});

// --- New tests: Group A — Organization Mutations ---

test.describe('Organization Mutations', () => {
  test('delete organization without licenses', async ({ page }) => {
    await page.goto('/ui/index.html#/orgs');
    await page.waitForSelector('table', { timeout: 10_000 });
    await expect(page.locator('text=EmptyOrg Ltd')).toBeVisible();

    // Register dialog handler BEFORE clicking delete
    page.on('dialog', async (dialog) => {
      expect(dialog.type()).toBe('confirm');
      await dialog.accept();
    });

    // Find the row containing EmptyOrg Ltd and click its delete button
    const emptyOrgRow = page.locator('tr', { hasText: 'EmptyOrg Ltd' });
    await emptyOrgRow.locator('[data-delete-org]').click();

    // EmptyOrg Ltd should disappear
    await expect(page.locator('text=EmptyOrg Ltd')).not.toBeVisible({ timeout: 5_000 });
  });

  test('delete organization with licenses keeps org', async ({ page }) => {
    await page.goto('/ui/index.html#/orgs');
    await page.waitForSelector('table', { timeout: 10_000 });
    await expect(page.locator('text=Acme Corp')).toBeVisible();

    const initialCount = await page.locator('table tbody tr').count();

    // Register confirm handler BEFORE clicking
    page.on('dialog', async (dialog) => {
      await dialog.accept();
    });

    const acmeRow = page.locator('tr', { hasText: 'Acme Corp' });
    // Set up response listener BEFORE clicking
    const deleteResponse = page.waitForResponse(
      (resp) => resp.url().includes('/api/v1/admin/orgs/') && resp.request().method() === 'DELETE',
    );
    await acmeRow.locator('[data-delete-org]').click();
    await deleteResponse;

    // Acme Corp should still be visible
    await expect(page.locator('text=Acme Corp')).toBeVisible();
    const afterCount = await page.locator('table tbody tr').count();
    expect(afterCount).toBe(initialCount);
  });
});

// --- New tests: Group B — License Mutations ---

test.describe('License Mutations', () => {
  test('create license via modal', async ({ page }) => {
    await page.goto('/ui/index.html#/licenses');
    await page.waitForSelector('table', { timeout: 10_000 });

    const initialCount = await page.locator('table tbody tr').count();

    await page.click('#create-lic-btn');
    await expect(page.locator('.modal')).toBeVisible();
    await expect(page.locator('.modal h3')).toHaveText('Create License');

    // Select first org, set tier/seats/days
    await page.selectOption('#lic-tier', 'enterprise');
    await page.fill('#lic-seats', '3');
    await page.fill('#lic-days', '90');
    await page.click('#modal-create');

    // Modal should close and new row should appear
    await expect(page.locator('.modal')).not.toBeVisible({ timeout: 5_000 });
    const newCount = await page.locator('table tbody tr').count();
    expect(newCount).toBeGreaterThan(initialCount);
  });

  test('revoke license', async ({ page }) => {
    // Create a fresh license via API to revoke
    const licResp = await page.evaluate(async (key) => {
      const orgsResp = await fetch('/api/v1/admin/orgs', {
        headers: { 'X-Triton-Admin-Key': key },
      });
      const orgs = await orgsResp.json();
      const resp = await fetch('/api/v1/admin/licenses', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Triton-Admin-Key': key },
        body: JSON.stringify({ orgID: orgs[0].id, tier: 'free', seats: 1, days: 30 }),
      });
      return resp.json();
    }, ADMIN_KEY);

    await page.goto('/ui/index.html#/licenses');
    await page.waitForSelector('table', { timeout: 10_000 });

    // Register confirm handler BEFORE clicking
    page.on('dialog', async (dialog) => {
      if (dialog.type() === 'confirm') {
        await dialog.accept();
      }
    });

    // Click the revoke button for the specific license we created
    const revokeBtn = page.locator(`[data-revoke="${licResp.id}"]`);
    await revokeBtn.click();

    // After revocation, a revoked badge should appear
    await expect(page.locator('.badge-revoked').first()).toBeVisible({ timeout: 5_000 });
  });
});

// --- New tests: Group C — Modal Behavior ---

test.describe('Modal Behavior', () => {
  test('cancel org modal does not create', async ({ page }) => {
    await page.goto('/ui/index.html#/orgs');
    await page.waitForSelector('table', { timeout: 10_000 });

    const initialCount = await page.locator('table tbody tr').count();

    await page.click('#create-org-btn');
    await expect(page.locator('.modal')).toBeVisible();

    // Fill name but cancel
    await page.fill('#org-name', 'CancelledOrg');
    await page.click('#modal-cancel');

    // Modal should close
    await expect(page.locator('.modal')).not.toBeVisible({ timeout: 5_000 });

    // Row count should be unchanged
    const afterCount = await page.locator('table tbody tr').count();
    expect(afterCount).toBe(initialCount);

    // CancelledOrg should not be visible
    await expect(page.locator('text=CancelledOrg')).not.toBeVisible();
  });

  test('cancel license modal does not create', async ({ page }) => {
    await page.goto('/ui/index.html#/licenses');
    await page.waitForSelector('table', { timeout: 10_000 });

    const initialCount = await page.locator('table tbody tr').count();

    await page.click('#create-lic-btn');
    await expect(page.locator('.modal')).toBeVisible();
    await page.click('#modal-cancel');

    await expect(page.locator('.modal')).not.toBeVisible({ timeout: 5_000 });
    const afterCount = await page.locator('table tbody tr').count();
    expect(afterCount).toBe(initialCount);
  });
});

// --- New tests: Group D — Auth Edge Cases ---

test.describe('Auth Edge Cases', () => {
  test('invalid key triggers auth prompt', async ({ page }) => {
    // Set an invalid key
    await page.evaluate(() => {
      localStorage.setItem('triton_admin_key', 'bad-key');
    });
    await page.goto('/ui/index.html#/');

    // The API call will return 403, which clears the key and shows auth prompt
    await expect(page.locator('#auth-prompt')).toBeVisible({ timeout: 10_000 });
  });

  test('re-authentication persists across navigation', async ({ page }) => {
    // Clear key
    await page.evaluate(() => localStorage.removeItem('triton_admin_key'));
    await page.goto('/ui/index.html#/');

    // Auth prompt should appear
    await expect(page.locator('#auth-prompt')).toBeVisible({ timeout: 10_000 });

    // Authenticate
    await page.fill('#key-input', ADMIN_KEY);
    await page.click('#key-submit');

    // Dashboard should load
    await expect(page.locator('.stat-cards')).toBeVisible({ timeout: 10_000 });

    // Navigate to orgs
    await page.click('a[href="#/orgs"]');
    await expect(page.locator('h2')).toHaveText('Organizations');

    // Org table should load (key persisted)
    await page.waitForSelector('table', { timeout: 10_000 });
    await expect(page.locator('text=Acme Corp')).toBeVisible();
  });
});

// --- New tests: Group E — Detail Pages & Edge Cases ---

test.describe('Detail Pages', () => {
  test('license detail shows activation data', async ({ page }) => {
    await page.goto('/ui/index.html#/licenses');
    await page.waitForSelector('table', { timeout: 10_000 });

    // Find the pro license row (the one with an activation) and click its link
    const proRow = page.locator('table tbody tr', { hasText: 'pro' }).filter({ hasText: 'Acme' });
    await proRow.locator('a').first().click();
    await expect(page.locator('h2')).toHaveText('License Detail');

    // Should show activation data
    await expect(page.locator('h3')).toHaveText('Activations');
    await expect(page.locator('text=e2e-host-01')).toBeVisible();
    await expect(page.locator('.badge-active').first()).toBeVisible();
  });

  test('license detail without activations shows empty table', async ({ page }) => {
    await page.goto('/ui/index.html#/licenses');
    await page.waitForSelector('table', { timeout: 10_000 });

    // Find the Globex enterprise license row (no activations seeded)
    const enterpriseRow = page.locator('table tbody tr', { hasText: 'enterprise' }).filter({ hasText: 'Globex' });
    await enterpriseRow.locator('a').first().click();

    await expect(page.locator('h2')).toHaveText('License Detail');
    await expect(page.locator('h3')).toHaveText('Activations');

    // Activations table body should have no rows
    const activationRows = page.locator('table').last().locator('tbody tr');
    await expect(activationRows).toHaveCount(0);
  });

  test('dashboard stats show correct values', async ({ page }) => {
    await page.goto('/ui/index.html#/');
    await page.waitForSelector('.stat-cards', { timeout: 10_000 });

    const cards = page.locator('.stat-card');
    await expect(cards).toHaveCount(6);

    // Read all stat card values
    const orgCount = parseInt(await cards.nth(0).locator('.value').textContent());
    const totalLicenses = parseInt(await cards.nth(1).locator('.value').textContent());
    const activeSeats = parseInt(await cards.nth(3).locator('.value').textContent());

    // Verify minimums based on seeded data (EmptyOrg deleted earlier, E2E-NewOrg created)
    expect(orgCount).toBeGreaterThanOrEqual(2);       // Acme, Globex (+ E2E-NewOrg from earlier test)
    expect(totalLicenses).toBeGreaterThanOrEqual(2);   // pro + enterprise
    expect(activeSeats).toBeGreaterThanOrEqual(1);     // 1 activation
  });
});
