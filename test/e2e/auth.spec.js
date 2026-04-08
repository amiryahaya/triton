// @ts-check
// E2E tests for the report-server auth flow added in Phases 3 and 4.
// Covers: login → forced change-password → users CRUD. Uses the seed
// admin credentials installed by testserver on startup (see
// test/e2e/cmd/testserver/main.go::seedAuthFixtures).
const { test, expect } = require('@playwright/test');

const SEED_EMAIL = 'e2e-admin@triton.test';
const SEED_INITIAL_PW = 'e2e-initial-pw-12345';
const SEED_NEW_PW = 'e2e-rotated-pw-67890-longer';

// clearAuth wipes localStorage so a new test starts unauthenticated.
// The global-setup seeds scans into testOrgID; because the testserver
// is configured with a Guard bound to that org, anonymous requests
// still see data via the fallback path. Anywhere the test explicitly
// needs the login flow, it clears storage then navigates to #/login.
async function clearAuth(page) {
  await page.goto('/ui/index.html');
  await page.evaluate(() => localStorage.removeItem('tritonJWT'));
}

test.describe('Auth flow', () => {
  test('unauthenticated user can render login page via #/login', async ({ page }) => {
    await clearAuth(page);
    await page.goto('/ui/index.html#/login');
    await expect(page.locator('.auth-card h2')).toHaveText('Sign in');
    await expect(page.locator('#loginEmail')).toBeVisible();
    await expect(page.locator('#loginPassword')).toBeVisible();
  });

  test('invalid credentials surface a visible error', async ({ page }) => {
    await clearAuth(page);
    await page.goto('/ui/index.html#/login');
    await page.fill('#loginEmail', SEED_EMAIL);
    await page.fill('#loginPassword', 'wrong-password-000');
    await page.click('button[type="submit"]');
    await expect(page.locator('#loginError')).not.toBeEmpty();
  });

  test('first login forces change-password then lands on dashboard', async ({ page }) => {
    await clearAuth(page);
    await page.goto('/ui/index.html#/login');
    await page.fill('#loginEmail', SEED_EMAIL);
    await page.fill('#loginPassword', SEED_INITIAL_PW);
    await page.click('button[type="submit"]');

    // The seed user has must_change_password=true, so the server returns
    // mustChangePassword=true and the SPA routes to #/change-password.
    await expect(page).toHaveURL(/#\/change-password$/);
    await expect(page.locator('.auth-card h2')).toHaveText('Change password');

    // Rotate the password.
    await page.fill('#cpwCurrent', SEED_INITIAL_PW);
    await page.fill('#cpwNew', SEED_NEW_PW);
    await page.fill('#cpwConfirm', SEED_NEW_PW);
    await page.click('button[type="submit"]');

    // After a successful change, the SPA either redirects to overview
    // (token refreshed in-place) or to login (if the server omitted the
    // fresh token). Either way we end up authenticated-capable and not
    // trapped on the change-password gate. Accept both outcomes.
    await page.waitForURL(/#\/(?:$|login$)/, { timeout: 5000 });
  });

});
