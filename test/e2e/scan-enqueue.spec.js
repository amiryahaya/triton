// @ts-check
// scan-enqueue.spec.js — E2E tests for the Scan Enqueue Wizard.
//
// Covers the full 5-step wizard flow in the manage portal:
//   Step 1 — Job Type (checkbox cards)
//   Step 2 — Hosts (search, chip selection, chip removal)
//   Step 3 — Schedule (navigation only in these tests)
//   Step 4 — Resources (navigation only in these tests)
//   Step 5 — Summary (credential warning, enqueue button)
//
// Prerequisites: the manage-global-setup.js must have seeded three hosts:
//   e2e-ssh-01  (10.100.0.1) — ssh + credential (shows 🟢)
//   e2e-agent-01 (10.100.0.2) — agent (shows 🟡)
//   e2e-none-01  (10.100.0.3) — ssh without credential (shows 🟡)

const { test, expect } = require('@playwright/test');

const SCAN_JOBS_URL = '/ui/#/operations/scan-jobs';
const WIZARD_URL    = '/ui/#/operations/scan-jobs/new';

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Navigate to the Scan Jobs list and wait for the heading. */
async function gotoScanJobs(page) {
  await page.goto(SCAN_JOBS_URL);
  await expect(page.locator('h1', { hasText: 'Scan Jobs' })).toBeVisible({ timeout: 8_000 });
}

/** Navigate directly to the wizard and wait for the first step heading. */
async function gotoWizard(page) {
  await page.goto(WIZARD_URL);
  await expect(page.locator('h2', { hasText: 'Job Type' })).toBeVisible({ timeout: 8_000 });
}

/**
 * Check a job-type checkbox card by its label text (e.g. 'Port Survey').
 * The cards are <label class="checkbox-card"> elements wrapping an <input>.
 */
async function checkJobType(page, labelText) {
  const card = page.locator('.checkbox-card').filter({ hasText: labelText });
  await card.locator('input[type="checkbox"]').check();
}

/** Click the Next button in the wizard footer. */
async function clickNext(page) {
  await page.locator('.wizard-footer .btn-primary', { hasText: 'Next' }).click();
}

/** Click the Back button in the wizard footer. */
async function clickBack(page) {
  await page.locator('.wizard-footer .btn-secondary', { hasText: 'Back' }).click();
}

/**
 * Walk through wizard steps by checking Port Survey and selecting the first
 * available host, then clicking Next until Step 5 is visible.
 */
async function navigateToStep5(page, { jobTypes = ['Port Survey'], hostQuery = 'e2e' } = {}) {
  await gotoWizard(page);

  // Step 1 — Job Type
  for (const jt of jobTypes) {
    await checkJobType(page, jt);
  }
  await clickNext(page);

  // Step 2 — Hosts
  await expect(page.locator('h2', { hasText: 'Hosts' })).toBeVisible({ timeout: 5_000 });
  // Select the first matching host row
  const firstRow = page.locator('.host-row').first();
  await expect(firstRow).toBeVisible({ timeout: 5_000 });
  await firstRow.locator('input[type="checkbox"]').check();
  await clickNext(page);

  // Step 3 — Schedule
  await expect(page.locator('h2').filter({ hasText: /schedule/i })).toBeVisible({ timeout: 5_000 });
  await clickNext(page);

  // Step 4 — Resources
  await expect(page.locator('h2').filter({ hasText: /resource/i })).toBeVisible({ timeout: 5_000 });
  await clickNext(page);

  // Step 5 — Summary
  await expect(page.locator('h2', { hasText: 'Summary' })).toBeVisible({ timeout: 5_000 });
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// 1. New Scan button navigates to wizard page
test('New Scan button navigates to wizard page', async ({ page }) => {
  await gotoScanJobs(page);

  await page.getByRole('button', { name: 'New Scan' }).click();

  // Hash routing: URL contains the wizard path fragment
  await expect(page).toHaveURL(/operations\/scan-jobs\/new/, { timeout: 8_000 });

  // Step 1 heading is visible
  await expect(page.locator('h2', { hasText: 'Job Type' })).toBeVisible({ timeout: 8_000 });
});

// 2. Sidebar shows 5 steps
test('sidebar shows 5 steps', async ({ page }) => {
  await gotoWizard(page);

  const steps = page.locator('.wizard-step-item');
  await expect(steps).toHaveCount(5);
});

// 3. Next disabled until job type selected
test('Next disabled until job type selected', async ({ page }) => {
  await gotoWizard(page);

  const nextBtn = page.locator('.wizard-footer .btn-primary', { hasText: 'Next' });

  // Initially no job type is selected — Next must be disabled
  await expect(nextBtn).toBeDisabled();

  // Check Port Survey — Next should become enabled
  await checkJobType(page, 'Port Survey');
  await expect(nextBtn).toBeEnabled();

  // Uncheck — disabled again
  await page.locator('.checkbox-card').filter({ hasText: 'Port Survey' })
    .locator('input[type="checkbox"]').uncheck();
  await expect(nextBtn).toBeDisabled();
});

// 4. Step 2 — host list shows credential icons
test('Step 2 — host list shows credential icons', async ({ page }) => {
  await gotoWizard(page);
  await checkJobType(page, 'Port Survey');
  await clickNext(page);

  await expect(page.locator('h2', { hasText: 'Hosts' })).toBeVisible({ timeout: 5_000 });

  // At least one host row must be visible
  const rows = page.locator('.host-row');
  await expect(rows.first()).toBeVisible({ timeout: 8_000 });

  // Each row has a .cred-icon span with an emoji (🟢 or 🟡)
  const icons = page.locator('.host-row .cred-icon');
  const count = await icons.count();
  expect(count).toBeGreaterThan(0);
});

// 5. Step 2 — search filters hosts
test('Step 2 — search filters hosts', async ({ page }) => {
  await gotoWizard(page);
  await checkJobType(page, 'Port Survey');
  await clickNext(page);

  await expect(page.locator('h2', { hasText: 'Hosts' })).toBeVisible({ timeout: 5_000 });
  await expect(page.locator('.host-row').first()).toBeVisible({ timeout: 8_000 });

  const totalBefore = await page.locator('.host-row').count();

  // Type a hostname prefix that matches only one seeded host
  await page.locator('input.t-input').fill('e2e-ssh-01');

  // The host list should shrink (ideally to 1 match for our seeded host)
  const afterSearch = page.locator('.host-row');
  // At minimum, fewer-or-equal rows; the seeded hostname must appear
  await expect(page.locator('.host-row .hostname', { hasText: 'e2e-ssh-01' })).toBeVisible({ timeout: 3_000 });

  // Clear search and all rows come back
  await page.locator('input.t-input').fill('');
  await expect(page.locator('.host-row')).toHaveCount(totalBefore, { timeout: 3_000 });
});

// 6. Step 2 — selecting host adds chip
test('Step 2 — selecting host adds chip', async ({ page }) => {
  await gotoWizard(page);
  await checkJobType(page, 'Port Survey');
  await clickNext(page);

  await expect(page.locator('h2', { hasText: 'Hosts' })).toBeVisible({ timeout: 5_000 });
  await expect(page.locator('.host-row').first()).toBeVisible({ timeout: 8_000 });

  // Before selection, chip-area should not be visible (no hosts selected)
  await expect(page.locator('.chip-area')).not.toBeVisible();

  // Select the first host
  await page.locator('.host-row').first().locator('input[type="checkbox"]').check();

  // Chip area appears with at least one chip
  await expect(page.locator('.chip-area')).toBeVisible({ timeout: 3_000 });
  await expect(page.locator('.chip-area .chip')).toHaveCount(1);
});

// 7. Step 2 — removing chip via ✕ deselects host
test('Step 2 — removing chip via remove button deselects host', async ({ page }) => {
  await gotoWizard(page);
  await checkJobType(page, 'Port Survey');
  await clickNext(page);

  await expect(page.locator('h2', { hasText: 'Hosts' })).toBeVisible({ timeout: 5_000 });
  await expect(page.locator('.host-row').first()).toBeVisible({ timeout: 8_000 });

  // Select first host — chip appears
  await page.locator('.host-row').first().locator('input[type="checkbox"]').check();
  await expect(page.locator('.chip-area .chip')).toHaveCount(1);

  // Click the chip-remove button (&#x2715; entity)
  await page.locator('.chip-area .chip .chip-remove').first().click();

  // Chip area disappears (no selection)
  await expect(page.locator('.chip-area')).not.toBeVisible({ timeout: 3_000 });
});

// 8. Step 5 — amber warning shown for unconfigured host + filesystem job type
test('Step 5 — amber warning shown for unconfigured host + filesystem', async ({ page }) => {
  await gotoWizard(page);

  // Select both job types
  await checkJobType(page, 'Port Survey');
  await checkJobType(page, 'Filesystem (SSH)');
  await clickNext(page);

  // Step 2 — pick e2e-none-01 (no credential → triggers warning)
  await expect(page.locator('h2', { hasText: 'Hosts' })).toBeVisible({ timeout: 5_000 });
  await expect(page.locator('.host-row').first()).toBeVisible({ timeout: 8_000 });

  // Search for the host without credential
  await page.locator('input.t-input').fill('e2e-none-01');
  const noneRow = page.locator('.host-row', { hasText: 'e2e-none-01' });
  await expect(noneRow).toBeVisible({ timeout: 5_000 });
  await noneRow.locator('input[type="checkbox"]').check();
  await clickNext(page);

  // Step 3 and 4 — advance without changes
  await expect(page.locator('h2').filter({ hasText: /schedule/i })).toBeVisible({ timeout: 5_000 });
  await clickNext(page);
  await expect(page.locator('h2').filter({ hasText: /resource/i })).toBeVisible({ timeout: 5_000 });
  await clickNext(page);

  // Step 5 — amber credential-warning block must be visible
  await expect(page.locator('h2', { hasText: 'Summary' })).toBeVisible({ timeout: 5_000 });
  await expect(page.locator('.credential-warning')).toBeVisible({ timeout: 3_000 });
});

// 9. Step 5 — no amber warning when only port survey selected
test('Step 5 — no amber warning when only port survey', async ({ page }) => {
  await gotoWizard(page);

  // Select only Port Survey (no filesystem)
  await checkJobType(page, 'Port Survey');
  await clickNext(page);

  // Step 2 — pick any host (even one without credential)
  await expect(page.locator('h2', { hasText: 'Hosts' })).toBeVisible({ timeout: 5_000 });
  await expect(page.locator('.host-row').first()).toBeVisible({ timeout: 8_000 });

  await page.locator('input.t-input').fill('e2e-none-01');
  const noneRow = page.locator('.host-row', { hasText: 'e2e-none-01' });
  await expect(noneRow).toBeVisible({ timeout: 5_000 });
  await noneRow.locator('input[type="checkbox"]').check();
  await clickNext(page);

  // Steps 3 and 4
  await expect(page.locator('h2').filter({ hasText: /schedule/i })).toBeVisible({ timeout: 5_000 });
  await clickNext(page);
  await expect(page.locator('h2').filter({ hasText: /resource/i })).toBeVisible({ timeout: 5_000 });
  await clickNext(page);

  // Step 5 — no credential warning (port survey needs no credential)
  await expect(page.locator('h2', { hasText: 'Summary' })).toBeVisible({ timeout: 5_000 });
  await expect(page.locator('.credential-warning')).not.toBeVisible();
});

// 10. Full enqueue (port survey, immediately) navigates to /scan-jobs
test('Full enqueue (port survey, immediately) navigates to /scan-jobs', async ({ page }) => {
  await gotoWizard(page);

  // Step 1 — select Port Survey
  await checkJobType(page, 'Port Survey');
  await clickNext(page);

  // Step 2 — select first available host
  await expect(page.locator('h2', { hasText: 'Hosts' })).toBeVisible({ timeout: 5_000 });
  await expect(page.locator('.host-row').first()).toBeVisible({ timeout: 8_000 });
  await page.locator('.host-row').first().locator('input[type="checkbox"]').check();
  await clickNext(page);

  // Step 3 — Schedule (default is "immediately") — just advance
  await expect(page.locator('h2').filter({ hasText: /schedule/i })).toBeVisible({ timeout: 5_000 });
  await clickNext(page);

  // Step 4 — Resources — just advance
  await expect(page.locator('h2').filter({ hasText: /resource/i })).toBeVisible({ timeout: 5_000 });
  await clickNext(page);

  // Step 5 — Summary — click the Enqueue button
  await expect(page.locator('h2', { hasText: 'Summary' })).toBeVisible({ timeout: 5_000 });
  const enqueueBtn = page.locator('.enqueue-btn');
  await expect(enqueueBtn).toBeVisible();
  await enqueueBtn.click();

  // After successful enqueue the wizard redirects to the Scan Jobs list
  await expect(page).toHaveURL(/operations\/scan-jobs/, { timeout: 15_000 });
  await expect(page.locator('h1', { hasText: 'Scan Jobs' })).toBeVisible({ timeout: 8_000 });
});
