// @ts-check
const { defineConfig } = require('@playwright/test');

module.exports = defineConfig({
  testDir: '.',
  testMatch: 'manage-hosts.spec.js',
  fullyParallel: false,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: process.env.CI ? 'github' : 'list',
  timeout: 30_000,

  use: {
    baseURL: 'http://localhost:8082',
    trace: 'on-first-retry',
    storageState: './.manage-auth.json',
  },

  projects: [
    {
      name: 'chromium',
      use: { browserName: 'chromium' },
    },
  ],

  globalSetup: './manage-global-setup.js',

  webServer: {
    command: 'MANAGE_E2E_RESET=1 go run ./test/e2e/cmd/managetestserver/main.go',
    cwd: '../../',
    url: 'http://localhost:8082/api/v1/health',
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
  },
});
