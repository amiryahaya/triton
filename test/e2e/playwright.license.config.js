// @ts-check
const { defineConfig } = require('@playwright/test');

module.exports = defineConfig({
  testDir: '.',
  testMatch: 'license-admin.spec.js',
  fullyParallel: false,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: process.env.CI ? 'github' : 'list',
  timeout: 30_000,

  use: {
    baseURL: 'http://localhost:8081',
    trace: 'on-first-retry',
  },

  projects: [
    {
      name: 'chromium',
      use: { browserName: 'chromium' },
    },
  ],

  globalSetup: './license-global-setup.js',

  webServer: {
    command: 'go run ./test/e2e/cmd/testlicenseserver/main.go',
    cwd: '../../',
    url: 'http://localhost:8081/api/v1/health',
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
  },
});
