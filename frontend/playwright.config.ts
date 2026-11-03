import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  testMatch: '*.spec.ts',
  outputDir: '../test-results',
  fullyParallel: false,
  workers: 1,
  timeout: 30_000,
  expect: { timeout: 8_000 },
  reporter: 'list',
  use: {
    browserName: 'firefox',
    headless: true,
    baseURL: 'http://127.0.0.1:8732',
    viewport: { width: 1440, height: 1000 },
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  webServer: {
    command: '../.venv/bin/python ../scripts/test_server.py',
    url: 'http://127.0.0.1:8732/api/health',
    reuseExistingServer: false,
    timeout: 30_000,
  },
});
