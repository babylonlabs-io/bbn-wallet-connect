# E2E Testing Setup Guide

## Overview

These tests use Playwright to launch a Chromium instance with selected wallet extensions. The required extensions (OKX, Keplr, etc.) download automatically as part of the test setup.

Use the following command to run the E2E tests:

```bash
npm run test:e2e
```

Additional test commands:

```bash
npm run test:e2e:ui      # Run tests with UI
npm run test:e2e:debug   # Run tests in debug mode
npm run test:e2e:headed  # Run tests in headed mode
```
