# E2E Testing Setup Guide

## Prerequisites

Before running E2E tests, you need to download the required Chrome extensions. The extensions are used to simulate wallet interactions during testing.

### 1. Download Extensions

Run the following command to download all required extensions:

```bash
npm run extensions:download
```

This will:

- Download Chrome extensions from the Chrome Web Store:
  - OKX Wallet
  - Keplr Wallet
  - Bitget Wallet
  - OneKey Wallet
- Save them in extensions directory
- Include version information in filenames (e.g., `mcohilncbfahbmgdjkbpemcciiolgcge_3.34.19.0.crx`)
- Unzip the extensions
- Skip downloading if a specific version already exists

### 1. Run E2E Tests

After downloading the extensions, you can run the tests with:

```bash
npm run test:e2e
```

Additional test commands:

```bash
npm run test:e2e:ui      # Run tests with UI
npm run test:e2e:debug   # Run tests in debug mode
npm run test:e2e:headed  # Run tests in headed mode
```
