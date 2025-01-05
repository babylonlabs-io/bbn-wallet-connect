<p align="center">
    <img
        alt="Babylon Logo"
        src="https://github.com/user-attachments/assets/b21652b5-847d-48b2-89a7-0f0969a50900"
        width="100"
    />
    <h3 align="center">@babylonlabs-io/bbn-wallet-connect</h3>
    <p align="center">Babylon Wallet Connector</p>
</p>
<br/>

The Babylon Wallet Connector repository provides the wallet connection component
used in the Babylon Staking Dashboard. This component enables the connection of
both Bitcoin and Babylon chain wallets.

## Key Features

- Unified interfaces for Bitcoin and Babylon wallet connections
- Support for browser extension wallets
- Support for hardware wallets
- Mobile wallet compatibility through injectable interfaces
- Tomo Connect integration for broader wallet ecosystem

## Overview

The Babylon Wallet Connector provides a unified interface for integrating both
Bitcoin and Babylon wallets into Babylon dApp. It supports both native wallet
extensions and injectable mobile wallets.

The main architectural difference is that native wallets are built into the
library, while injectable wallets can be dynamically added by injecting their
implementation into the webpage's `window` object before the dApp loads.

## Installation

```bash
npm i @babylonlabs-io/bbn-wallet-connect
```

## Version Release

### Stable version

Stable release versions are manually released from the main branch.

## Storybook

```bash
npm run dev
```

## Wallet Developers

Wallet developers that want to integrate their wallet into the Babylon Wallet
Connect interface for listing in the Babylon staking dashboard have the
following options:

- **Browser Extension Wallets** can integrate through the
  [Tomo Connet SDK](https://docs.tomo.inc/tomo-sdk/tomo-connect-sdk-lite), which
  is the external Wallet Connection interface that ensures compatibility with
  our application. Native integrations into the Babylon Wallet Connector require
  significant maintenance and will happen only for critical wallets for the
  staking application.
- **Mobile Wallets** can integrate through the mobile injectable interface. For
  a detailed integration specification, please refer to our
  [Wallet Integration Guide](docs/wallet-integration.md).
