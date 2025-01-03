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

- Unified interfaces for BTC and BBN wallet connections
- Support for browser extension wallets
- Support for hardware wallets
- Mobile wallet compatibility through injectable interfaces
- Tomo Connect integration for broader wallet ecosystem

## Overview

The Babylon Wallet Connector provides a unified interface for integrating both
Bitcoin (BTC) and Babylon (BBN) wallets into Babylon dApp. It supports both
native wallet extensions and injectable mobile wallets.

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

## For Wallet Developers

If you're interested in integrating your wallet with the Babylon staking dApp,
we strongly recommend using
[Tomo Connect SDK Lite](https://docs.tomo.inc/tomo-sdk/tomo-connect-sdk-lite).
For detailed integration specifications and alternatives, please refer to our
[Wallet Integration Guide](docs/wallet-integration.md).

## FAQ

Q: What's the difference between native and injectable wallets? A: Native
wallets are built into the library, while injectable wallets (common in mobile
apps) can dynamically inject their implementation into the webpage.

Q: Should I integrate through Tomo Connect or directly? A: We recommend
integrating through Tomo Connect. Direct integration should only be considered
**only** if Tomo Connect integration isn't feasible for your use case.
