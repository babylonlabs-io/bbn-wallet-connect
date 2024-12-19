<p align="center">
    <img alt="Babylon Logo" src="https://github.com/user-attachments/assets/b21652b5-847d-48b2-89a7-0f0969a50900" width="100" />
    <h3 align="center">@babylonlabs-io/bbn-wallet-connect</h3>
    <p align="center">Babylon Wallet Connector</p>
</p>
<br/>

## Overview

The Babylon Wallet Connector provides a unified interface for integrating both Bitcoin (BTC) and Babylon (BBN) wallets into Babylon dApp. It supports both native wallet extensions and injectable mobile wallets.

## Installation

```console
npm i @babylonlabs-io/bbn-wallet-connect
```

## Version Release

### Stable version

Stable release versions are manually released from the main branch.

## Storybook

```console
npm run storybook
```

## Wallet Integration

This guide explains how to integrate wallets with the Babylon staking dApp. The dApp supports both Bitcoin (BTC) and Babylon (BBN) wallets through a unified interface.

### Supported Wallet Types

#### Bitcoin (BTC) Wallets

Both native and injectable wallets require implementing `IBTCProvider` interface

1. Native Wallets

- Must submit a PR to add the implementation
- Examples: `OKX` and `OneKey` Chrome Extensions, `Keystone` Hardware Wallet

2. Injectable Wallets

- No PR required
- Must inject implementation into `window.btcwallet`
- Common in mobile wallet browsers

#### Babylon (BBN) Wallets

Both native and injectable wallets require implementing `IBBNProvider` interface

1. Native Wallets

- Must submit a PR to add the implementation
- Example: `Keplr`

2. Injectable Wallets

- No PR required
- Must inject implementation into `window.bbnwallet`
- Common in mobile wallet browsers

### Integration Process

#### 1. Implement Provider Interface

Choose the appropriate interface based on your wallet type:

```ts
// For BTC wallets
interface IBTCProvider {
  connectWallet(): Promise<void>;
  getAddress(): Promise<string>;
  getPublicKeyHex(): Promise<string>;
  signPsbt(psbtHex: string): Promise<string>;
  signPsbts(psbtsHexes: string[]): Promise<string[]>;
  getNetwork(): Promise<Network>;
  signMessage(message: string, type: "ecdsa"): Promise<string>;
  getInscriptions(): Promise<InscriptionIdentifier[]>;
  on(eventName: string, callBack: () => void): void;
  off(eventName: string, callBack: () => void): void;
  getWalletProviderName(): Promise<string>;
  getWalletProviderIcon(): Promise<string>;
}

// For BBN wallets
interface IBBNProvider {
  connectWallet(): Promise<void>;
  getAddress(): Promise<string>;
  getPublicKeyHex(): Promise<string>;
  getOfflineSigner(): Promise<OfflineAminoSigner & OfflineDirectSigner>;
  getWalletProviderName(): Promise<string>;
  getWalletProviderIcon(): Promise<string>;
}
```

#### 2. Integration Method

For Native Wallets:

1. Create wallet provider implementation
2. Create wallet metadata file
3. Submit PR to add your wallet

Example metadata for BTC wallet:

```ts
const metadata: WalletMetadata<IBTCProvider, BTCConfig> = {
  id: "wallet-id",
  name: WALLET_PROVIDER_NAME,
  icon: logo,
  docs: "https://docs.example.com",
  wallet: "window-key", // Global window key to detect wallet
  createProvider: (wallet, config) => new WalletProvider(wallet, config),
  networks: [Network.MAINNET, Network.SIGNET], // Supported networks
};
```

For Injectable Wallets:

1. Implement provider interface
2. Inject into `window` before loading dApp:

```ts
// For BTC wallets
window.btcwallet = new BTCWalletImplementation();

// For BBN wallets
window.bbnwallet = new BBNWalletImplementation();
```

### Integration Through Tomo Connect SDK Lite

In addition to direct integration, wallets can also be integrated through [Tomo Connect SDK Lite](https://docs.tomo.inc/tomo-sdk/tomo-connect-sdk-lite).
