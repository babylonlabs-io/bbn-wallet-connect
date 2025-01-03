## Wallet Integration

This guide explains how to integrate wallets with the Babylon staking dApp. The
dApp supports both Bitcoin (BTC) and Babylon (BBN) wallets through two
integration paths:

### 1. Integration Through Tomo Connect SDK Lite (Recommended)

The recommended way to integrate your wallet with Babylon staking dApp is
through
[Tomo Connect SDK Lite](https://docs.tomo.inc/tomo-sdk/tomo-connect-sdk-lite).
This provides:

- Simplified integration process
- Broader wallet ecosystem access
- Maintained by Tomo team

We strongly encourage wallet developers to integrate via Tomo Connect first.
Please refer to Tomo's documentation for integration details.

### 2. Direct Native Integration

Direct native integration should only be considered if Tomo Connect integration
is not feasible for your use case. This repository contains a set of natively
integrated wallets that are maintained by the Babylon team.

### Supported Wallet Types

#### Bitcoin (BTC) Wallets

Both native and injectable wallets must implement the `IBTCProvider` interface.

1. Native Wallets

- Browser extension wallets like `OKX` and `OneKey`
- Hardware wallets like `Keystone`
- Note: Native wallet integrations are managed by the Babylon team

2. Injectable Wallets

- No repository changes required
- Must inject implementation into `window.btcwallet`
- Common in mobile wallet browsers

#### Babylon (BBN) Wallets

Both native and injectable wallets must implement the `IBBNProvider` interface.

1. Native Wallets

- Browser extension wallets like Keplr
- Note: Native wallet integrations are managed by the Babylon team

2. Injectable Wallets

- No repository changes required
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
