import { ChainInfo, OfflineAminoSigner, OfflineDirectSigner } from "@keplr-wallet/types";
import { ComponentType } from "react";

export type Fees = {
  // fee for inclusion in the next block
  fastestFee: number;
  // fee for inclusion in a block in 30 mins
  halfHourFee: number;
  // fee for inclusion in a block in 1 hour
  hourFee: number;
  // economy fee: inclusion not guaranteed
  economyFee: number;
  // minimum fee: the minimum fee of the network
  minimumFee: number;
};

// UTXO is a structure defining attributes for a UTXO
export interface UTXO {
  // hash of transaction that holds the UTXO
  txid: string;
  // index of the output in the transaction
  vout: number;
  // amount of satoshis the UTXO holds
  value: number;
  // the script that the UTXO contains
  scriptPubKey: string;
}

export interface InscriptionIdentifier {
  // hash of transaction that holds the ordinals/brc-2-/runes etc in the UTXO
  txid: string;
  // index of the output in the transaction
  vout: number;
}
// supported networks
export enum Network {
  MAINNET = "mainnet",
  CANARY = "canary",
  TESTNET = "testnet",
  SIGNET = "signet",
}

// WalletInfo is a structure defining attributes for a wallet
export type WalletInfo = {
  publicKeyHex: string;
  address: string;
};

export interface BTCConfig {
  coinName: string;
  coinSymbol: string;
  networkName: string;
  mempoolApiUrl: string;
  network: Network;
}

export type BBNConfig = {
  chainId: string;
  rpc: string;
  chainData: ChainInfo;
  networkName: string;
  networkFullName: string;
  coinSymbol: string;
};

export interface IProvider {
  connectWallet: () => Promise<void>;
  getAddress: () => Promise<string>;
  getPublicKeyHex: () => Promise<string>;
}

export interface IWallet<P extends IProvider = IProvider> {
  id: string;
  name: string;
  icon: string;
  docs: string;
  installed: boolean;
  provider: P | null;
  account: Account | null;
  label: string;
}

export interface IChain<K extends string = string, P extends IProvider = IProvider, C = any> {
  id: K;
  name: string;
  icon: string;
  wallets: IWallet<P>[];
  config: C;
}

export interface IConnector<K extends string = string, P extends IProvider = IProvider, C = any>
  extends IChain<K, P, C> {
  connect(wallet: string | IWallet<P>): Promise<IWallet<P> | null>;
  disconnect(): Promise<void>;
  on(event: string, cb: (wallet: IWallet<P>) => void): () => void;
}

export interface Account {
  address: string;
  publicKeyHex: string;
}

export interface WalletMetadata<P extends IProvider, C> {
  id: string;
  wallet?: string | ((context: any, config: C) => any);
  label?: string;
  name: string | ((wallet: any, config: C) => Promise<string>);
  icon: string | ((wallet: any, config: C) => Promise<string>);
  docs: string;
  networks: Network[];
  createProvider: (wallet: any, config: C) => P;
}

export interface ChainMetadata<N extends string, P extends IProvider, C> {
  chain: N;
  name: string;
  icon: string;
  wallets: WalletMetadata<P, C>[];
}

export interface ExternalWalletProps<P extends IProvider> {
  id: string;
  name: string;
  icon: string;
  provider: P;
}

export interface WidgetProps<P extends IProvider = IProvider> {
  id: string;
  connector: IConnector;
  createWallet: (props: ExternalWalletProps<P>) => IWallet<P>;
}

export type WidgetComponent<P extends IProvider = IProvider> = ComponentType<WidgetProps<P>>;

export interface ExternalConnector<P extends IProvider = IProvider> {
  id: string;
  widget: WidgetComponent<P>;
}

export interface IBTCProvider extends IProvider {
  /**
   * Connects to the wallet and returns the instance of the wallet provider.
   * Currently only supports "native segwit" and "taproot" address types.
   * @returns A promise that resolves to an instance of the wrapper wallet provider in babylon friendly format.
   * @throws An error if the wallet is not installed or if connection fails.
   */
  connectWallet(): Promise<void>;

  /**
   * Gets the address of the connected wallet.
   * @returns A promise that resolves to the address of the connected wallet.
   */
  getAddress(): Promise<string>;

  /**
   * Gets the public key of the connected wallet.
   * @returns A promise that resolves to the public key of the connected wallet.
   */
  getPublicKeyHex(): Promise<string>;

  /**
   * Signs the given PSBT in hex format.
   * @param psbtHex - The hex string of the unsigned PSBT to sign.
   * @returns A promise that resolves to the hex string of the signed PSBT.
   */
  signPsbt(psbtHex: string): Promise<string>;

  /**
   * Signs multiple PSBTs in hex format.
   * @param psbtsHexes - The hex strings of the unsigned PSBTs to sign.
   * @returns A promise that resolves to an array of hex strings, each representing a signed PSBT.
   */
  signPsbts(psbtsHexes: string[]): Promise<string[]>;

  /**
   * Gets the network of the current account.
   * @returns A promise that resolves to the network of the current account.
   */
  getNetwork(): Promise<Network>;

  /**
   * Signs a message using the specified signing method.
   * @param message - The message to sign.
   * @param type - The signing method to use.
   * @returns A promise that resolves to the signed message.
   */
  signMessage(message: string, type: "ecdsa"): Promise<string>;

  /**
   * Retrieves the inscriptions for the connected wallet.
   * @returns A promise that resolves to an array of inscriptions.
   */
  getInscriptions(): Promise<InscriptionIdentifier[]>;

  /**
   * Registers an event listener for the specified event.
   * At the moment, only the "accountChanged" event is supported.
   * @param eventName - The name of the event to listen for.
   * @param callBack - The callback function to be executed when the event occurs.
   */
  on(eventName: string, callBack: () => void): void;

  /**
   * Unregisters an event listener for the specified event.
   * @param eventName - The name of the event to listen for.
   * @param callBack - The callback function to be executed when the event occurs.
   */
  off(eventName: string, callBack: () => void): void;

  /**
   * Gets the name of the wallet provider.
   * @returns A promise that resolves to the name of the wallet provider.
   */
  getWalletProviderName(): Promise<string>;

  /**
   * Gets the icon of the wallet provider.
   * @returns A promise that resolves to the icon of the wallet provider.
   */
  getWalletProviderIcon(): Promise<string>;
}

export interface IBBNProvider extends IProvider {
  /**
   * Connects to the wallet and returns the instance of the wallet provider.
   * @returns A promise that resolves to an instance of the wrapper wallet provider.
   * @throws An error if the wallet is not installed or if connection fails.
   */
  connectWallet(): Promise<void>;

  /**
   * Gets the address of the connected wallet.
   * @returns A promise that resolves to the address of the connected wallet.
   */
  getAddress(): Promise<string>;

  /**
   * Gets the public key of the connected wallet.
   * @returns A promise that resolves to the public key of the connected wallet.
   */
  getPublicKeyHex(): Promise<string>;

  /**
   * Gets the name of the wallet provider.
   * @returns A promise that resolves to the name of the wallet provider.
   */
  getWalletProviderName(): Promise<string>;

  /**
   * Gets the icon of the wallet provider.
   * @returns A promise that resolves to the icon of the wallet provider.
   */
  getWalletProviderIcon(): Promise<string>;

  /**
   * Retrieves an offline signer that supports both Amino and Direct signing methods.
   * This signer is used for signing transactions offline before broadcasting them to the network.
   *
   * @returns {Promise<OfflineAminoSigner | OfflineDirectSigner>} A promise that resolves to a signer supporting either Amino or Direct signing
   * @throws {Error} If wallet connection is not established or signer cannot be retrieved
   */
  getOfflineSigner(): Promise<OfflineAminoSigner | OfflineDirectSigner>;
}
