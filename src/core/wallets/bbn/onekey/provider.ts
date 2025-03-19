import { OfflineAminoSigner, OfflineDirectSigner } from "@keplr-wallet/types/src/cosmjs";

import { BBNConfig, IBBNProvider, WalletInfo } from "@/core/types";

import logo from "./logo.svg";

export const WALLET_PROVIDER_NAME = "OneKey";

export class OneKeyProvider implements IBBNProvider {
  private provider: any;
  private walletInfo: WalletInfo | undefined;
  private chainId: string | undefined;
  private rpc: string | undefined;

  constructor(
    private wallet: any,
    config: BBNConfig,
  ) {
    if (!wallet || !wallet.bbnCosmos) {
      throw new Error("OneKey Wallet extension not found");
    }
    this.chainId = config.chainId;
    this.rpc = config.rpc;
    this.provider = wallet.bbnCosmos;
  }

  async connectWallet(): Promise<void> {
    if (!this.chainId) throw new Error("Chain ID is not initialized");
    if (!this.rpc) throw new Error("RPC URL is not initialized");
    if (!this.wallet.bbnCosmos) throw new Error("OneKey Wallet extension not found");

    try {
      await this.provider.connectWallet(this.chainId);
    } catch (error: Error | any) {
      if ((error as Error)?.message?.includes("rejected")) {
        throw new Error("Connection to OneKey Wallet was rejected");
      } else {
        throw new Error((error as Error)?.message);
      }
    }

    const publicKeyHex = await this.provider.getPublicKeyHex(this.chainId);
    const address = await this.provider.getAddress(this.chainId);

    if (!publicKeyHex || !address) throw new Error("Failed to get OneKey key");

    this.walletInfo = {
      publicKeyHex,
      address,
    };
  }

  async getAddress(): Promise<string> {
    if (!this.walletInfo) throw new Error("Wallet not connected");
    return this.walletInfo.address;
  }

  async getPublicKeyHex(): Promise<string> {
    if (!this.walletInfo) throw new Error("Wallet not connected");
    return this.walletInfo.publicKeyHex;
  }

  async getWalletProviderName(): Promise<string> {
    return WALLET_PROVIDER_NAME;
  }

  async getWalletProviderIcon(): Promise<string> {
    return logo;
  }

  async getOfflineSigner(): Promise<OfflineAminoSigner & OfflineDirectSigner> {
    if (!this.provider) throw new Error("OneKey Wallet extension not found");
    if (!this.chainId) throw new Error("Chain ID is not initialized");

    try {
      return this.provider.getOfflineSigner(this.chainId);
    } catch {
      throw new Error("Failed to get offline signer");
    }
  }

  async getOfflineSignerAuto(): Promise<OfflineAminoSigner | OfflineDirectSigner> {
    if (!this.provider) throw new Error("OneKey Wallet extension not found");
    if (!this.chainId) throw new Error("Chain ID is not initialized");

    try {
      return this.provider.getOfflineSignerAuto(this.chainId);
    } catch {
      throw new Error("Failed to get offline signer auto");
    }
  }

  on = (eventName: string, callBack: () => void) => {
    if (!this.walletInfo) throw new Error("Wallet not connected");
    if (eventName === "accountChanged") {
      this.provider._provider.on("keplr_keystorechange", callBack);
    }
  };

  off = (eventName: string, callBack: () => void) => {
    if (!this.walletInfo) throw new Error("Wallet not connected");
    if (eventName === "accountChanged") {
      this.provider._provider.off("keplr_keystorechange", callBack);
    }
  };
}
