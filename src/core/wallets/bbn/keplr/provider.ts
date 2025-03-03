import { Window as KeplrWindow } from "@keplr-wallet/types";
import { OfflineAminoSigner, OfflineDirectSigner } from "@keplr-wallet/types/src/cosmjs";
import { Buffer } from "buffer";

import { BBNConfig, IBBNProvider, WalletInfo } from "@/core/types";

import logo from "./logo.svg";

declare global {
  // eslint-disable-next-line @typescript-eslint/no-empty-object-type
  interface Window extends KeplrWindow {}
}

export const WALLET_PROVIDER_NAME = "Keplr";

export class KeplrProvider implements IBBNProvider {
  private walletInfo: WalletInfo | undefined;
  private chainId: string | undefined;
  private rpc: string | undefined;
  private chainData: BBNConfig["chainData"];

  constructor(
    private keplr: Window["keplr"],
    config: BBNConfig,
  ) {
    if (!keplr) {
      throw new Error("Keplr extension not found");
    }
    this.chainId = config.chainId;
    this.rpc = config.rpc;
    this.chainData = config.chainData;
  }

  isRealKeplr() {
    return (
      typeof this?.keplr?.signEthereum === "function" ||
      typeof this?.keplr?.sendEthereumTx === "function" ||
      (this?.keplr?.defaultOptions && typeof this?.keplr?.defaultOptions === "object")
    );
  }

  async connectWallet(): Promise<void> {
    if (!this.chainId) throw new Error("Chain ID is not initialized");
    if (!this.rpc) throw new Error("RPC URL is not initialized");
    if (!this.keplr) throw new Error("Keplr extension not found");

    const notRealKeplrFlags = ["isBitKeep", "isOneKey", "isOkxWallet"];
    const keplrHasFlags = notRealKeplrFlags.some((flag) => (this.keplr as any)?.[flag]);

    if (!this.isRealKeplr() || keplrHasFlags) {
      console.log("not real keplr");
      throw new Error("Keplr extension not found");
    }

    try {
      await this.keplr.enable(this.chainId);
    } catch (error: Error | any) {
      if (error?.message.includes(this.chainId)) {
        try {
          // User has no BBN chain in their wallet
          await this.keplr.experimentalSuggestChain(this.chainData);
          await this.keplr.enable(this.chainId);
        } catch {
          throw new Error("Failed to add BBN chain");
        }
      } else {
        if (error?.message.includes("rejected")) {
          throw new Error("Keplr wallet connection request rejected");
        } else if (error?.message.includes("context invalidated")) {
          throw new Error("Keplr extension context invalidated");
        } else {
          throw new Error(error?.message || "Failed to connect to Keplr");
        }
      }
    }
    const key = await this.keplr.getKey(this.chainId);

    if (!key) throw new Error("Failed to get Keplr key");

    const { bech32Address, pubKey } = key;

    if (bech32Address && pubKey) {
      this.walletInfo = {
        publicKeyHex: Buffer.from(key.pubKey).toString("hex"),
        address: bech32Address,
      };
    } else {
      throw new Error("Could not connect to Keplr");
    }
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
    if (!this.keplr) throw new Error("Keplr extension not found");
    if (!this.chainId) throw new Error("Chain ID is not initialized");

    try {
      return this.keplr.getOfflineSigner(this.chainId);
    } catch {
      throw new Error("Failed to get offline signer");
    }
  }
}
