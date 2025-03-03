import type { Account, BTCConfig, IBTCProvider, InscriptionIdentifier } from "@/core/types";
import { Network } from "@/core/types";
import { validateAddress } from "@/core/utils/wallet";

import logo from "./logo.svg";

const INTERNAL_NETWORK_NAMES = {
  [Network.MAINNET]: "livenet",
  [Network.TESTNET]: "testnet",
  [Network.SIGNET]: "signet",
};

export const WALLET_PROVIDER_NAME = "OneKey";

export class OneKeyProvider implements IBTCProvider {
  private provider: any;

  constructor(
    wallet: any,
    private readonly config: BTCConfig,
    private connectedAccount: Account | null = null,
  ) {
    // check whether there is an OneKey extension
    if (!wallet?.btcwallet) {
      throw new Error("OneKey Wallet extension not found");
    }

    this.provider = wallet.btcwallet;
  }

  connectWallet = async (): Promise<Account> => {
    try {
      await this.provider.connectWallet();
    } catch (error) {
      if ((error as Error)?.message?.includes("rejected")) {
        throw new Error("Connection to OneKey Wallet was rejected");
      } else {
        throw new Error((error as Error)?.message);
      }
    }

    const address = await this.provider.getAddress();
    validateAddress(this.config.network, address);

    const publicKeyHex = await this.provider.getPublicKeyHex();

    if (publicKeyHex && address) {
      this.connectedAccount = {
        publicKeyHex,
        address,
      };
    } else {
      throw new Error("Could not connect to OneKey Wallet");
    }

    return this.connectedAccount;
  };

  getAddress = async (): Promise<string> => {
    if (!this.connectedAccount) throw new Error("OneKey Wallet not connected");

    return this.connectedAccount.address;
  };

  getPublicKeyHex = async (): Promise<string> => {
    if (!this.connectedAccount) throw new Error("OneKey Wallet not connected");

    return this.connectedAccount.publicKeyHex;
  };

  signPsbt = async (psbtHex: string): Promise<string> => {
    if (!this.connectedAccount) throw new Error("OneKey Wallet not connected");
    if (!psbtHex) throw new Error("psbt hex is required");

    return this.provider.signPsbt(psbtHex);
  };

  signPsbts = async (psbtsHexes: string[]): Promise<string[]> => {
    if (!this.connectedAccount) throw new Error("OneKey Wallet not connected");
    if (!psbtsHexes && !Array.isArray(psbtsHexes)) throw new Error("psbts hexes are required");

    return this.provider.signPsbts(psbtsHexes);
  };

  getNetwork = async () => {
    const internalNetwork = await this.provider.getNetwork();

    for (const [key, value] of Object.entries(INTERNAL_NETWORK_NAMES)) {
      // TODO remove as soon as OneKey implements
      if (value === "testnet") {
        // in case of testnet return signet
        return Network.SIGNET;
      } else if (value === internalNetwork) {
        return key as Network;
      }
    }

    throw new Error("Unsupported network");
  };

  signMessage = async (message: string, type: "ecdsa"): Promise<string> => {
    if (!this.connectedAccount) throw new Error("OneKey Wallet not connected");

    return await this.provider.signMessage(message, type);
  };

  // Inscriptions are only available on OneKey Wallet BTC mainnet
  getInscriptions = async (): Promise<InscriptionIdentifier[]> => {
    if (!this.connectedAccount) throw new Error("OneKey Wallet not connected");
    if (this.config.network !== Network.MAINNET) {
      throw new Error("Inscriptions are only available on OneKey Wallet BTC Mainnet");
    }

    // max num of iterations to prevent infinite loop
    const MAX_ITERATIONS = 100;
    // Fetch inscriptions in batches of 100
    const limit = 100;
    const inscriptionIdentifiers: InscriptionIdentifier[] = [];
    let cursor = 0;
    let iterations = 0;
    try {
      while (iterations < MAX_ITERATIONS) {
        const { list } = await this.provider.getInscriptions(cursor, limit);
        const identifiers = list.map((i: { output: string }) => {
          const [txid, vout] = i.output.split(":");
          return {
            txid,
            vout,
          };
        });
        inscriptionIdentifiers.push(...identifiers);
        if (list.length < limit) {
          break;
        }
        cursor += limit;
        iterations++;
        if (iterations >= MAX_ITERATIONS) {
          throw new Error("Exceeded maximum iterations when fetching inscriptions");
        }
      }
    } catch {
      throw new Error("Failed to get inscriptions from OneKey Wallet");
    }

    return inscriptionIdentifiers;
  };

  on = (eventName: string, callBack: () => void) => {
    if (!this.connectedAccount) throw new Error("OneKey Wallet not connected");

    // subscribe to account change event
    if (eventName === "accountChanged") {
      return this.provider.on(eventName, callBack);
    }
  };

  off = (eventName: string, callBack: () => void) => {
    if (!this.connectedAccount) throw new Error("OneKey Wallet not connected");

    // unsubscribe from account change event
    if (eventName === "accountChanged") {
      return this.provider.off(eventName, callBack);
    }
  };

  getWalletProviderName = async (): Promise<string> => {
    return WALLET_PROVIDER_NAME;
  };

  getWalletProviderIcon = async (): Promise<string> => {
    return logo;
  };
}
