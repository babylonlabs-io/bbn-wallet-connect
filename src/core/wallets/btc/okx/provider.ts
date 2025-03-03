import type { Account, BTCConfig, InscriptionIdentifier } from "@/core/types";
import { IBTCProvider, Network } from "@/core/types";
import { validateAddress } from "@/core/utils/wallet";

import logo from "./logo.svg";

const PROVIDER_NAMES = {
  [Network.MAINNET]: "bitcoin",
  [Network.CANARY]: "bitcoin",
  [Network.TESTNET]: "bitcoinTestnet",
  [Network.SIGNET]: "bitcoinSignet",
};

export const WALLET_PROVIDER_NAME = "OKX";

export class OKXProvider implements IBTCProvider {
  private provider: any;

  constructor(
    private wallet: any,
    private readonly config: BTCConfig,
    private connectedAccount: Account | null = null,
  ) {
    // check whether there is an OKX Wallet extension
    if (!wallet) {
      throw new Error("OKX Wallet extension not found");
    }

    const providerName = PROVIDER_NAMES[config.network];

    if (!providerName) {
      throw new Error("Unsupported network");
    }

    this.provider = wallet[providerName];
  }

  connectWallet = async (): Promise<Account> => {
    try {
      await this.wallet.enable(); // Connect to OKX Wallet extension
    } catch (error) {
      if ((error as Error)?.message?.includes("rejected")) {
        throw new Error("Connection to OKX Wallet was rejected");
      } else {
        throw new Error((error as Error)?.message);
      }
    }
    let result;
    try {
      // this will not throw an error even if user has no network enabled
      result = await this.provider.connect();
    } catch {
      throw new Error(`BTC ${this.config.network} is not enabled in OKX Wallet`);
    }

    const { address, compressedPublicKey } = result;

    validateAddress(this.config.network, address);

    if (compressedPublicKey && address) {
      this.connectedAccount = {
        publicKeyHex: compressedPublicKey,
        address,
      };
    } else {
      throw new Error("Could not connect to OKX Wallet");
    }

    return this.connectedAccount;
  };

  getAddress = async (): Promise<string> => {
    if (!this.connectedAccount) throw new Error("OKX Wallet not connected");

    return this.provider.getAddress();
  };

  getPublicKeyHex = async (): Promise<string> => {
    if (!this.connectedAccount) throw new Error("OKX Wallet not connected");

    return this.provider.getPublicKey();
  };

  signPsbt = async (psbtHex: string): Promise<string> => {
    if (!this.connectedAccount) throw new Error("OKX Wallet not connected");

    return await this.provider.signPsbt(psbtHex);
  };

  signPsbts = async (psbtsHexes: string[]): Promise<string[]> => {
    if (!this.connectedAccount) throw new Error("OKX Wallet not connected");

    return await this.provider.signPsbts(psbtsHexes);
  };

  getNetwork = async (): Promise<Network> => {
    // OKX does not provide a way to get the network for Signet and Testnet
    // So we pass the check on connection and return the environment network
    if (!this.config.network) throw new Error("Network not set");

    return this.config.network;
  };

  signMessage = async (message: string, type: "ecdsa"): Promise<string> => {
    if (!this.connectedAccount) throw new Error("OKX Wallet not connected");

    return await this.provider.signMessage(message, type);
  };

  // Inscriptions are only available on OKX Wallet BTC mainnet (i.e okxWallet.bitcoin)
  getInscriptions = async (): Promise<InscriptionIdentifier[]> => {
    if (!this.connectedAccount) throw new Error("OKX Wallet not connected");
    if (this.config.network !== Network.MAINNET) {
      throw new Error("Inscriptions are only available on OKX Wallet BTC mainnet");
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
      throw new Error("Failed to get inscriptions from OKX Wallet");
    }

    return inscriptionIdentifiers;
  };

  on = (eventName: string, callBack: () => void) => {
    if (!this.connectedAccount) throw new Error("OKX Wallet not connected");

    // subscribe to account change event
    if (eventName === "accountChanged") {
      return this.provider.on(eventName, callBack);
    }
  };

  off = (eventName: string, callBack: () => void) => {
    if (!this.connectedAccount) throw new Error("OKX Wallet not connected");

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
