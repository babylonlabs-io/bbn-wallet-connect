import { initBTCCurve } from "@babylonlabs-io/btc-staking-ts";
import { Psbt, address as btcAddress, networks } from "bitcoinjs-lib";

import type { BTCConfig, IBTCProvider, InscriptionIdentifier, WalletInfo } from "@/core/types";
import { Network } from "@/core/types";
import { validateAddress } from "@/core/utils/wallet";

import logo from "./logo.svg";

enum UnisatChainEnum {
  BITCOIN_SIGNET = "BITCOIN_SIGNET",
  BITCOIN_MAINNET = "BITCOIN_MAINNET",
  BITCOIN_TESTNET = "BITCOIN_TESTNET",
}

interface UnisatChainResponse {
  enum: UnisatChainEnum;
  name: string;
  network: "testnet" | "livenet";
}

export const WALLET_PROVIDER_NAME = "Unisat";

// Unisat derivation path for BTC Signet
// Taproot: `m/86'/1'/0'/0`
// Native Segwit: `m/84'/1'/0'/0`
export class UnisatProvider implements IBTCProvider {
  private provider: any;
  private walletInfo: WalletInfo | undefined;
  private config: BTCConfig;

  constructor(wallet: any, config: BTCConfig) {
    this.config = config;

    // check whether there is an Unisat extension
    if (!wallet) {
      throw new Error("Unisat Wallet extension not found");
    }

    this.provider = wallet;
  }

  connectWallet = async (): Promise<void> => {
    let accounts;
    try {
      accounts = await this.provider.requestAccounts();
    } catch (error) {
      if ((error as Error)?.message?.includes("rejected")) {
        throw new Error("Connection to Unisat Wallet was rejected");
      } else {
        throw new Error((error as Error)?.message);
      }
    }

    const address = accounts[0];
    validateAddress(this.config.network, address);

    const publicKeyHex = await this.provider.getPublicKey();

    if (publicKeyHex && address) {
      this.walletInfo = {
        publicKeyHex,
        address,
      };
    } else {
      throw new Error("Could not connect to Unisat Wallet");
    }
  };

  getAddress = async (): Promise<string> => {
    if (!this.walletInfo) throw new Error("Unisat Wallet not connected");

    return this.walletInfo.address;
  };

  getPublicKeyHex = async (): Promise<string> => {
    if (!this.walletInfo) throw new Error("Unisat Wallet not connected");

    return this.walletInfo.publicKeyHex;
  };

  signPsbt = async (psbtHex: string): Promise<string> => {
    if (!this.walletInfo) throw new Error("Unisat Wallet not connected");
    if (!psbtHex) throw new Error("psbt hex is required");

    const network = await this.getNetwork();
    try {
      const signedHex = await this.provider.signPsbt(psbtHex, this.getSignPsbtDefaultOptions(psbtHex, network));
      return signedHex;
    } catch (error: Error | any) {
      throw new Error(error?.message || error);
    }
  };

  signPsbts = async (psbtsHexes: string[]): Promise<string[]> => {
    if (!this.walletInfo) throw new Error("Unisat Wallet not connected");
    if (!psbtsHexes && !Array.isArray(psbtsHexes)) throw new Error("psbts hexes are required");

    const network = await this.getNetwork();
    try {
      return await this.provider.signPsbts(
        psbtsHexes,
        psbtsHexes.map((psbtHex) => this.getSignPsbtDefaultOptions(psbtHex, network)),
      );
    } catch (error: Error | any) {
      throw new Error(error?.message || error);
    }
  };

  private getSignPsbtDefaultOptions(psbtHex: string, network: Network) {
    const toSignInputs: any[] = [];
    const psbt = Psbt.fromHex(psbtHex);
    psbt.data.inputs.forEach((input, index) => {
      let useTweakedSigner = false;
      if (input.witnessUtxo && input.witnessUtxo.script) {
        let btcNetwork = networks.bitcoin;

        if (network === Network.TESTNET || network === Network.SIGNET) {
          btcNetwork = networks.testnet;
        }

        let addressToBeSigned;
        try {
          addressToBeSigned = btcAddress.fromOutputScript(input.witnessUtxo.script, btcNetwork);
        } catch (error: Error | any) {
          if (error instanceof Error && error.message.toLowerCase().includes("has no matching address")) {
            // initialize the BTC curve if not already initialized
            initBTCCurve();
            addressToBeSigned = btcAddress.fromOutputScript(input.witnessUtxo.script, btcNetwork);
          } else {
            throw new Error(error);
          }
        }
        // check if the address is a taproot address
        const isTaproot = addressToBeSigned.indexOf("tb1p") === 0 || addressToBeSigned.indexOf("bc1p") === 0;
        // check if the address is the same as the wallet address
        const isWalletAddress = addressToBeSigned === this.walletInfo?.address;
        // tweak the signer if needed
        if (isTaproot && isWalletAddress) {
          useTweakedSigner = true;
        }
      }

      const signed = input.finalScriptSig || input.finalScriptWitness;

      if (!signed) {
        toSignInputs.push({
          index,
          publicKey: this.walletInfo?.publicKeyHex,
          sighashTypes: undefined,
          useTweakedSigner,
        });
      }
    });

    return {
      autoFinalized: true,
      toSignInputs,
    };
  }

  getNetwork = async (): Promise<Network> => {
    const chainInfo: UnisatChainResponse = await this.provider.getChain();

    switch (chainInfo.enum) {
      case UnisatChainEnum.BITCOIN_MAINNET:
        return Network.MAINNET;
      case UnisatChainEnum.BITCOIN_SIGNET:
        return Network.SIGNET;
      case UnisatChainEnum.BITCOIN_TESTNET:
        // For testnet, we return Signet
        return Network.SIGNET;
      default:
        throw new Error("Unsupported network");
    }
  };

  signMessage = async (message: string, type: "bip322-simple" | "ecdsa"): Promise<string> => {
    if (!this.walletInfo) throw new Error("Unisat Wallet not connected");

    return await this.provider.signMessage(message, type);
  };

  getInscriptions = async (): Promise<InscriptionIdentifier[]> => {
    if (!this.walletInfo) throw new Error("Unisat Wallet not connected");
    if (this.config.network !== Network.MAINNET) {
      throw new Error("Inscriptions are only available on Unisat Wallet BTC Mainnet");
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
      throw new Error("Failed to get inscriptions from Unisat Wallet");
    }

    return inscriptionIdentifiers;
  };

  on = (eventName: string, callBack: () => void) => {
    if (!this.walletInfo) throw new Error("Unisat Wallet not connected");

    // subscribe to account change event: `accountChanged` -> `accountsChanged`
    if (eventName === "accountChanged") {
      return this.provider.on("accountsChanged", callBack);
    }
  };

  off = (eventName: string, callBack: () => void) => {
    if (!this.walletInfo) throw new Error("Unisat Wallet not connected");

    // unsubscribe from account change event: `accountChanged` -> `accountsChanged`
    if (eventName === "accountChanged") {
      return this.provider.removeListener("accountsChanged", callBack);
    }
  };

  getWalletProviderName = async (): Promise<string> => {
    return WALLET_PROVIDER_NAME;
  };

  getWalletProviderIcon = async (): Promise<string> => {
    return logo;
  };
}
