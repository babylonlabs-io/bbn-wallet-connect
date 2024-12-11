import type { BTCConfig, Fees, InscriptionIdentifier, UTXO, WalletInfo } from "@/core/types";
import { Network } from "@/core/types";
import { validateAddress } from "@/core/utils/wallet";
import { BTCProvider } from "@/core/wallets/btc/BTCProvider";

const INTERNAL_NETWORK_NAMES = {
  [Network.MAINNET]: "mainnet",
  [Network.TESTNET]: "testnet",
  [Network.SIGNET]: "signet",
};

export class CactusLinkProvider extends BTCProvider {
  private provider: any;
  private walletInfo: WalletInfo | undefined;

  constructor(wallet: any, config: BTCConfig) {
    super(config);

    // check whether there is a Cactus Link Wallet extension
    if (!wallet) {
      throw new Error("Cactus Link Wallet extension not found");
    }

    this.provider = wallet;
  }

  connectWallet = async (): Promise<void> => {
    const walletNetwork = await this.getNetwork();
    if (this.config.network !== walletNetwork) {
      throw new Error(`Wallet is not switched to Bitcoin ${this.config.network} network`);
    }

    try {
      await this.provider.requestAccounts();
    } catch (error) {
      if ((error as Error)?.message?.includes("rejected")) {
        throw new Error("Connection to Cactus Link Wallet was rejected");
      } else {
        throw new Error((error as Error)?.message);
      }
    }

    const address = await this.getAddress();
    validateAddress(this.config.network, address);

    const publicKeyHex = await this.getPublicKeyHex();

    if (publicKeyHex && address) {
      this.walletInfo = {
        publicKeyHex,
        address,
      };
    } else {
      throw new Error("Could not connect to Cactus Link Wallet");
    }
  };

  getWalletProviderName = async (): Promise<string> => {
    return "Cactus Link";
  };

  async getAddress(): Promise<string> {
    const accounts = (await this.provider.getAccounts()) || [];
    if (!accounts?.[0]) {
      throw new Error("Cactus Link Wallet not connected");
    }
    return accounts[0];
  }

  getPublicKeyHex = async (): Promise<string> => {
    const publicKey = await this.provider.getPublicKey();
    if (!publicKey) {
      throw new Error("Cactus Link Wallet not connected");
    }
    return publicKey;
  };

  signPsbt = async (psbtHex: string): Promise<string> => {
    if (!this.walletInfo) throw new Error("Cactus Link Wallet not connected");
    if (!psbtHex) throw new Error("psbt hex is required");

    return await this.provider.signPsbt(psbtHex, {
      autoFinalized: true,
    });
  };

  signPsbts = async (psbtsHexes: string[]): Promise<string[]> => {
    if (!this.walletInfo) throw new Error("Cactus Link Wallet not connected");
    if (!psbtsHexes && !Array.isArray(psbtsHexes)) throw new Error("psbts hexes are required");

    const options = psbtsHexes.map(() => {
      return {
        autoFinalized: true,
      };
    });

    return await this.provider.signPsbts(psbtsHexes, options);
  };

  signMessageBIP322 = async (message: string): Promise<string> => {
    if (!this.walletInfo) throw new Error("Cactus Link Wallet not connected");
    return await this.provider.signMessage(message, "bip322-simple");
  };

  signMessage = async (message: string, type: "ecdsa" | "bip322-simple" = "ecdsa"): Promise<string> => {
    if (!this.walletInfo) throw new Error("Cactus Link Wallet not connected");
    return await this.provider.signMessage(message, type);
  };

  getNetwork = async (): Promise<Network> => {
    const internalNetwork = await this.provider.getNetwork();

    for (const [key, value] of Object.entries(INTERNAL_NETWORK_NAMES)) {
      if (value === internalNetwork) {
        return key as Network;
      }
    }

    throw new Error("Unsupported network");
  };

  on = (eventName: string, callBack: () => void) => {
    if (!this.walletInfo) throw new Error("Cactus Link Wallet not connected");

    // subscribe to account change event: `accountChanged` -> `accountsChanged`
    if (eventName === "accountChanged") {
      return this.provider.on("accountsChanged", callBack);
    }
    return this.provider.on(eventName, callBack);
  };

  off = (eventName: string, callBack: () => void) => {
    if (!this.walletInfo) throw new Error("Cactus Link Wallet not connected");

    // unsubscribe to account change event
    if (eventName === "accountChanged") {
      return this.provider.off("accountsChanged", callBack);
    }
    return this.provider.off(eventName, callBack);
  };

  // Mempool calls
  getBalance = async (): Promise<number> => {
    return await this.mempool.getAddressBalance(await this.getAddress());
  };

  getNetworkFees = async (): Promise<Fees> => {
    return await this.mempool.getNetworkFees();
  };

  pushTx = async (txHex: string): Promise<string> => {
    return await this.mempool.pushTx(txHex);
  };

  getUtxos = async (address: string, amount: number): Promise<UTXO[]> => {
    return await this.mempool.getFundingUTXOs(address, amount);
  };

  getBTCTipHeight = async (): Promise<number> => {
    return await this.mempool.getTipHeight();
  };

  getInscriptions = async (): Promise<InscriptionIdentifier[]> => {
    // Temporary solution to ignore inscriptions filtering for Cactus Link Wallet
    return Promise.resolve([]);
  };
}