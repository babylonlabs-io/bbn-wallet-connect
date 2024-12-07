import { BTCProvider } from "@/core/wallets/btc/BTCProvider";
import { validateNetwork } from "@/core/utils/wallet";
import type { Fees, InscriptionIdentifier, BTCConfig, UTXO, WalletInfo } from "@/core/types";
import { Network } from "@/core/types";

const PROVIDER_NAMES = {
  [Network.MAINNET]: "bitcoin",
  [Network.TESTNET]: "bitcoinTestnet",
  [Network.SIGNET]: "bitcoinSignet",
};

export class OKXProvider extends BTCProvider {
  private provider: any;
  private walletInfo: WalletInfo | undefined;

  constructor(
    private wallet: any,
    config: BTCConfig,
  ) {
    super(config);

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

  connectWallet = async (): Promise<void> => {
    // Validate the network before connecting
    try {
      validateNetwork(this.config.network);
    } catch (error) {
      throw new Error((error as Error)?.message);
    }
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

    if (compressedPublicKey && address) {
      this.walletInfo = {
        publicKeyHex: compressedPublicKey,
        address,
      };
    } else {
      throw new Error("Could not connect to OKX Wallet");
    }
  };

  getWalletProviderName = async (): Promise<string> => {
    return "OKX";
  };

  getAddress = async (): Promise<string> => {
    if (!this.walletInfo) {
      throw new Error("OKX Wallet not connected");
    }
    return this.walletInfo.address;
  };

  getPublicKeyHex = async (): Promise<string> => {
    if (!this.walletInfo) {
      throw new Error("OKX Wallet not connected");
    }
    return this.walletInfo.publicKeyHex;
  };

  signPsbt = async (psbtHex: string): Promise<string> => {
    if (!this.walletInfo) {
      throw new Error("OKX Wallet not connected");
    }
    // Use signPsbt since it shows the fees
    return await this.provider.signPsbt(psbtHex);
  };

  signPsbts = async (psbtsHexes: string[]): Promise<string[]> => {
    if (!this.walletInfo) {
      throw new Error("OKX Wallet not connected");
    }
    // sign the PSBTs
    return await this.provider.signPsbts(psbtsHexes);
  };

  signMessageBIP322 = async (message: string): Promise<string> => {
    if (!this.walletInfo) {
      throw new Error("OKX Wallet not connected");
    }
    return await this.provider.signMessage(message, "bip322-simple");
  };

  async signMessage(message: string, type: "ecdsa" | "bip322-simple" = "ecdsa"): Promise<string> {
    if (!this.walletInfo) {
      throw new Error("OKX Wallet not connected");
    }
    return await this.provider.signMessage(message, type);
  }

  getNetwork = async (): Promise<Network> => {
    // OKX does not provide a way to get the network for Signet and Testnet
    // So we pass the check on connection and return the environment network
    if (!this.config.network) {
      throw new Error("Network not set");
    }
    return this.config.network;
  };

  on = (eventName: string, callBack: () => void) => {
    if (!this.walletInfo) {
      throw new Error("OKX Wallet not connected");
    }
    // subscribe to account change event
    if (eventName === "accountChanged") {
      return this.provider.on(eventName, callBack);
    }
  };

  off = (eventName: string, callBack: () => void) => {
    if (!this.walletInfo) {
      throw new Error("OKX Wallet not connected");
    }
    // subscribe to account change event
    if (eventName === "accountChanged") {
      return this.provider.off(eventName, callBack);
    }
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
    // mempool call
    return await this.mempool.getFundingUTXOs(address, amount);
  };

  getBTCTipHeight = async (): Promise<number> => {
    return await this.mempool.getTipHeight();
  };

  // Inscriptions are only available on OKX Wallet BTC mainnet (i.e okxWallet.bitcoin)
  getInscriptions = async (): Promise<InscriptionIdentifier[]> => {
    if (!this.walletInfo) {
      throw new Error("OKX Wallet not connected");
    }
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
}
