import { initBTCCurve } from "@babylonlabs-io/btc-staking-ts";
import TransportWebHID from "@ledgerhq/hw-transport-webhid";
import TransportWebUSB from "@ledgerhq/hw-transport-webusb";
import { HDKey } from "@scure/bip32";
import { Network as BitcoinNetwork, payments } from "bitcoinjs-lib";
import { toXOnly } from "bitcoinjs-lib/src/psbt/bip371";
import { Buffer } from "buffer";
import AppClient, { DefaultWalletPolicy, signPsbt, tryParsePsbt } from "ledger-bitcoin-babylon";
import { signMessage } from "ledger-bitcoin-babylon/build/main/lib/babylon/index";

import type { BTCConfig, InscriptionIdentifier } from "@/core/types";
import { IBTCProvider, Network } from "@/core/types";
import { toNetwork } from "@/core/utils/wallet";

import logo from "./logo.svg";

type LedgerWalletInfo = {
  app: AppClient;
  policy: DefaultWalletPolicy;
  mfp: string | undefined;
  extendedPublicKey: string | undefined;
  address: string | undefined;
  path: string | undefined;
  publicKeyHex: string | undefined;
  scriptPubKeyHex: string | undefined;
};

export const WALLET_PROVIDER_NAME = "Ledger";

export class LedgerProvider implements IBTCProvider {
  private ledgerWalletInfo: LedgerWalletInfo | undefined;
  private config: BTCConfig;

  constructor(_wallet: any, config: BTCConfig) {
    this.config = config;
  }

  private createTransportWebUSB = async () => {
    return await TransportWebUSB.create();
  };

  private createTransportWebHID = async () => {
    return await TransportWebHID.create();
  };

  connectWallet = async (): Promise<void> => {
    const transport = await this.createTransportWebUSB().catch(async (usbError) => {
      // If WebUSB fails, try WebHID
      return await this.createTransportWebHID().catch((hidError) => {
        throw new Error(
          `Could not connect to Ledger device: ${usbError.message || usbError}, ${hidError.message || hidError}`,
        );
      });
    });

    const app = new AppClient(transport);

    // Get the master key fingerprint
    const fpr = await app.getMasterFingerprint();

    const networkDerivationIndex = this.config.network === Network.MAINNET ? 0 : 1;
    const taprootPath = `m/86'/${networkDerivationIndex}'/0'`;

    // Get and display on the screen the first taproot address
    const firstTaprootAccountPubkey = await app.getExtendedPubkey(taprootPath);
    if (!firstTaprootAccountPubkey) throw new Error("Could not retrieve the extended public key");

    const firstTaprootAccountPolicy = new DefaultWalletPolicy(
      "tr(@0/**)",
      `[${fpr}/86'/${networkDerivationIndex}'/0']${firstTaprootAccountPubkey}`,
    );
    if (!firstTaprootAccountPolicy) throw new Error("Could not retrieve the policy");

    const currentNetwork = await this.getNetwork();

    const firstTaprootAccountAddress = await app.getWalletAddress(
      firstTaprootAccountPolicy,
      null,
      0, // 0 - normal, 1 - change
      0, // address index
      true, // show address on the wallet's screen
    );

    // compare with the Keystone process
    const { publicKeyHex, scriptPubKeyHex } = generateP2TRaddressFromXpub(
      firstTaprootAccountPubkey,
      "M/0/0",
      toNetwork(currentNetwork),
    );

    this.ledgerWalletInfo = {
      app,
      policy: firstTaprootAccountPolicy,
      mfp: fpr,
      extendedPublicKey: firstTaprootAccountPubkey,
      path: taprootPath,
      address: firstTaprootAccountAddress,
      publicKeyHex,
      scriptPubKeyHex,
    };
  };

  getAddress = async (): Promise<string> => {
    if (!this.ledgerWalletInfo?.address) throw new Error("Could not retrieve the address");

    return this.ledgerWalletInfo.address;
  };

  getPublicKeyHex = async (): Promise<string> => {
    if (!this.ledgerWalletInfo?.publicKeyHex) throw new Error("Could not retrieve the BTC public key");

    return this.ledgerWalletInfo.publicKeyHex;
  };

  signPsbt = async (psbtHex: string): Promise<string> => {
    if (!this.ledgerWalletInfo?.address || !this.ledgerWalletInfo?.publicKeyHex) {
      throw new Error("Ledger is not connected");
    }
    if (!psbtHex) throw new Error("psbt hex is required");
    const psbtBase64 = Buffer.from(psbtHex, "hex").toString("base64");
    const transport = this.ledgerWalletInfo.app.transport;
    const policy = await tryParsePsbt(transport, psbtBase64, true);
    const tx = await signPsbt({ transport, psbt: psbtBase64, policy: policy! });
    const signedHex = tx.hex;
    return signedHex;
  };

  signPsbts = async (psbtsHexes: string[]): Promise<string[]> => {
    if (!this.ledgerWalletInfo?.address || !this.ledgerWalletInfo?.publicKeyHex || !this.ledgerWalletInfo?.policy) {
      throw new Error("Ledger is not connected");
    }
    if (!psbtsHexes && !Array.isArray(psbtsHexes)) throw new Error("psbts hexes are required");

    const result = [];
    for (const psbt of psbtsHexes) {
      const psbtBase64 = Buffer.from(psbt, "hex").toString("base64");
      const transport = this.ledgerWalletInfo.app.transport;
      const policy = await tryParsePsbt(transport, psbtBase64, true);
      const tx = await signPsbt({ transport, psbt: psbtBase64, policy: policy! });
      const signedHex = tx.hex;
      result.push(signedHex);
    }
    return result;
  };

  getNetwork = async (): Promise<Network> => {
    return this.config.network;
  };

  signMessage = async (message: string, type: "bip322-simple" | "ecdsa"): Promise<string> => {
    if (!this.ledgerWalletInfo?.app.transport || !this.ledgerWalletInfo?.path) {
      throw new Error("Ledger is not connected");
    }
    const isTestnet = this.config.network !== Network.MAINNET;

    const signedMessage = await signMessage({
      transport: this.ledgerWalletInfo?.app.transport,
      message,
      type,
      isTestnet,
    });

    // TODO bip322 does not work
    // const signedMessage = await signMessageBIP322({
    //   transport: this.ledgerWalletInfo?.app.transport,
    //   message,
    //   addressType: "p2tr" as AddressType,
    //   derivationPath: this.ledgerWalletInfo?.path,
    //   isTestnet: true,
    // });

    return signedMessage.signature;
  };

  getInscriptions = async (): Promise<InscriptionIdentifier[]> => {
    throw new Error("Method not implemented.");
  };

  // Not implemented because of the hardware wallet nature
  on = (): void => {};
  off = (): void => {};

  getWalletProviderName = async (): Promise<string> => {
    return WALLET_PROVIDER_NAME;
  };

  getWalletProviderIcon = async (): Promise<string> => {
    return logo;
  };
}

/**
 * Generates the p2tr Bitcoin address from an extended public key and a path.
 * @param xpub - The extended public key.
 * @param path - The derivation path.
 * @param network - The Bitcoin network.
 * @returns The Bitcoin address and the public key as a hex string.
 */
// TODO remove the Keystone implementation if not needed
const generateP2TRaddressFromXpub = (
  xpub: string,
  path: string,
  network: BitcoinNetwork,
): { address: string; publicKeyHex: string; scriptPubKeyHex: string } => {
  const hdNode = HDKey.fromExtendedKey(xpub, network.bip32);
  const derivedNode = hdNode.derive(path);
  const pubkeyBuffer = Buffer.from(derivedNode.publicKey!);
  const childNodeXOnlyPubkey = toXOnly(pubkeyBuffer);
  let address: string;
  let output: Buffer;
  try {
    const res = payments.p2tr({
      internalPubkey: childNodeXOnlyPubkey,
      network,
    });
    address = res.address!;
    output = res.output!;
  } catch (error: Error | any) {
    if (error instanceof Error && error.message.includes("ECC")) {
      // initialize the BTC curve if not already initialized
      initBTCCurve();
      const res = payments.p2tr({
        internalPubkey: childNodeXOnlyPubkey,
        network,
      });
      address = res.address!;
      output = res.output!;
    } else {
      throw new Error(error);
    }
  }
  return {
    address: address!,
    publicKeyHex: pubkeyBuffer.toString("hex"),
    scriptPubKeyHex: output!.toString("hex"),
  };
};
