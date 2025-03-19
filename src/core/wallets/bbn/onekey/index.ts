import { IBBNProvider, Network, type BBNConfig, type WalletMetadata } from "@/core/types";

import logo from "./logo.svg";
import { OneKeyProvider, WALLET_PROVIDER_NAME } from "./provider";

const metadata: WalletMetadata<IBBNProvider, BBNConfig> = {
  id: "onekey",
  name: WALLET_PROVIDER_NAME,
  icon: logo,
  docs: "https://onekey.so/download",
  wallet: "$onekey",
  createProvider: (wallet, config) => new OneKeyProvider(wallet, config),
  networks: [Network.MAINNET, Network.SIGNET],
};

export default metadata;
